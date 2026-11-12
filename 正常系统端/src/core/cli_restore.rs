//! Normal-Windows CLI adapter for the native restore planner/executor.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use super::cli_backup::{first_cached_pe_verified_summary, stable_digest};
use super::cli_config::RestoreSpec;
use super::disk::DiskManager;
use super::dism::Dism;
use super::install_config::RestoreConfig;
use super::native_restore_controller::{plan_restore_launch, RestoreLaunchPlan};
use super::native_restore_executor::{execute_restore, RestoreWorkerMessage};

pub struct PreparedRestore {
    plan: RestoreLaunchPlan,
    auto_reboot: bool,
    wim_engine: u8,
    image_identity: lr_core::windows_storage::StableVolumeIdentity,
    target_identity: lr_core::windows_storage::StableVolumeIdentity,
    image_path: PathBuf,
    image_file: lr_core::backup_atomic_publish::FileExpectation,
    image_bitlocker: super::bitlocker::VolumeStatus,
    target_bitlocker: super::bitlocker::VolumeStatus,
    pe_summary: Value,
}

pub fn plan_restore(spec: &RestoreSpec) -> Result<PreparedRestore> {
    let partitions =
        DiskManager::get_partitions().context("failed to refresh partition inventory")?;
    let target = partitions
        .iter()
        .find(|partition| {
            partition
                .letter
                .eq_ignore_ascii_case(&spec.target_partition)
        })
        .ok_or_else(|| {
            anyhow!(
                "target partition {} is absent from the fresh inventory",
                spec.target_partition
            )
        })?;
    let target_letter = spec
        .target_partition
        .chars()
        .next()
        .ok_or_else(|| anyhow!("target partition has no drive letter"))?;
    let target_identity = target.stable_identity.ok_or_else(|| {
        anyhow!(
            "target partition {} has no stable volume identity",
            spec.target_partition
        )
    })?;
    let fresh_target = lr_core::windows_storage::stable_volume_identity(target_letter)
        .map_err(|error| anyhow!("failed to bind target identity: {error}"))?;
    if !lr_core::windows_storage::same_stable_volume_identity(target_identity, fresh_target) {
        return Err(anyhow!(
            "target volume identity changed during restore planning"
        ));
    }

    let image_path = PathBuf::from(&spec.image_path);
    let image_letter = absolute_local_drive_letter(&image_path)?;
    let image_metadata = std::fs::symlink_metadata(&image_path)
        .with_context(|| format!("inspect restore image {}", image_path.display()))?;
    if !image_metadata.file_type().is_file() || image_metadata.file_type().is_symlink() {
        return Err(anyhow!("restore image is not a plain regular file"));
    }
    let image_file = lr_core::backup_atomic_publish::inspect_existing_file(&image_path)
        .context("bind CLI restore image identity")?;
    let image_identity = lr_core::windows_storage::stable_volume_identity(image_letter)
        .map_err(|error| anyhow!("failed to bind image volume identity: {error}"))?;
    if lr_core::windows_storage::same_stable_volume_identity(image_identity, target_identity) {
        return Err(anyhow!(
            "restore image must be on a different stable volume than the target"
        ));
    }
    let image_partition = partitions
        .iter()
        .find(|partition| partition.letter.starts_with(image_letter))
        .ok_or_else(|| anyhow!("restore image volume is absent from fresh inventory"))?;

    validate_bitlocker_for_restore(image_partition.bitlocker_status, target.bitlocker_status)?;

    let (verified_pe, pe_summary) = first_cached_pe_verified_summary()?
        .ok_or_else(|| anyhow!("PE restore requires a verified cached PE entry"))?;

    // Bind the display fields from the verified catalog at plan time; the executor re-reads
    // the catalog under its own authorization before anything is written.
    let catalog = Dism::read_verified_backup_catalog(&image_path)
        .context("read restore image catalog during planning")?;
    let selected = catalog
        .images()
        .get(spec.image_index.saturating_sub(1) as usize)
        .ok_or_else(|| {
            anyhow!(
                "image_index {} is outside the restore image catalog",
                spec.image_index
            )
        })?;

    let config = RestoreConfig {
        image_path: spec.image_path.clone(),
        target_partition: spec.target_partition.clone(),
        image_index: spec.image_index,
        image_name: selected.name.clone(),
        image_description: selected.description.clone(),
        wim_engine: lr_core::active_engine().as_u8(),
        handoff: None,
    };
    let plan = plan_restore_launch(&config, Some(&verified_pe))
        .map_err(|error| anyhow!("restore preflight rejected the request: {error}"))?;
    Ok(PreparedRestore {
        plan,
        auto_reboot: spec.auto_reboot,
        wim_engine: config.wim_engine,
        image_identity,
        target_identity,
        image_path,
        image_file,
        image_bitlocker: image_partition.bitlocker_status,
        target_bitlocker: target.bitlocker_status,
        pe_summary,
    })
}

pub fn restore_plan_json(prepared: &PreparedRestore) -> Value {
    let plan = &prepared.plan;
    json!({
        "mode": "via_pe",
        "image_path": plan.preview.image_path,
        "target_partition": plan.preview.target_partition,
        "image_index": plan.preview.image_index,
        "image_name": plan.preview.image_name,
        "image_stable_identity_digest": stable_digest(prepared.image_identity),
        "target_stable_identity_digest": stable_digest(prepared.target_identity),
        "image_bitlocker": format!("{:?}", prepared.image_bitlocker).to_ascii_lowercase(),
        "target_bitlocker": format!("{:?}", prepared.target_bitlocker).to_ascii_lowercase(),
        "requires_pe_preparation": true,
        "pe_display_name": plan.preview.pe_display_name,
        "pe": prepared.pe_summary.clone(),
        "effective_config": {
            "image_path": plan.preview.image_path,
            "target_partition": plan.preview.target_partition,
            "image_index": plan.preview.image_index,
            "execution_mode": "via_pe",
            "auto_reboot": prepared.auto_reboot,
            "wim_engine": prepared.wim_engine,
            "wim_engine_name": lr_core::WimEngine::from_u8(prepared.wim_engine).name(),
        },
        "warnings": [],
    })
}

/// Runs the existing restore executor. The caller must enforce explicit `--yes`.
pub fn run_restore(prepared: PreparedRestore) -> Result<Value> {
    let image_letter = absolute_local_drive_letter(&prepared.image_path)?;
    let target_letter = prepared
        .plan
        .preview
        .target_partition
        .chars()
        .next()
        .ok_or_else(|| anyhow!("planned target partition has no drive letter"))?;
    let image_identity = lr_core::windows_storage::stable_volume_identity(image_letter)
        .map_err(|error| anyhow!("failed to revalidate image volume identity: {error}"))?;
    let target_identity = lr_core::windows_storage::stable_volume_identity(target_letter)
        .map_err(|error| anyhow!("failed to revalidate target volume identity: {error}"))?;
    if !lr_core::windows_storage::same_stable_volume_identity(
        prepared.image_identity,
        image_identity,
    ) || !lr_core::windows_storage::same_stable_volume_identity(
        prepared.target_identity,
        target_identity,
    ) {
        return Err(anyhow!(
            "restore image or target stable volume identity changed before execution"
        ));
    }
    let current_image = lr_core::backup_atomic_publish::inspect_existing_file(&prepared.image_path)
        .context("revalidate CLI restore image identity")?;
    if current_image != prepared.image_file {
        return Err(anyhow!(
            "restore image changed after confirmation; refusing to restore"
        ));
    }
    let inventory = DiskManager::get_partitions()
        .context("failed to refresh restore volume inventory before execution")?;
    let image_partition = inventory
        .iter()
        .find(|partition| partition.letter.starts_with(image_letter))
        .ok_or_else(|| anyhow!("image volume disappeared before execution"))?;
    let target = inventory
        .iter()
        .find(|partition| {
            partition
                .letter
                .eq_ignore_ascii_case(&prepared.plan.preview.target_partition)
        })
        .ok_or_else(|| anyhow!("target volume disappeared before execution"))?;
    validate_bitlocker_for_restore(image_partition.bitlocker_status, target.bitlocker_status)?;

    let auto_reboot = prepared.auto_reboot;
    let plan = prepared.plan;
    let execution = execute_restore(plan.intent)
        .map_err(|error| anyhow!("native restore executor failed to start: {error}"))?;
    let mut event_count = 0usize;
    let mut last_emitted_progress = None::<u8>;
    for event in execution.messages {
        event_count = event_count.saturating_add(1);
        let progress = match &event {
            RestoreWorkerMessage::Started => json!({"event":"started","mode":"via_pe"}),
            RestoreWorkerMessage::Progress { percentage, .. } => {
                json!({"event":"progress","percentage":percentage})
            }
            RestoreWorkerMessage::PeCommitStarted => json!({"event":"pe_commit_started"}),
            RestoreWorkerMessage::Completed => json!({"event":"completed","mode":"via_pe"}),
            RestoreWorkerMessage::Cancelled => json!({"event":"cancelled"}),
            RestoreWorkerMessage::Failed { .. } => json!({"event":"failed","mode":"via_pe"}),
        };
        let should_emit = match &event {
            RestoreWorkerMessage::Progress { percentage, .. } => {
                let changed = last_emitted_progress != Some(*percentage);
                if changed {
                    last_emitted_progress = Some(*percentage);
                }
                changed
            }
            _ => true,
        };
        if should_emit {
            super::cli::emit_progress(progress);
        }
        match event {
            RestoreWorkerMessage::Completed => {
                let mut restart_scheduled = false;
                let mut warnings = Vec::<Value>::new();
                if auto_reboot {
                    match lr_core::windows_shutdown::schedule_restart(
                        5,
                        "R装机 restore preparation completed; Windows will restart into PE.",
                    ) {
                        Ok(()) => restart_scheduled = true,
                        Err(error) => warnings.push(json!({
                            "code": "restart_not_scheduled",
                            "message": format!(
                                "restore handoff was already committed, but the requested restart could not be scheduled: {error}"
                            ),
                        })),
                    }
                }
                return Ok(json!({
                    "outcome": "ready_to_reboot_into_pe",
                    "restore_not_yet_applied": true,
                    "auto_reboot_requested": auto_reboot,
                    "restart_scheduled": restart_scheduled,
                    "warnings": warnings,
                    "event_count": event_count,
                }));
            }
            RestoreWorkerMessage::Cancelled => return Err(anyhow!("restore was cancelled")),
            RestoreWorkerMessage::Failed { error } => {
                return Err(anyhow!("restore failed: {error}"))
            }
            _ => {}
        }
    }
    Err(anyhow!("restore worker ended without a terminal result"))
}

fn validate_bitlocker_for_restore(
    image: super::bitlocker::VolumeStatus,
    target: super::bitlocker::VolumeStatus,
) -> Result<()> {
    use super::bitlocker::VolumeStatus;
    let via_pe_allowed = |status| {
        matches!(
            status,
            VolumeStatus::NotEncrypted
                | VolumeStatus::EncryptedUnlocked
                | VolumeStatus::EncryptedLocked
        )
    };
    if via_pe_allowed(image) && via_pe_allowed(target) {
        Ok(())
    } else {
        Err(anyhow!(
            "PE restore BitLocker state is unknown (image={image:?}, target={target:?})"
        ))
    }
}

fn absolute_local_drive_letter(path: &Path) -> Result<char> {
    let text = path.as_os_str().to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
    {
        return Err(anyhow!(
            "CLI restore image must be an absolute local drive path; UNC and mapped-path identity cannot be proven safely"
        ));
    }
    Ok((bytes[0] as char).to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::super::bitlocker::VolumeStatus;
    use super::*;

    #[test]
    fn cli_restore_bitlocker_policy_matches_via_pe_execution() {
        assert!(validate_bitlocker_for_restore(
            VolumeStatus::NotEncrypted,
            VolumeStatus::EncryptedLocked,
        )
        .is_ok());
        assert!(validate_bitlocker_for_restore(
            VolumeStatus::EncryptedUnlocked,
            VolumeStatus::EncryptedUnlocked,
        )
        .is_ok());
        assert!(
            validate_bitlocker_for_restore(VolumeStatus::Unknown, VolumeStatus::NotEncrypted,)
                .is_err()
        );
        assert!(
            validate_bitlocker_for_restore(VolumeStatus::NotEncrypted, VolumeStatus::Unknown,)
                .is_err()
        );
    }

    #[test]
    fn cli_restore_image_path_must_be_an_absolute_local_drive_path() {
        assert_eq!(
            absolute_local_drive_letter(Path::new("d:\\images\\system.wim")).unwrap(),
            'D'
        );
        assert!(absolute_local_drive_letter(Path::new("images\\system.wim")).is_err());
        assert!(absolute_local_drive_letter(Path::new("\\\\server\\share\\system.wim")).is_err());
    }
}
