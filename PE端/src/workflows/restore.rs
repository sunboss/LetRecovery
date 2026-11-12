use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::app::WorkerMessage;
use crate::core::bcdedit::BootManager;
use crate::core::config::{
    AuthenticatedOperationConfig, AuthenticatedOperationTask, RestoreConfig,
};
use crate::core::disk::DiskManager;
use crate::core::dism::{Dism, DismProgress};
use crate::tr;
use crate::ui::progress::RestoreStep;
use crate::utils::reboot_pe;

pub(crate) fn execute_restore_workflow(
    tx: Sender<WorkerMessage>,
    authenticated_handoff: crate::core::config::AuthenticatedOperationGuard,
) {
    log::info!("========== 开始严格 LRRH2 PE 系统还原流程 ==========");
    let authenticated_task = match authenticated_handoff.into_task() {
        Ok(task) => task,
        Err(error) => {
            let _ = tx.send(WorkerMessage::Failed(tr!("还原任务认证失效: {}", error)));
            return;
        }
    };
    if let Err(error) = run_restore_workflow(&tx, authenticated_task) {
        log::error!("[PE RESTORE] {error:#}");
        let _ = tx.send(WorkerMessage::Failed(tr!("还原失败: {}", error)));
    }
}

fn run_restore_workflow(
    tx: &Sender<WorkerMessage>,
    mut authenticated_task: AuthenticatedOperationTask,
) -> Result<()> {
    let _ = tx.send(WorkerMessage::SetRestoreStep(RestoreStep::ReadConfig));
    let _ = tx.send(WorkerMessage::SetStatus(tr!("正在读取并验证还原任务...")));
    let config = match authenticated_task.config() {
        AuthenticatedOperationConfig::Restore(config) => config.clone(),
        _ => anyhow::bail!("authenticated task is not a restore operation"),
    };
    log::info!("[PE RESTORE] authenticated language={}", config.language);
    let handoff = config
        .handoff
        .as_ref()
        .context("LRRH2 authorization is absent")?;
    lr_core::set_active_engine(lr_core::WimEngine::from_u8(config.wim_engine));
    let selected_engine = lr_core::active_engine();
    log::info!(
        "[PE RESTORE] configured WIM restore engine={}",
        selected_engine.name()
    );

    // The target volume is selected only by the independent random target marker consumed
    // during task authentication. Drive letters are display aliases and never select a disk.
    let (target_partition, expected_target) = authenticated_task.restore_target()?;
    let target_partition = target_partition.to_owned();
    let image_path = authenticated_task.restore_image_path()?;
    log::info!(
        "[PE RESTORE] session={} image={} target={} index={}",
        handoff.session_id,
        image_path.display(),
        target_partition,
        config.image_index
    );
    let _ = tx.send(WorkerMessage::SetProgress(100));

    let _ = tx.send(WorkerMessage::SetRestoreStep(RestoreStep::VerifyImage));
    let _ = tx.send(WorkerMessage::SetStatus(tr!("正在校验备份镜像...")));
    rebind_and_gate_restore_volumes(&config, &image_path, expected_target)?;
    verify_restore_image_catalog(&config, &image_path)?;
    let _ = tx.send(WorkerMessage::SetProgress(100));

    // The one-shot WIM/SDI and BCD objects are required only to reach this already-running X:
    // environment, and the private payload root sits on the target system volume itself.
    // Remove the exact authenticated session before formatting that volume, then release the
    // target marker through its already-locked handle (the format is about to destroy it).
    authenticated_task.verify_unchanged()?;
    crate::cleanup_persistent_pe_boot_payload(authenticated_task.guard())
        .context("clean the authenticated private PE boot payload before restore format")?;
    authenticated_task.release_restore_target_marker()?;

    // Step: format the target partition. Point of no return: a failed format can already have
    // destroyed file-system metadata, so no later error path may pretend the old system is
    // still restorable.
    let _ = tx.send(WorkerMessage::SetRestoreStep(RestoreStep::FormatPartition));
    let _ = tx.send(WorkerMessage::SetStatus(tr!("正在格式化目标分区...")));
    DiskManager::verify_partition_volume_identity(&target_partition, expected_target)
        .context("restore target volume identity changed before format")?;
    log::warn!(
        "[PE RESTORE] irreversible boundary entered: target format started; old-system rollback is disabled"
    );
    DiskManager::format_partition_with_label(&target_partition, expected_target, None)
        .context("format restore target partition")?;
    let _ = tx.send(WorkerMessage::SetProgress(100));

    // Step: apply the authenticated backup image. The image bytes were already authenticated
    // against the LRHM3 manifest (length + SHA-256 behind deny-write/delete locks) when this
    // task was created, so no second full decompression verification is repeated here.
    let _ = tx.send(WorkerMessage::SetRestoreStep(RestoreStep::ApplyImage));
    let _ = tx.send(WorkerMessage::SetStatus(tr!(
        "正在使用 {} 释放系统镜像...",
        selected_engine.name()
    )));
    let (progress_tx, progress_rx) = channel::<DismProgress>();
    let progress_messages = tx.clone();
    let relay = thread::spawn(move || {
        while let Ok(progress) = progress_rx.recv() {
            let _ = progress_messages.send(WorkerMessage::SetProgress(progress.percentage));
        }
    });
    let apply_dir = format!("{}\\", target_partition);
    let image_text = image_path.to_string_lossy().into_owned();
    let apply_result = Dism::new().apply_image_with_exact_swm_resources(
        &image_text,
        std::slice::from_ref(&image_path),
        &apply_dir,
        config.image_index,
        Some(progress_tx),
    );
    let _ = relay.join();
    apply_result.context("apply restore image")?;
    let _ = tx.send(WorkerMessage::SetProgress(100));

    // Step: repair the boot configuration for the restored system, reusing the installation
    // boot chain (firmware mode is probed from the target, PCA mode stays automatic).
    let _ = tx.send(WorkerMessage::SetRestoreStep(RestoreStep::RepairBoot));
    let _ = tx.send(WorkerMessage::SetStatus(tr!("正在修复引导...")));
    let use_uefi = DiskManager::resolve_install_uefi_mode(0, &target_partition)
        .context("determine restore boot mode")?;
    BootManager::new()
        .repair_boot_advanced(
            &target_partition,
            use_uefi,
            lr_core::boot_pca::BootPcaMode::Auto,
        )
        .context("repair restored system boot")?;
    let _ = tx.send(WorkerMessage::SetProgress(100));

    let _ = tx.send(WorkerMessage::SetRestoreStep(RestoreStep::Cleanup));
    let _ = tx.send(WorkerMessage::SetStatus(tr!("正在清理本次还原会话文件...")));
    authenticated_task
        .cleanup_public_control_files()
        .context("delete the exact authenticated LRRH2 markers")?;
    let _ = tx.send(WorkerMessage::SetProgress(100));
    let _ = tx.send(WorkerMessage::SetRestoreStep(RestoreStep::Complete));
    let _ = tx.send(WorkerMessage::Completed);
    log::info!("========== LRRH2 PE 系统还原流程完成 ==========");
    thread::sleep(Duration::from_secs(3));
    reboot_pe();
    Ok(())
}

/// Rebind both LRRH2 volumes against the current physical layout and prove the canonical
/// target is the same physical extent the random target marker selected. Both volumes must
/// also be readable after the authenticated BitLocker handoff unlock.
fn rebind_and_gate_restore_volumes(
    config: &RestoreConfig,
    image_path: &Path,
    expected_target: lr_core::windows_storage::VolumeIdentity,
) -> Result<()> {
    let handoff = config.handoff.as_ref().context("missing LRRH2 handoff")?;
    let disk_numbers = lr_core::windows_storage::physical_disk_numbers()
        .context("enumerate complete physical disk inventory")?;
    let mut candidates = Vec::with_capacity(disk_numbers.len());
    for disk_number in disk_numbers {
        candidates.push((
            disk_number,
            lr_core::windows_storage::disk_layout_snapshot(disk_number)
                .with_context(|| format!("snapshot physical disk {disk_number}"))?,
        ));
    }
    let (image_disk, target_disk) =
        lr_core::restore_handoff::bind_unique_restore_volumes(handoff, &candidates)?;
    if target_disk != expected_target.disk_number
        || handoff.target.partition_offset_bytes != expected_target.offset_bytes
        || handoff.target.partition_length_bytes != expected_target.extent_length_bytes
    {
        anyhow::bail!(
            "restore target canonical identity does not match the authenticated target marker"
        );
    }
    let image_root = lr_core::windows_storage::volume_guid_path_for_partition(
        image_disk,
        handoff.image_volume.partition_offset_bytes,
    )
    .context("resolve restore image volume GUID")?;
    let target_root = lr_core::windows_storage::volume_guid_path_for_partition(
        target_disk,
        handoff.target.partition_offset_bytes,
    )
    .context("resolve restore target volume GUID")?;
    if !image_path.starts_with(&image_root) {
        anyhow::bail!("authenticated restore image is not on its LRRH2 image volume");
    }
    require_accessible_volume(&image_root).context("image volume BitLocker access gate")?;
    require_accessible_volume(&target_root).context("target volume BitLocker access gate")?;
    Ok(())
}

/// The manifest hash already proves the image bytes; this catalog check proves the file is a
/// readable backup image whose entry at the authenticated index is the one the user selected.
fn verify_restore_image_catalog(config: &RestoreConfig, image_path: &Path) -> Result<()> {
    let catalog =
        Dism::read_verified_backup_catalog(image_path).context("read restore image catalog")?;
    let images = catalog.images();
    let index = config.image_index as usize;
    if index == 0 || index > images.len() {
        anyhow::bail!(
            "restore image index {} is outside the image catalog ({} image(s))",
            config.image_index,
            images.len()
        );
    }
    let entry = &images[index - 1];
    if entry.name != config.image_name {
        anyhow::bail!("restore image catalog does not match the authenticated selection");
    }
    Ok(())
}

fn require_accessible_volume(path: &str) -> Result<()> {
    use lr_core::fveapi::{FveError, FveLockStatus};

    let api = lr_core::fveapi::FveApi::instance()
        .map_err(|error| anyhow::anyhow!("load BitLocker status API: {error}"))?;
    match api.get_status_by_path(path) {
        Ok(info) if info.lock_status != FveLockStatus::Locked => Ok(()),
        Err(FveError::NotEncrypted) | Err(FveError::NotBitLockerVolume) => Ok(()),
        Ok(info) => anyhow::bail!(
            "volume remains inaccessible after BitLocker handoff unlock (status={:?})",
            info.lock_status
        ),
        Err(error) => anyhow::bail!("cannot verify BitLocker volume accessibility: {error}"),
    }
}
