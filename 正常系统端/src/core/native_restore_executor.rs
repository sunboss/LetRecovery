//! Worker boundary for restore launch intents emitted by the native UI.
//!
//! Restore exists only as a PE handoff: the target is the live system partition. This module
//! mirrors the ViaPE half of the backup executor — it authorizes the intent against stable
//! volume identities, binds the selected image by length/SHA-256 and its catalog name, writes
//! the LRRH2 configuration transactionally, and installs the PE boot entry. Reboot/shutdown
//! stays outside this boundary, exactly as with backup.

#[cfg(not(feature = "non-elevated-tests"))]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use crate::core::native_restore_controller::PeRestorePreparationIntent;

#[cfg(not(feature = "non-elevated-tests"))]
use crate::core::dism::Dism;
#[cfg(not(feature = "non-elevated-tests"))]
use crate::core::install_config::ConfigFileManager;
#[cfg(not(feature = "non-elevated-tests"))]
use crate::core::native_backup_executor::{require_verified_cached_pe, strict_bitlocker_status};
#[cfg(not(feature = "non-elevated-tests"))]
use std::sync::mpsc::{self, Sender};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreWorkerMessage {
    Started,
    Progress { percentage: u8, status: String },
    PeCommitStarted,
    Completed,
    Cancelled,
    Failed { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreExecutionError {
    #[error("开发测试构建禁止执行真实还原或 PE 启动准备")]
    DisabledInDevelopment,
    #[error("无法启动还原工作线程: {0}")]
    Spawn(String),
    #[error("restore authorization failed: {0}")]
    UnsafeIntent(String),
}

#[cfg(not(feature = "non-elevated-tests"))]
#[derive(Debug, Clone)]
struct AuthorizedPeRestoreIntent {
    intent: PeRestorePreparationIntent,
    authorization: crate::core::native_restore_controller::RestoreStableAuthorization,
    requires_bitlocker_secret: bool,
}

/// Receiver and cooperative cancellation handle owned by the native UI.
pub struct RestoreExecution {
    pub messages: Receiver<RestoreWorkerMessage>,
    cancel_requested: Arc<AtomicBool>,
}

impl RestoreExecution {
    pub fn request_cancel(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
    }

    pub fn cancellation_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::SeqCst)
    }
}

#[cfg(not(feature = "non-elevated-tests"))]
fn authorize_restore_intent(
    intent: PeRestorePreparationIntent,
) -> Result<AuthorizedPeRestoreIntent, String> {
    use crate::core::bitlocker::VolumeStatus;
    use crate::core::native_restore_controller::RestoreStableAuthorization;
    use lr_core::install_handoff::CanonicalInstallTargetV2;
    use lr_core::restore_handoff::{RestoreHandoffV2, RestoreImageIdentity};

    let mut config = intent.config.clone();
    let image_path = PathBuf::from(&config.image_path);
    if !image_path.is_absolute() {
        return Err("restore image must be an absolute local drive path".to_owned());
    }
    let image_letter = lr_core::windows_storage::path_drive_letter(&image_path)
        .ok_or_else(|| "restore image must be an absolute local drive path".to_owned())?;
    let image_root = PathBuf::from(format!("{}:\\", image_letter));
    let image_relative_path = image_path
        .strip_prefix(&image_root)
        .map_err(|_| "restore image is not rooted on its parsed local volume".to_owned())?
        .to_path_buf();
    lr_core::backup_handoff::validate_relative_output_path(&image_relative_path)
        .map_err(|error| error.to_string())?;
    let target_letter = lr_core::windows_storage::path_drive_letter(Path::new(&format!(
        "{}\\",
        config.target_partition.trim_end_matches(['\\', '/'])
    )))
    .ok_or_else(|| "restore target must be a local drive root".to_owned())?;

    let image_identity = lr_core::windows_storage::stable_volume_identity(image_letter)
        .map_err(|error| format!("bind restore image volume identity: {error}"))?;
    let target_identity = lr_core::windows_storage::stable_volume_identity(target_letter)
        .map_err(|error| format!("bind restore target volume identity: {error}"))?;
    if lr_core::windows_storage::same_stable_volume_identity(image_identity, target_identity) {
        return Err("restore image and target are the same stable volume".to_owned());
    }

    let image_status = strict_bitlocker_status(&format!("{}:", image_letter))?;
    let target_status = strict_bitlocker_status(&format!("{}:", target_letter))?;
    let via_pe_allowed = |status| {
        matches!(
            status,
            VolumeStatus::NotEncrypted
                | VolumeStatus::EncryptedUnlocked
                | VolumeStatus::EncryptedLocked
        )
    };
    if !via_pe_allowed(image_status) || !via_pe_allowed(target_status) {
        return Err(format!(
            "PE restore requires a known image and target BitLocker state (image={image_status:?}, target={target_status:?})"
        ));
    }

    let image_layout =
        lr_core::windows_storage::disk_layout_snapshot(image_identity.extent.disk_number)
            .map_err(|error| format!("snapshot restore image disk: {error}"))?;
    let target_layout =
        lr_core::windows_storage::disk_layout_snapshot(target_identity.extent.disk_number)
            .map_err(|error| format!("snapshot restore target disk: {error}"))?;
    let image_canonical = CanonicalInstallTargetV2::from_snapshot(
        &image_layout,
        image_identity.extent.offset_bytes,
        image_identity.extent.extent_length_bytes,
    )
    .map_err(|error| format!("canonicalize restore image volume: {error}"))?;
    let target_canonical = CanonicalInstallTargetV2::from_snapshot(
        &target_layout,
        target_identity.extent.offset_bytes,
        target_identity.extent.extent_length_bytes,
    )
    .map_err(|error| format!("canonicalize restore target volume: {error}"))?;

    let image_metadata = std::fs::symlink_metadata(&image_path)
        .map_err(|error| format!("inspect restore image: {error}"))?;
    if !image_metadata.file_type().is_file() || image_metadata.file_type().is_symlink() {
        return Err("restore image is not a plain regular file".to_owned());
    }
    let image_file = lr_core::backup_atomic_publish::inspect_existing_file(&image_path)
        .map_err(|error| format!("bind restore image identity: {error}"))?;
    let catalog = Dism::read_verified_backup_catalog(&image_path)
        .map_err(|error| format!("read restore image catalog: {error}"))?;
    let selected = catalog
        .images()
        .get(config.image_index.saturating_sub(1) as usize)
        .ok_or_else(|| {
            format!(
                "restore image index {} is outside the image catalog",
                config.image_index
            )
        })?;
    // The authenticated display fields come from the verified catalog, never from free text.
    config.image_name = selected.name.clone();
    config.image_description = selected.description.clone();

    let handoff = RestoreHandoffV2 {
        session_id: ConfigFileManager::new_session_id()
            .map_err(|error| format!("generate restore session identifier: {error}"))?,
        image_volume: image_canonical,
        image_relative_path,
        image: RestoreImageIdentity {
            length_bytes: image_file.length,
            sha256: image_file.sha256,
        },
        target: target_canonical,
        image_index: config.image_index,
    };
    handoff.validate().map_err(|error| error.to_string())?;
    config.handoff = Some(handoff);
    let authorization = RestoreStableAuthorization {
        image: image_identity,
        target: target_identity,
    };

    Ok(AuthorizedPeRestoreIntent {
        intent: PeRestorePreparationIntent {
            config,
            pe: intent.pe.clone(),
        },
        authorization,
        requires_bitlocker_secret: image_status != VolumeStatus::NotEncrypted
            || target_status != VolumeStatus::NotEncrypted,
    })
}

/// Starts an existing, fully planned restore intent on a background thread.
///
/// The test-only non-elevated feature fails before a thread is created, so unit/UI development
/// can never modify BCD, write a handoff marker or reboot the host.
#[cfg(feature = "non-elevated-tests")]
pub fn execute_restore(
    _intent: PeRestorePreparationIntent,
) -> Result<RestoreExecution, RestoreExecutionError> {
    Err(RestoreExecutionError::DisabledInDevelopment)
}

#[cfg(not(feature = "non-elevated-tests"))]
pub fn execute_restore(
    intent: PeRestorePreparationIntent,
) -> Result<RestoreExecution, RestoreExecutionError> {
    let intent = authorize_restore_intent(intent).map_err(RestoreExecutionError::UnsafeIntent)?;
    let (messages_tx, messages) = mpsc::channel();
    let cancel_requested = Arc::new(AtomicBool::new(false));
    let cancel_for_worker = Arc::clone(&cancel_requested);

    std::thread::Builder::new()
        .name("letrecovery-native-restore".to_owned())
        .spawn(move || run_intent(intent, cancel_for_worker, messages_tx))
        .map_err(|error| RestoreExecutionError::Spawn(error.to_string()))?;

    Ok(RestoreExecution {
        messages,
        cancel_requested,
    })
}

#[cfg(not(feature = "non-elevated-tests"))]
fn run_intent(
    intent: AuthorizedPeRestoreIntent,
    cancel_requested: Arc<AtomicBool>,
    messages: Sender<RestoreWorkerMessage>,
) {
    let _ = messages.send(RestoreWorkerMessage::Started);

    if cancel_requested.load(Ordering::SeqCst) {
        let _ = messages.send(RestoreWorkerMessage::Cancelled);
        return;
    }

    match run_pe_handoff(intent, &cancel_requested, &messages) {
        Ok(()) => {
            let _ = messages.send(RestoreWorkerMessage::Completed);
        }
        Err(RestoreRunError::Cancelled) => {
            let _ = messages.send(RestoreWorkerMessage::Cancelled);
        }
        Err(RestoreRunError::Failed(error)) => {
            let _ = messages.send(RestoreWorkerMessage::Failed { error });
        }
    }
}

#[cfg(not(feature = "non-elevated-tests"))]
enum RestoreRunError {
    Cancelled,
    Failed(String),
}

#[cfg(not(feature = "non-elevated-tests"))]
fn run_pe_handoff(
    authorized: AuthorizedPeRestoreIntent,
    cancel_requested: &AtomicBool,
    messages: &Sender<RestoreWorkerMessage>,
) -> Result<(), RestoreRunError> {
    let AuthorizedPeRestoreIntent {
        intent,
        authorization,
        requires_bitlocker_secret,
    } = authorized;
    send_progress(messages, 10, &crate::tr!("正在验证 PE 环境"));
    let pe_snapshot = require_verified_cached_pe(&intent.pe).map_err(RestoreRunError::Failed)?;
    stop_before_next_stage(cancel_requested)?;

    let image_letter =
        lr_core::windows_storage::path_drive_letter(Path::new(&intent.config.image_path))
            .ok_or_else(|| {
                RestoreRunError::Failed("restore image has no local drive".to_owned())
            })?;
    let current_image =
        lr_core::windows_storage::stable_volume_identity(image_letter).map_err(|error| {
            RestoreRunError::Failed(format!("recheck restore image volume: {error}"))
        })?;
    if !lr_core::windows_storage::same_stable_volume_identity(authorization.image, current_image) {
        return Err(RestoreRunError::Failed(
            "restore image drive letter changed before handoff".to_owned(),
        ));
    }
    let target_letter =
        lr_core::windows_storage::path_drive_letter(Path::new(&intent.config.target_partition))
            .ok_or_else(|| {
                RestoreRunError::Failed("restore target has no local drive".to_owned())
            })?;
    let current_target =
        lr_core::windows_storage::stable_volume_identity(target_letter).map_err(|error| {
            RestoreRunError::Failed(format!("recheck restore target volume: {error}"))
        })?;
    if !lr_core::windows_storage::same_stable_volume_identity(authorization.target, current_target)
    {
        return Err(RestoreRunError::Failed(
            "restore target drive letter changed before authenticated handoff".to_owned(),
        ));
    }
    let image_status =
        strict_bitlocker_status(&format!("{}:", image_letter)).map_err(RestoreRunError::Failed)?;
    let target_status =
        strict_bitlocker_status(&format!("{}:", target_letter)).map_err(RestoreRunError::Failed)?;
    let known_via_pe_status = |status| {
        matches!(
            status,
            crate::core::bitlocker::VolumeStatus::NotEncrypted
                | crate::core::bitlocker::VolumeStatus::EncryptedUnlocked
                | crate::core::bitlocker::VolumeStatus::EncryptedLocked
        )
    };
    if !known_via_pe_status(image_status) || !known_via_pe_status(target_status) {
        return Err(RestoreRunError::Failed(format!(
            "PE restore volume BitLocker state changed to an unsupported state (image={image_status:?}, target={target_status:?})"
        )));
    }
    let requires_bitlocker_secret = requires_bitlocker_secret
        || image_status != crate::core::bitlocker::VolumeStatus::NotEncrypted
        || target_status != crate::core::bitlocker::VolumeStatus::NotEncrypted;
    let image_partition = format!("{}:", image_letter);
    send_progress(messages, 30, &crate::tr!("正在暂存还原配置"));
    let handoff_auth_key = lr_core::handoff_auth::SessionAuthKey::generate().map_err(|error| {
        RestoreRunError::Failed(format!("generate authenticated PE handoff key: {error}"))
    })?;
    let bitlocker_secret = crate::core::install_config::collect_bitlocker_secret_best_effort();
    if requires_bitlocker_secret && bitlocker_secret.is_none() {
        return Err(RestoreRunError::Failed(
            "PE restore needs a Windows-held BitLocker recovery password for an encrypted image or target volume, but none was available".to_owned(),
        ));
    }
    let mut transaction =
        ConfigFileManager::write_restore_config_transactional_with_bitlocker_secret(
            &image_partition,
            &intent.config.target_partition,
            &intent.config,
            &handoff_auth_key,
            bitlocker_secret,
        )
        .map_err(|error| RestoreRunError::Failed(format!("还原配置写入失败: {error}")))?;

    if let Err(cancelled) = stop_before_next_stage(cancel_requested) {
        if let Err(error) = transaction.rollback() {
            log::error!("取消 PE 还原交接时回滚暂存配置失败: {error}");
        }
        return Err(cancelled);
    }
    send_progress(messages, 60, &crate::tr!("正在安装 PE 启动项"));
    let _ = messages.send(RestoreWorkerMessage::PeCommitStarted);
    let session_id = &intent
        .config
        .handoff
        .as_ref()
        .ok_or_else(|| RestoreRunError::Failed("missing LRRH2 session".to_owned()))?
        .session_id;
    let config_bytes = transaction.take_boot_config_bytes().map_err(|error| {
        RestoreRunError::Failed(format!("take authenticated restore config: {error}"))
    })?;
    let manifest_bytes = transaction.take_boot_manifest_bytes().map_err(|error| {
        RestoreRunError::Failed(format!("take authenticated restore manifest: {error}"))
    })?;
    let bitlocker_secret = transaction.take_bitlocker_secret();
    let payload = crate::core::pe::HandoffBootPayload::new(
        handoff_auth_key,
        lr_core::handoff_auth::HandoffPurpose::Restore,
        session_id,
        config_bytes,
        manifest_bytes,
        None,
        None,
    )
    .map_err(|error| {
        RestoreRunError::Failed(format!("build authenticated restore boot payload: {error}"))
    })?;
    let payload = match bitlocker_secret {
        Some(secret) => payload.with_bitlocker_secret(secret).map_err(|error| {
            RestoreRunError::Failed(format!("bind protected BitLocker boot secret: {error}"))
        })?,
        None => payload,
    };
    if let Err(error) = crate::core::pe::PeManager::new()
        .boot_to_pe_for_restore(
            &pe_snapshot.path.to_string_lossy(),
            &intent.pe.display_name,
            payload,
        )
        .and_then(|transaction| transaction.commit())
    {
        let rollback = transaction.rollback();
        let detail = match rollback {
            Ok(()) => format!("PE 启动项安装失败，还原配置已回滚: {error}"),
            Err(rollback_error) => {
                format!("PE 启动项安装失败: {error}; 还原配置回滚也失败: {rollback_error}")
            }
        };
        return Err(RestoreRunError::Failed(detail));
    }
    send_progress(messages, 100, &crate::tr!("PE 还原准备完成"));
    Ok(())
}

#[cfg(not(feature = "non-elevated-tests"))]
fn stop_before_next_stage(cancel_requested: &AtomicBool) -> Result<(), RestoreRunError> {
    if cancel_requested.load(Ordering::SeqCst) {
        Err(RestoreRunError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(not(feature = "non-elevated-tests"))]
fn send_progress(messages: &Sender<RestoreWorkerMessage>, percentage: u8, status: &str) {
    let _ = messages.send(RestoreWorkerMessage::Progress {
        percentage,
        status: status.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_message_keeps_terminal_state_explicit() {
        assert_ne!(
            RestoreWorkerMessage::Completed,
            RestoreWorkerMessage::Cancelled
        );
    }

    #[cfg(feature = "non-elevated-tests")]
    #[test]
    fn development_feature_fails_closed_before_starting_a_worker() {
        let intent = PeRestorePreparationIntent {
            config: crate::core::install_config::RestoreConfig {
                image_path: "D:\\RZhuangJi_Backups\\system.wim".to_owned(),
                target_partition: "C:".to_owned(),
                image_index: 1,
                image_name: "System Backup".to_owned(),
                image_description: String::new(),
                wim_engine: 0,
                handoff: None,
            },
            pe: crate::download::config::OnlinePE {
                download_url: "https://example.invalid/pe.wim".to_owned(),
                display_name: "R装机 PE".to_owned(),
                filename: "RZhuangJi_PE.wim".to_owned(),
                md5: None,
                sha256: Some("00".repeat(32)),
            },
        };
        assert!(matches!(
            execute_restore(intent),
            Err(RestoreExecutionError::DisabledInDevelopment)
        ));
    }
}
