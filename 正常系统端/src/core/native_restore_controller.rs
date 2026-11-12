//! Pure launch planning for the native system-restore UI.
//!
//! Restore always runs inside PE: the target is the live system partition, so there is no
//! direct mode. The planner mirrors the backup planner's shape but deliberately has no
//! executor: it does not inspect disks, download or install PE, write configuration, start a
//! worker, or reboot.

use crate::core::install_config::RestoreConfig;
use crate::download::config::OnlinePE;

/// Request for the PE preparation/handoff pipeline.
///
/// Consumers must still perform cached-artifact verification immediately before use and write
/// the restore configuration through the existing safe handoff path.
#[derive(Debug, Clone)]
pub struct PeRestorePreparationIntent {
    pub config: RestoreConfig,
    pub pe: OnlinePE,
}

#[derive(Debug, Clone, Copy)]
pub struct RestoreStableAuthorization {
    pub image: lr_core::windows_storage::StableVolumeIdentity,
    pub target: lr_core::windows_storage::StableVolumeIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreLaunchPreview {
    pub image_path: String,
    pub target_partition: String,
    pub image_index: u32,
    pub image_name: String,
    pub pe_display_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RestoreLaunchPlan {
    pub preview: RestoreLaunchPreview,
    pub intent: PeRestorePreparationIntent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestorePlanningError {
    ImagePathMissing,
    InvalidImagePath,
    UnsupportedImageExtension,
    TargetPartitionMissing,
    InvalidImageIndex,
    PeUnavailable,
}

impl std::fmt::Display for RestorePlanningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImagePathMissing => formatter.write_str("备份镜像路径不能为空"),
            Self::InvalidImagePath => {
                formatter.write_str(&crate::tr!("备份镜像路径必须是绝对文件路径"))
            }
            Self::UnsupportedImageExtension => {
                formatter.write_str(&crate::tr!("系统还原只支持 .wim / .esd 备份镜像"))
            }
            Self::TargetPartitionMissing => formatter.write_str("还原目标分区不能为空"),
            Self::InvalidImageIndex => formatter.write_str("映像索引必须从 1 开始"),
            Self::PeUnavailable => {
                formatter.write_str(&crate::tr!("系统还原需要可用的 PE 环境。"))
            }
        }
    }
}

impl std::error::Error for RestorePlanningError {}

/// Builds a side-effect-free launch plan from an already validated restore configuration.
pub fn plan_restore_launch(
    config: &RestoreConfig,
    first_available_pe: Option<&OnlinePE>,
) -> Result<RestoreLaunchPlan, RestorePlanningError> {
    validate_minimum_config(config)?;
    let pe = first_available_pe.ok_or(RestorePlanningError::PeUnavailable)?;
    let preview = RestoreLaunchPreview {
        image_path: config.image_path.clone(),
        target_partition: config.target_partition.clone(),
        image_index: config.image_index,
        image_name: config.image_name.clone(),
        pe_display_name: Some(pe.display_name.clone()),
    };
    Ok(RestoreLaunchPlan {
        preview,
        intent: PeRestorePreparationIntent {
            config: config.clone(),
            pe: pe.clone(),
        },
    })
}

fn validate_minimum_config(config: &RestoreConfig) -> Result<(), RestorePlanningError> {
    if config.image_path.trim().is_empty() {
        return Err(RestorePlanningError::ImagePathMissing);
    }
    if config.target_partition.trim().is_empty() {
        return Err(RestorePlanningError::TargetPartitionMissing);
    }
    if config.image_index == 0 {
        return Err(RestorePlanningError::InvalidImageIndex);
    }
    let path = std::path::Path::new(config.image_path.trim());
    if !crate::core::native_backup_controller::is_absolute_windows_file_path(
        config.image_path.trim(),
    ) || path.file_name().is_none()
    {
        return Err(RestorePlanningError::InvalidImagePath);
    }
    let supported = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("wim") || value.eq_ignore_ascii_case("esd")
        });
    if !supported {
        return Err(RestorePlanningError::UnsupportedImageExtension);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RestoreConfig {
        RestoreConfig {
            image_path: "D:\\RZhuangJi_Backups\\system.wim".to_owned(),
            target_partition: "C:".to_owned(),
            image_index: 1,
            image_name: "System Backup".to_owned(),
            image_description: "Created by R装机".to_owned(),
            wim_engine: 0,
            handoff: None,
        }
    }

    fn pe() -> OnlinePE {
        OnlinePE {
            download_url: "https://example.invalid/pe.wim".to_owned(),
            display_name: "R装机 PE".to_owned(),
            filename: "RZhuangJi_PE.wim".to_owned(),
            md5: None,
            sha256: Some("00".repeat(32)),
        }
    }

    #[test]
    fn restore_requires_an_available_pe() {
        assert!(matches!(
            plan_restore_launch(&config(), None),
            Err(RestorePlanningError::PeUnavailable)
        ));
        let plan = plan_restore_launch(&config(), Some(&pe())).unwrap();
        assert_eq!(plan.preview.pe_display_name.as_deref(), Some("R装机 PE"));
        assert_eq!(plan.intent.config.image_index, 1);
        assert_eq!(plan.intent.pe.filename, "RZhuangJi_PE.wim");
    }

    #[test]
    fn image_must_be_an_absolute_wim_or_esd_file() {
        let mut value = config();
        value.image_path = "system.wim".to_owned();
        assert!(matches!(
            plan_restore_launch(&value, Some(&pe())),
            Err(RestorePlanningError::InvalidImagePath)
        ));

        value.image_path = "D:\\RZhuangJi_Backups\\system.gho".to_owned();
        assert!(matches!(
            plan_restore_launch(&value, Some(&pe())),
            Err(RestorePlanningError::UnsupportedImageExtension)
        ));

        value.image_path = "D:\\RZhuangJi_Backups\\system.esd".to_owned();
        assert!(plan_restore_launch(&value, Some(&pe())).is_ok());
    }

    #[test]
    fn missing_fields_are_rejected_without_creating_an_intent() {
        let mut value = config();
        value.image_path = "  ".to_owned();
        assert!(matches!(
            plan_restore_launch(&value, Some(&pe())),
            Err(RestorePlanningError::ImagePathMissing)
        ));
        let mut value = config();
        value.target_partition = String::new();
        assert!(matches!(
            plan_restore_launch(&value, Some(&pe())),
            Err(RestorePlanningError::TargetPartitionMissing)
        ));
        let mut value = config();
        value.image_index = 0;
        assert!(matches!(
            plan_restore_launch(&value, Some(&pe())),
            Err(RestorePlanningError::InvalidImageIndex)
        ));
    }
}
