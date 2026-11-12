//! Versioned, drive-letter-independent restore authorization shared by normal Windows and WinPE.
//!
//! LRRH2 mirrors the LRBK2 backup authorization shape: the normal endpoint binds the exact
//! backup image file (length + SHA-256 + catalog index), the stable identity of the volume
//! holding that image, and the stable identity of the target system volume to be overwritten.
//! WinPE rebinds both volumes by canonical layout identity only; drive letters are display
//! values and never select a disk. Only WIM/ESD backup images are restorable — GHO and other
//! foreign formats are deliberately outside this protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::Digest;

use crate::backup_handoff::{parse_volume, serialize_volume, validate_relative_output_path};
use crate::install_handoff::{encode_hex, unique_canonical_target_match, CanonicalInstallTargetV2};
use crate::windows_storage::DiskLayoutSnapshot;

pub const RESTORE_HANDOFF_VERSION: u8 = 2;
pub const RESTORE_MARKER_MAGIC: &str = "LRRH2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreImageIdentity {
    pub length_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePayloadFields {
    pub image_path: String,
    pub target_partition: String,
    pub image_name: String,
    pub image_description: String,
    pub wim_engine: u8,
    pub language: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreHandoffV2 {
    pub session_id: String,
    pub image_volume: CanonicalInstallTargetV2,
    pub image_relative_path: PathBuf,
    pub image: RestoreImageIdentity,
    pub target: CanonicalInstallTargetV2,
    pub image_index: u32,
}

impl RestoreHandoffV2 {
    pub fn validate(&self) -> Result<()> {
        crate::handoff_auth::validate_session_id(&self.session_id)?;
        validate_relative_output_path(&self.image_relative_path)?;
        validate_restore_image_path(&self.image_relative_path)?;
        if self.image.length_bytes == 0 {
            bail!("restore image length must be non-zero");
        }
        if self.image.sha256 == [0; 32] {
            bail!("restore image SHA-256 must not be all-zero");
        }
        if self.image_index == 0 {
            bail!("restore image index must be at least one");
        }
        if self.image_volume == self.target {
            bail!("restore image volume and target volume resolve to the same stable volume");
        }
        Ok(())
    }

    pub fn serialize_fields(&self) -> Result<String> {
        self.validate()?;
        let relative_path = self
            .image_relative_path
            .to_str()
            .context("restore image path is not valid Unicode")?;
        Ok(format!(
            "HandoffVersion={}\r\nSessionId={}\r\nImageRelativePath={}\r\nImageLengthBytes={}\r\nImageSha256={}\r\nImageIndex={}\r\n{}{}",
            RESTORE_HANDOFF_VERSION,
            self.session_id,
            relative_path,
            self.image.length_bytes,
            encode_hex(&self.image.sha256),
            self.image_index,
            serialize_volume("ImageVolume", &self.image_volume),
            serialize_volume("Target", &self.target),
        ))
    }

    pub fn parse_fields(content: &str) -> Result<Self> {
        let fields = parse_strict_restore_fields(content)?;
        parse_handoff_from_fields(&fields)
    }
}

pub fn parse_restore_payload(content: &str) -> Result<(RestorePayloadFields, RestoreHandoffV2)> {
    if content.len() > 128 * 1024 {
        bail!("restore handoff exceeds its byte limit");
    }
    let fields = parse_strict_restore_fields(content)?;
    let value = |name: &str| -> Result<&str> {
        fields
            .get(name)
            .copied()
            .with_context(|| format!("missing restore handoff field {name}"))
    };
    let image_path = value("ImagePath")?.to_owned();
    let target_partition = value("TargetPartition")?.to_owned();
    let image_name = value("ImageName")?.to_owned();
    let image_description = value("ImageDescription")?.to_owned();
    let language = value("Language")?.to_owned();
    validate_text(&image_path, 32_767, false, "ImagePath")?;
    validate_text(&image_name, 256, false, "ImageName")?;
    validate_text(&image_description, 2_048, true, "ImageDescription")?;
    validate_text(&language, 32, false, "Language")?;
    if target_partition.len() != 2
        || !target_partition.as_bytes()[0].is_ascii_alphabetic()
        || target_partition.as_bytes()[1] != b':'
    {
        bail!("TargetPartition must be one local drive letter");
    }
    let wim_engine = value("WimEngine")?
        .parse::<u8>()
        .context("invalid WimEngine")?;
    if wim_engine > 1 {
        bail!("unsupported WimEngine");
    }
    let handoff = parse_handoff_from_fields(&fields)?;
    Ok((
        RestorePayloadFields {
            image_path,
            target_partition,
            image_name,
            image_description,
            wim_engine,
            language,
        },
        handoff,
    ))
}

fn validate_text(value: &str, maximum_utf16: usize, allow_empty: bool, field: &str) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.encode_utf16().count() > maximum_utf16
        || value.chars().any(char::is_control)
    {
        bail!("invalid or oversized restore field {field}");
    }
    Ok(())
}

fn validate_restore_image_path(path: &Path) -> Result<()> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    match extension.as_deref() {
        Some("wim" | "esd") => Ok(()),
        _ => bail!("restore image must be a WIM or ESD file; other formats are not supported"),
    }
}

fn parse_handoff_from_fields(fields: &BTreeMap<&str, &str>) -> Result<RestoreHandoffV2> {
    let value = |name: &str| -> Result<&str> {
        fields
            .get(name)
            .copied()
            .with_context(|| format!("missing restore handoff field {name}"))
    };
    let version = value("HandoffVersion")?
        .parse::<u8>()
        .context("invalid restore handoff version")?;
    if version != RESTORE_HANDOFF_VERSION {
        bail!("unsupported restore handoff version {version}");
    }
    let image_volume = parse_volume("ImageVolume", fields)?;
    let target = parse_volume("Target", fields)?;
    let handoff = RestoreHandoffV2 {
        session_id: value("SessionId")?.to_string(),
        image_volume,
        image_relative_path: PathBuf::from(value("ImageRelativePath")?),
        image: RestoreImageIdentity {
            length_bytes: value("ImageLengthBytes")?
                .parse::<u64>()
                .context("invalid restore image length")?,
            sha256: crate::install_handoff::decode_hex_array::<32>(
                value("ImageSha256")?,
                "ImageSha256",
            )
            .context("invalid restore image SHA-256")?,
        },
        target,
        image_index: value("ImageIndex")?
            .parse::<u32>()
            .context("invalid restore ImageIndex")?,
    };
    handoff.validate()?;
    Ok(handoff)
}

fn parse_strict_restore_fields(content: &str) -> Result<BTreeMap<&str, &str>> {
    const REQUIRED: &[&str] = &[
        "ImagePath",
        "TargetPartition",
        "ImageName",
        "ImageDescription",
        "WimEngine",
        "Language",
        "HandoffVersion",
        "SessionId",
        "ImageRelativePath",
        "ImageLengthBytes",
        "ImageSha256",
        "ImageIndex",
        "ImageVolumeCanonicalVersion",
        "ImageVolumeLayoutSha256",
        "ImageVolumeOffsetBytes",
        "ImageVolumeLengthBytes",
        "ImageVolumeDiskStyle",
        "ImageVolumeGptPartitionId",
        "TargetCanonicalVersion",
        "TargetLayoutSha256",
        "TargetOffsetBytes",
        "TargetLengthBytes",
        "TargetDiskStyle",
        "TargetGptPartitionId",
    ];
    const OPTIONAL: &[&str] = &[
        "ImageVolumeStorageIdSha256",
        "TargetStorageIdSha256",
        "HandoffManifestVersion",
        "HandoffManifestLength",
        "HandoffManifestSha256",
    ];

    let allowed = REQUIRED
        .iter()
        .chain(OPTIONAL.iter())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut fields = BTreeMap::new();
    let mut saw_restore_section = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if line != "[Restore]" || saw_restore_section {
                bail!("unknown or duplicate restore handoff section: {line}");
            }
            saw_restore_section = true;
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .with_context(|| format!("invalid restore handoff line: {line}"))?;
        let key = key.trim();
        let value = raw_value.trim();
        if !allowed.contains(key) {
            bail!("unknown restore handoff field {key}");
        }
        if fields.insert(key, value).is_some() {
            bail!("duplicate restore handoff field {key}");
        }
    }
    if !saw_restore_section {
        bail!("missing [Restore] section");
    }
    for key in REQUIRED {
        if !fields.contains_key(key) {
            bail!("missing restore handoff field {key}");
        }
    }
    Ok(fields)
}

pub fn bind_unique_restore_volumes(
    handoff: &RestoreHandoffV2,
    candidates: &[(u32, DiskLayoutSnapshot)],
) -> Result<(u32, u32)> {
    handoff.validate()?;
    let image_disk = unique_canonical_target_match(&handoff.image_volume, candidates)
        .context("rebind restore image volume")?;
    let target_disk = unique_canonical_target_match(&handoff.target, candidates)
        .context("rebind restore target volume")?;
    if image_disk == target_disk
        && handoff.image_volume.partition_offset_bytes == handoff.target.partition_offset_bytes
    {
        bail!("restore image and target rebound to the same physical volume");
    }
    Ok((image_disk, target_disk))
}

pub fn marker_text(session_id: &str, config_bytes: &[u8]) -> Result<String> {
    crate::handoff_auth::validate_session_id(session_id)?;
    let digest = sha2::Sha256::digest(config_bytes);
    Ok(format!(
        "{RESTORE_MARKER_MAGIC}\r\nSessionId={session_id}\r\nConfigSha256={}\r\n",
        encode_hex(&digest)
    ))
}

pub fn validate_marker(
    marker: &str,
    handoff: &RestoreHandoffV2,
    config_bytes: &[u8],
) -> Result<()> {
    if marker.lines().next().map(str::trim) != Some(RESTORE_MARKER_MAGIC) {
        bail!("invalid restore marker version");
    }
    let expected = marker_text(&handoff.session_id, config_bytes)?;
    if marker.replace('\n', "\r\n").replace("\r\r\n", "\r\n") != expected {
        bail!("restore marker does not match the exact session/configuration");
    }
    Ok(())
}

pub fn marker_session_id(marker: &str) -> Result<&str> {
    let mut lines = marker.lines().map(str::trim);
    if lines.next() != Some(RESTORE_MARKER_MAGIC) {
        bail!("invalid restore marker version");
    }
    let session = lines
        .next()
        .and_then(|line| line.strip_prefix("SessionId="))
        .context("restore marker is missing SessionId")?;
    crate::handoff_auth::validate_session_id(session)?;
    let hash = lines
        .next()
        .and_then(|line| line.strip_prefix("ConfigSha256="))
        .context("restore marker is missing ConfigSha256")?;
    let _ = crate::install_handoff::decode_hex_array::<32>(hash, "ConfigSha256")?;
    if lines.next().is_some() {
        bail!("restore marker has trailing fields");
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_handoff::{CanonicalInstallTargetV2, CanonicalTargetStyle};

    fn volume(byte: u8, offset: u64) -> CanonicalInstallTargetV2 {
        CanonicalInstallTargetV2 {
            layout_digest: [byte; 32],
            device_id_hash: Some([byte.wrapping_add(1); 32]),
            partition_offset_bytes: offset,
            partition_length_bytes: 1024,
            style: CanonicalTargetStyle::Gpt,
            gpt_partition_id: Some([byte; 16]),
        }
    }

    fn handoff() -> RestoreHandoffV2 {
        RestoreHandoffV2 {
            session_id: "0123456789abcdef0123456789abcdef".into(),
            image_volume: volume(1, 1024),
            image_relative_path: PathBuf::from("backups\\system.wim"),
            image: RestoreImageIdentity {
                length_bytes: 4096,
                sha256: [9; 32],
            },
            target: volume(2, 2048),
            image_index: 1,
        }
    }

    fn serialized_config(value: &RestoreHandoffV2) -> String {
        format!(
            "[Restore]\r\nImagePath=D:\\backups\\system.wim\r\nTargetPartition=C:\r\nImageName=System\r\nImageDescription=\r\nWimEngine=0\r\nLanguage=zh-CN\r\n{}",
            value.serialize_fields().unwrap()
        )
    }

    #[test]
    fn round_trip_preserves_image_target_and_index() {
        let expected = handoff();
        let text = serialized_config(&expected);
        let (payload, parsed) = parse_restore_payload(&text).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(payload.image_path, "D:\\backups\\system.wim");
        assert_eq!(payload.target_partition, "C:");
        assert_eq!(RestoreHandoffV2::parse_fields(&text).unwrap(), expected);
    }

    #[test]
    fn same_volume_zero_index_and_foreign_formats_are_rejected() {
        let mut same_volume = handoff();
        same_volume.target = same_volume.image_volume.clone();
        assert!(same_volume.validate().is_err());

        let mut zero_index = handoff();
        zero_index.image_index = 0;
        assert!(zero_index.validate().is_err());

        let mut zero_length = handoff();
        zero_length.image.length_bytes = 0;
        assert!(zero_length.validate().is_err());

        for path in [
            "backups\\system.gho",
            "backups\\system.swm",
            "backups\\system",
        ] {
            let mut foreign = handoff();
            foreign.image_relative_path = PathBuf::from(path);
            assert!(
                foreign.validate().is_err(),
                "accepted foreign format {path}"
            );
        }

        let mut traversal = handoff();
        traversal.image_relative_path = PathBuf::from("..\\system.wim");
        assert!(traversal.validate().is_err());
    }

    #[test]
    fn stale_marker_and_unknown_fields_are_rejected() {
        let valid = handoff();
        let marker = marker_text(&valid.session_id, b"one").unwrap();
        assert!(validate_marker(&marker, &valid, b"two").is_err());
        assert_eq!(
            marker_session_id(&marker).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        let text = serialized_config(&valid);
        assert!(RestoreHandoffV2::parse_fields(&format!("{text}Unexpected=true\r\n")).is_err());
        assert!(parse_restore_payload(&text.replace("WimEngine=0", "WimEngine=9")).is_err());
        assert!(parse_restore_payload(&text.replace("ImageIndex=1", "ImageIndex=0")).is_err());
    }
}
