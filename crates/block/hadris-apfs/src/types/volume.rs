//! APFS volume superblock parsing.

use crate::types::object::{ObjectHeader, ObjectType};
use crate::types::{le_u32, le_u64, take};

/// Magic value in volume superblocks (`APSB` on disk).
pub const VOLUME_MAGIC: [u8; 4] = *b"APSB";
/// Length of the APFS volume name field.
pub const VOLUME_NAME_LENGTH: usize = 256;
/// Volume flag (`APFS_FS_UNENCRYPTED`): the volume's filesystem tree is
/// stored unencrypted.
pub const VOLUME_FLAG_UNENCRYPTED: u64 = 0x0000_0001;

/// Parsed APFS volume superblock (`apfs_superblock_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSuperblock {
    /// Common object header.
    pub object: ObjectHeader,
    /// Volume index in the container volume array.
    pub fs_index: u32,
    /// Optional feature flags.
    pub optional_features: u64,
    /// Read-only compatible feature flags.
    pub readonly_compatible_features: u64,
    /// Incompatible feature flags.
    pub incompatible_features: u64,
    /// Blocks allocated by the volume.
    pub allocated_block_count: u64,
    /// Volume object map physical OID.
    pub object_map_oid: u64,
    /// Root filesystem tree OID.
    pub root_tree_oid: u64,
    /// Extent-reference tree OID.
    pub extent_reference_tree_oid: u64,
    /// Snapshot metadata tree OID.
    pub snapshot_metadata_tree_oid: u64,
    /// Number of regular files.
    pub number_files: u64,
    /// Number of directories.
    pub number_directories: u64,
    /// Number of symbolic links.
    pub number_symlinks: u64,
    /// Number of snapshots.
    pub number_snapshots: u64,
    /// Volume UUID.
    pub volume_id: [u8; 16],
    /// Volume flags.
    pub flags: u64,
    /// Null-terminated UTF-8 volume name bytes.
    pub volume_name: [u8; VOLUME_NAME_LENGTH],
    /// Transaction identifier of the snapshot this volume roots from, or 0
    /// to root normally from the volume's own live state
    /// (`apfs_root_to_xid`).
    ///
    /// Set on sealed system volumes (and other volumes mounted from a
    /// specific snapshot instead of their live state): the volume
    /// superblock's own `object.transaction_identifier` keeps advancing as
    /// the container is written to, but the *filesystem tree actually
    /// presented to users* is frozen at this transaction. Resolving
    /// virtual object-map lookups against the live transaction id instead
    /// of this one walks blocks the live filesystem has since freed and
    /// reused, surfacing as spurious checksum mismatches on an otherwise
    /// perfectly healthy, unencrypted, and even read-only volume. See
    /// [`Self::default_read_transaction_id`].
    pub root_to_xid: u64,
}

impl VolumeSuperblock {
    /// Parses a volume superblock from bytes beginning at an APFS object.
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        let object = ObjectHeader::parse(data)?;
        if object.kind() != ObjectType::VolumeSuperblock as u16 {
            return Err(crate::ApfsError::InvalidValue(
                "volume superblock object type",
            ));
        }
        let magic = take::<4>(data, 32)?;
        if magic != VOLUME_MAGIC {
            return Err(crate::ApfsError::InvalidMagic {
                expected: VOLUME_MAGIC,
                actual: magic,
            });
        }
        Ok(Self {
            object,
            fs_index: le_u32(data, 36)?,
            optional_features: le_u64(data, 40)?,
            readonly_compatible_features: le_u64(data, 48)?,
            incompatible_features: le_u64(data, 56)?,
            allocated_block_count: le_u64(data, 88)?,
            object_map_oid: le_u64(data, 128)?,
            root_tree_oid: le_u64(data, 136)?,
            extent_reference_tree_oid: le_u64(data, 144)?,
            snapshot_metadata_tree_oid: le_u64(data, 152)?,
            number_files: le_u64(data, 184)?,
            number_directories: le_u64(data, 192)?,
            number_symlinks: le_u64(data, 200)?,
            number_snapshots: le_u64(data, 216)?,
            volume_id: take(data, 240)?,
            flags: le_u64(data, 264)?,
            volume_name: take(data, 704)?,
            root_to_xid: le_u64(data, 968)?,
        })
    }

    /// Returns whether the volume's filesystem tree is encrypted on disk.
    ///
    /// When true, the volume superblock and object map are still readable
    /// (APFS keeps container-level metadata in plaintext), but the
    /// filesystem B-tree blocks the object map points at are AES-XTS
    /// ciphertext: reading them raw yields bytes whose stored checksum
    /// field cannot verify, surfacing as a deterministic
    /// [`crate::ApfsError::ChecksumMismatch`]. Decrypting them requires
    /// unwrapping the volume encryption key from the container keybag,
    /// which this crate does not implement. Note that Apple Silicon and T2
    /// Macs encrypt the Data volume even when FileVault is disabled.
    pub const fn is_encrypted(&self) -> bool {
        self.flags & VOLUME_FLAG_UNENCRYPTED == 0
    }

    /// Returns the volume name as UTF-8 up to the first NUL byte.
    pub fn name(&self) -> crate::Result<&str> {
        let len = self
            .volume_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(VOLUME_NAME_LENGTH);
        core::str::from_utf8(&self.volume_name[..len])
            .map_err(|_| crate::ApfsError::InvalidValue("volume name UTF-8"))
    }

    /// Returns the transaction identifier B-tree walks rooted at this
    /// volume should default to bounding lookups by.
    ///
    /// This is [`Self::root_to_xid`] when non-zero (the volume is mounted
    /// from a frozen snapshot, as with a sealed system volume), otherwise
    /// the volume superblock's own live transaction identifier.
    pub const fn default_read_transaction_id(&self) -> u64 {
        if self.root_to_xid != 0 {
            self.root_to_xid
        } else {
            self.object.transaction_identifier
        }
    }
}
