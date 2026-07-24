//! APFS keybag (`kb_locker_t`/`media_keybag_t`) parsing.
//!
//! Every APFS container has a keybag at the block range recorded by the
//! container superblock's `nx_keylocker`, holding wrapped Volume Encryption
//! Keys (VEKs) and pointers to each volume's own keybag (which in turn holds
//! wrapped Key Encryption Keys, one per enrolled user/password/recovery key).
//! See [`crate::crypto`] for unwrapping these into usable AES-XTS keys.

use crate::types::object::ObjectHeader;
use crate::types::{le_u16, le_u32, le_u64};

/// Raw APFS object type of a container keybag (`APFS_KEYBAG_OBJ`, `'keys'`).
///
/// Unlike the small sequential values in [`ObjectType`], keybag object types
/// are ASCII four-character codes and are compared against the *entire*
/// 32-bit `o_type` field, not just [`ObjectHeader::kind`]'s low 16 bits.
pub const CONTAINER_KEYBAG_OBJECT_TYPE: u32 = 0x6B65_7973;
/// Raw APFS object type of a volume keybag (`APFS_VOL_KEYBAG_OBJ`, `'recs'`).
pub const VOLUME_KEYBAG_OBJECT_TYPE: u32 = 0x7265_6373;

/// Current keybag format version (`KEYBAG_VERSION`).
pub const KEYBAG_VERSION: u16 = 2;

/// A keybag entry's tag, describing what kind of key material it holds
/// (`keybag_tag_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KeybagTag {
    /// Reserved; never expected on disk.
    Unknown = 0,
    /// Reserved (`KB_TAG_WRAPPING_KEY`).
    WrappingKey = 1,
    /// Wrapped Volume Encryption Key (container keybag only).
    VolumeKey = 2,
    /// In a container keybag: location of a volume's own keybag. In a
    /// volume keybag: a wrapped Key Encryption Key.
    VolumeUnlockRecords = 3,
    /// User-supplied password hint, stored as plain text (volume keybag only).
    VolumePassphraseHint = 4,
    /// Reserved (`KB_TAG_USER_PAYLOAD`).
    UserPayload = 5,
}

impl KeybagTag {
    /// Converts a raw on-disk tag value to a known variant, if recognized.
    pub const fn from_raw(value: u16) -> Option<Self> {
        Some(match value {
            0 => Self::Unknown,
            1 => Self::WrappingKey,
            2 => Self::VolumeKey,
            3 => Self::VolumeUnlockRecords,
            4 => Self::VolumePassphraseHint,
            5 => Self::UserPayload,
            _ => return None,
        })
    }
}

/// A physical block range (`prange_t`): used by keybag entries that point at
/// another keybag's location on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRange {
    /// First physical APFS block address in the range.
    pub start_block: u64,
    /// Number of blocks in the range.
    pub block_count: u64,
}

impl PhysicalRange {
    /// Parses a physical range from its 16-byte on-disk representation.
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        Ok(Self {
            start_block: le_u64(data, 0)?,
            block_count: le_u64(data, 8)?,
        })
    }
}

/// One entry in a keybag (`keybag_entry_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeybagEntry {
    /// In a container keybag: a volume's UUID. In a volume keybag: a user's UUID.
    pub uuid: [u8; 16],
    /// Raw on-disk tag value; see [`KeybagTag`] for known values.
    pub tag: u16,
    /// This entry's key data.
    pub key_data: alloc::vec::Vec<u8>,
}

impl KeybagEntry {
    /// Fixed-size header preceding an entry's variable-length key data.
    const HEADER_SIZE: usize = 24;

    /// Parses one keybag entry starting at `data`'s beginning, returning the
    /// parsed entry and the total size (header + key data, rounded up to a
    /// 16-byte boundary) it occupies.
    fn parse_one(data: &[u8]) -> crate::Result<(Self, usize)> {
        let uuid = crate::types::take::<16>(data, 0)?;
        let tag = le_u16(data, 16)?;
        let key_length = le_u16(data, 18)? as usize;
        let key_data = data
            .get(Self::HEADER_SIZE..Self::HEADER_SIZE + key_length)
            .ok_or(crate::ApfsError::InputTooSmall)?
            .to_vec();
        let occupied = (key_length + Self::HEADER_SIZE + 0x0f) & !0x0f;
        Ok((
            Self {
                uuid,
                tag,
                key_data,
            },
            occupied,
        ))
    }
}

/// A parsed keybag (`kb_locker_t`), either a container's or a volume's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keybag {
    /// On-disk format version; should be [`KEYBAG_VERSION`].
    pub version: u16,
    /// This keybag's entries.
    pub entries: alloc::vec::Vec<KeybagEntry>,
}

impl Keybag {
    /// Parses a keybag body (`kb_locker_t`), i.e. the bytes starting right
    /// after a [`MediaKeybag`]'s object header.
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        let version = le_u16(data, 0)?;
        let number_entries = le_u16(data, 2)? as usize;
        let entries_bytes = le_u32(data, 4)? as usize;
        let entries_data = data
            .get(16..16 + entries_bytes)
            .ok_or(crate::ApfsError::InputTooSmall)?;
        let mut entries = alloc::vec::Vec::with_capacity(number_entries);
        let mut offset = 0_usize;
        for _ in 0..number_entries {
            let remaining = entries_data
                .get(offset..)
                .ok_or(crate::ApfsError::InputTooSmall)?;
            let (entry, occupied) = KeybagEntry::parse_one(remaining)?;
            entries.push(entry);
            offset += occupied;
        }
        Ok(Self { version, entries })
    }

    /// Finds an entry by UUID and tag.
    pub fn find(&self, uuid: &[u8; 16], tag: KeybagTag) -> Option<&KeybagEntry> {
        self.entries
            .iter()
            .find(|entry| entry.uuid == *uuid && entry.tag == tag as u16)
    }

    /// Returns every entry matching a tag, regardless of UUID.
    ///
    /// A volume keybag may hold one Key Encryption Key per enrolled user (or
    /// recovery key); when unlocking with a password, any of them may match,
    /// so callers typically need to try all of them rather than just the one
    /// keyed by a specific user UUID.
    pub fn find_all(&self, tag: KeybagTag) -> impl Iterator<Item = &KeybagEntry> {
        self.entries
            .iter()
            .filter(move |entry| entry.tag == tag as u16)
    }
}

/// A keybag stored as a container-layer object (`media_keybag_t`): an object
/// header followed by a [`Keybag`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaKeybag {
    /// Common object header. Its raw `object_type` (not just
    /// [`ObjectHeader::kind`]) must be compared against
    /// [`CONTAINER_KEYBAG_OBJECT_TYPE`] or [`VOLUME_KEYBAG_OBJECT_TYPE`] to
    /// tell whether this block was read successfully decrypted: an
    /// undecrypted (or wrongly decrypted) keybag block's checksum still
    /// might not verify, but a type mismatch is the most direct signal.
    pub object: ObjectHeader,
    /// The keybag itself.
    pub keybag: Keybag,
}

impl MediaKeybag {
    /// Parses a media keybag from a full, decrypted (if applicable) APFS block.
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        let object = ObjectHeader::parse(data)?;
        let keybag = Keybag::parse(data.get(32..).ok_or(crate::ApfsError::InputTooSmall)?)?;
        Ok(Self { object, keybag })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_entry_keybag() {
        let mut data = alloc::vec![0_u8; 16 + 32];
        // kb_locker_t header
        data[0..2].copy_from_slice(&KEYBAG_VERSION.to_le_bytes());
        data[2..4].copy_from_slice(&1_u16.to_le_bytes()); // kl_nkeys
        data[4..8].copy_from_slice(&32_u32.to_le_bytes()); // kl_nbytes
        // one entry: uuid, tag=VolumePassphraseHint, key_length=4, key_data="hint"
        data[16..32].fill(0xAB);
        data[32..34].copy_from_slice(&(KeybagTag::VolumePassphraseHint as u16).to_le_bytes());
        data[34..36].copy_from_slice(&4_u16.to_le_bytes());
        data[40..44].copy_from_slice(b"hint");

        let keybag = Keybag::parse(&data).unwrap();
        assert_eq!(keybag.version, KEYBAG_VERSION);
        assert_eq!(keybag.entries.len(), 1);
        assert_eq!(keybag.entries[0].uuid, [0xAB_u8; 16]);
        assert_eq!(keybag.entries[0].key_data, b"hint");
        assert!(
            keybag
                .find(&[0xAB; 16], KeybagTag::VolumePassphraseHint)
                .is_some()
        );
    }
}
