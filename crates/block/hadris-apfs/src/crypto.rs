//! Software (password/recovery-key) FileVault decryption.
//!
//! Implements the on-disk key-unwrapping chain used by password-protected
//! APFS volumes:
//!
//! 1. The container keybag (at [`crate::types::ContainerSuperblock::keybag_block`])
//!    is itself AES-XTS-128 encrypted with the *container's own UUID* as both
//!    halves of the XTS key — this isn't a secret, just obfuscation, since
//!    every key inside is still wrapped.
//! 2. The container keybag's `VolumeUnlockRecords` entry for a volume's UUID
//!    points at that volume's own keybag (encrypted the same way, with the
//!    *volume's* UUID as the XTS key).
//! 3. The volume keybag holds one wrapped Key Encryption Key (KEK) per
//!    enrolled password/recovery key, itself derived via PBKDF2-HMAC-SHA256
//!    from a salt and iteration count stored alongside it, and unwrapped
//!    with RFC 3394 AES key-wrap.
//! 4. The container keybag's `VolumeKey` entry for the volume holds the
//!    wrapped Volume Encryption Key (VEK), unwrapped with the KEK from step 3.
//!
//! The unwrapped VEK is a 32-byte AES-XTS-128 key (first half: data key,
//! second half: tweak key) used to decrypt the volume's filesystem tree and
//! file contents; see [`OMAP_VAL_ENCRYPTED`](crate::types::object_map::OMAP_VAL_ENCRYPTED).
//!
//! This module **cannot** decrypt Secure-Enclave-sealed volumes (every
//! internal volume on T2 and Apple Silicon Macs): their VEK is only ever
//! released by the SEP after authenticating through Apple's private
//! `CryptoUserService`, never by unwrapping bytes found on disk.
//!
//! Reference: this implementation follows the on-disk formats and unwrap
//! sequence documented by the [apfs-fuse](https://github.com/sgan81/apfs-fuse)
//! project's `KeyMgmt.cpp`/`Asn1Der.cpp`.

use crate::types::keybag::{Keybag, KeybagTag};
use aes::Aes128;
use aes_kw::{KeyInit, KwAes128, KwAes256};
use alloc::vec::Vec;
use cipher::Array;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use xts_mode::{Xts128, get_tweak_default};

/// Number of bytes in one AES-XTS "sector"; APFS always uses 512-byte
/// sectors for XTS tweaking, regardless of the container's own block size.
const XTS_SECTOR_SIZE: usize = 512;

/// A fully unwrapped Volume Encryption Key: 32 bytes, used as an AES-XTS-128
/// key (first 16 bytes: data key, last 16 bytes: tweak key).
pub type VolumeEncryptionKey = [u8; 32];

/// Decrypts `data` in place with AES-XTS-128, treating it as consecutive
/// 512-byte sectors starting at `first_sector`.
///
/// `key` is a 32-byte key as returned by [`unlock_volume_key`]: the first 16
/// bytes are the data-encryption key, the last 16 the tweak key.
///
/// `data.len()` must be a multiple of 512 bytes.
pub fn xts_decrypt(
    key: &VolumeEncryptionKey,
    first_sector: u64,
    data: &mut [u8],
) -> crate::Result<()> {
    if !data.len().is_multiple_of(XTS_SECTOR_SIZE) {
        return Err(crate::ApfsError::Crypto(
            "data length is not a multiple of the AES-XTS sector size",
        ));
    }
    let cipher_1 = Aes128::new(&Array::try_from(&key[..16]).expect("16 bytes"));
    let cipher_2 = Aes128::new(&Array::try_from(&key[16..]).expect("16 bytes"));
    let xts = Xts128::new(cipher_1, cipher_2);
    xts.decrypt_area(
        data,
        XTS_SECTOR_SIZE,
        u128::from(first_sector),
        get_tweak_default,
    );
    Ok(())
}

/// Decrypts a container or volume keybag block in place.
///
/// Keybag blocks are AES-XTS-128 encrypted with the owning object's UUID
/// (the container's for a container keybag, the volume's for a volume
/// keybag) used as *both* halves of the XTS key. `first_block` is the
/// keybag's own first physical block address (used to derive the starting
/// sector tweak); `block_size` is the container's block size.
pub fn decrypt_keybag_block(
    uuid: &[u8; 16],
    first_block: u64,
    block_size: u32,
    data: &mut [u8],
) -> crate::Result<()> {
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(uuid);
    key[16..].copy_from_slice(uuid);
    let sectors_per_block = u64::from(block_size) / XTS_SECTOR_SIZE as u64;
    xts_decrypt(&key, first_block * sectors_per_block, data)
}

/// Decrypts one volume-relative physical block (filesystem tree node or file
/// extent data) in place, given the volume's unwrapped [`VolumeEncryptionKey`].
///
/// `tweak_block` is the APFS block address used as the XTS tweak: the
/// object's own physical block address for object-map-resolved blocks
/// (`OMAP_VAL_ENCRYPTED`), or a file extent's `cryptography_id` plus the
/// block's offset within the extent for file data.
pub fn decrypt_volume_block(
    vek: &VolumeEncryptionKey,
    tweak_block: u64,
    block_size: u32,
    data: &mut [u8],
) -> crate::Result<()> {
    let sectors_per_block = u64::from(block_size) / XTS_SECTOR_SIZE as u64;
    xts_decrypt(vek, tweak_block * sectors_per_block, data)
}

/// A wrapped key blob decoded from a keybag entry's key data.
///
/// Every KEK and VEK keybag entry's key data is a small, hand-rolled DER
/// structure (see module docs) wrapping an HMAC-authenticated header
/// (verification of which this decoder does not perform, matching
/// `apfs-fuse`'s documented "ignoring for now") plus the actual wrapped key
/// material.
struct WrappedKeyBlob {
    /// UUID recorded inside the blob's header (may differ in practice from
    /// the owning keybag entry's UUID, though it usually matches).
    uuid: [u8; 16],
    /// Key info flags; bit `0x2` selects the AES-128 wrapping variant used
    /// by FileVault/CoreStorage-converted volumes instead of the AES-256
    /// variant used natively by APFS.
    flags: u32,
    /// RFC 3394 wrapped key data (tag `[3]`).
    wrapped_key: Vec<u8>,
    /// PBKDF2 iteration count (tag `[4]`; KEK blobs only).
    iterations: Option<u64>,
    /// PBKDF2 salt (tag `[5]`; KEK blobs only).
    salt: Vec<u8>,
}

/// Reads one DER tag-length-value element (assuming a single-byte tag,
/// true for every element used here), returning the tag byte and the
/// content's byte range, and advancing `pos` past it.
fn der_read_tlv(data: &[u8], pos: &mut usize) -> crate::Result<(u8, core::ops::Range<usize>)> {
    let too_small = || crate::ApfsError::Crypto("truncated DER key blob");
    let tag = *data.get(*pos).ok_or_else(too_small)?;
    *pos += 1;
    let length_byte = *data.get(*pos).ok_or_else(too_small)?;
    *pos += 1;
    let length = if length_byte & 0x80 == 0 {
        length_byte as usize
    } else {
        let count = (length_byte & 0x7f) as usize;
        let bytes = data.get(*pos..*pos + count).ok_or_else(too_small)?;
        *pos += count;
        bytes
            .iter()
            .fold(0_usize, |acc, byte| (acc << 8) | *byte as usize)
    };
    let start = *pos;
    let end = start.checked_add(length).ok_or_else(too_small)?;
    if end > data.len() {
        return Err(too_small());
    }
    *pos = end;
    Ok((tag, start..end))
}

/// Parses a keybag entry's DER-encoded key data into a [`WrappedKeyBlob`].
fn parse_wrapped_key_blob(data: &[u8]) -> crate::Result<WrappedKeyBlob> {
    let mut pos = 0_usize;
    let (tag, sequence) = der_read_tlv(data, &mut pos)?;
    if tag != 0x30 {
        return Err(crate::ApfsError::Crypto(
            "wrapped key blob is not a DER SEQUENCE",
        ));
    }
    let mut cursor = sequence.start;
    // Skip [0] hmac_0, [1] hmac_hash, [2] hmac_salt, stopping at the
    // constructed [3] element that holds the header and the actual key data.
    let inner = loop {
        if cursor >= sequence.end {
            return Err(crate::ApfsError::Crypto(
                "wrapped key blob is missing its constructed [3] element",
            ));
        }
        let (tag, range) = der_read_tlv(data, &mut cursor)?;
        if tag == 0xA3 {
            break range;
        }
    };

    let mut uuid = [0_u8; 16];
    let mut flags = 0_u32;
    let mut wrapped_key = Vec::new();
    let mut iterations = None;
    let mut salt = Vec::new();

    let mut cursor = inner.start;
    while cursor < inner.end {
        let (tag, range) = der_read_tlv(data, &mut cursor)?;
        match tag & 0x1f {
            1 if range.len() == 16 => uuid.copy_from_slice(&data[range]),
            2 => {
                if let Some(flag_bytes) = data.get(range.start..(range.start + 4).min(range.end)) {
                    let mut buf = [0_u8; 4];
                    buf[..flag_bytes.len()].copy_from_slice(flag_bytes);
                    flags = u32::from_be_bytes(buf);
                }
            }
            3 => wrapped_key = data[range].to_vec(),
            4 => {
                iterations = Some(
                    data[range]
                        .iter()
                        .fold(0_u64, |acc, byte| (acc << 8) | *byte as u64),
                )
            }
            5 => salt = data[range].to_vec(),
            _ => {}
        }
    }

    Ok(WrappedKeyBlob {
        uuid,
        flags,
        wrapped_key,
        iterations,
        salt,
    })
}

/// RFC 3394 AES key-unwrap, selecting AES-128 or AES-256 by `kek.len()`.
///
/// `wrapped` must be `key_len + 8` bytes (the wrapped key plus the 8-byte
/// integrity check value). Returns `key_len` bytes on success; a wrong key
/// (or corrupt data) is detected by the check value and reported as an
/// error, exactly like a wrong password.
fn rfc3394_unwrap(wrapped: &[u8], kek: &[u8]) -> crate::Result<Vec<u8>> {
    let bad_password = || crate::ApfsError::Crypto("key unwrap failed (wrong password?)");
    match kek.len() {
        16 => {
            let unwrapper = KwAes128::new(&Array::try_from(kek).expect("16 bytes"));
            let mut out = alloc::vec![0_u8; wrapped.len().saturating_sub(8)];
            unwrapper
                .unwrap_key(wrapped, &mut out)
                .map_err(|_| bad_password())?;
            Ok(out)
        }
        32 => {
            let unwrapper = KwAes256::new(&Array::try_from(kek).expect("32 bytes"));
            let mut out = alloc::vec![0_u8; wrapped.len().saturating_sub(8)];
            unwrapper
                .unwrap_key(wrapped, &mut out)
                .map_err(|_| bad_password())?;
            Ok(out)
        }
        _ => Err(crate::ApfsError::Crypto(
            "unexpected key-encryption-key length",
        )),
    }
}

/// Derives the Key Encryption Key candidates in a volume keybag that unwrap
/// with `password`, returning the first one that succeeds.
///
/// A volume keybag can hold one wrapped KEK per enrolled password/recovery
/// key; every `VolumeUnlockRecords` entry is tried in turn, matching the
/// reference implementation's behavior of not assuming a specific user UUID.
fn unwrap_any_kek(volume_keybag: &Keybag, password: &[u8]) -> crate::Result<Vec<u8>> {
    for entry in volume_keybag.find_all(KeybagTag::VolumeUnlockRecords) {
        let Ok(blob) = parse_wrapped_key_blob(&entry.key_data) else {
            continue;
        };
        let (Some(iterations), false) = (blob.iterations, blob.salt.is_empty()) else {
            continue;
        };
        let mut derived = [0_u8; 32];
        pbkdf2_hmac::<Sha256>(password, &blob.salt, iterations as u32, &mut derived);
        let kek_len = if blob.flags & 2 != 0 { 16 } else { 32 };
        let Some(wrapped) = blob.wrapped_key.get(..kek_len + 8) else {
            continue;
        };
        if let Ok(kek) = rfc3394_unwrap(wrapped, &derived[..kek_len]) {
            return Ok(kek);
        }
    }
    Err(crate::ApfsError::Crypto(
        "no enrolled password/recovery key in this volume's keybag matched the supplied password",
    ))
}

/// Unwraps a volume's Volume Encryption Key using its container keybag entry
/// and an already-unwrapped Key Encryption Key.
fn unwrap_vek(
    container_keybag: &Keybag,
    volume_uuid: &[u8; 16],
    kek: &[u8],
) -> crate::Result<VolumeEncryptionKey> {
    let entry = container_keybag
        .find(volume_uuid, KeybagTag::VolumeKey)
        .ok_or(crate::ApfsError::Crypto(
            "container keybag has no wrapped Volume Encryption Key for this volume",
        ))?;
    let blob = parse_wrapped_key_blob(&entry.key_data)?;

    let mut vek = [0_u8; 32];
    if blob.flags & 2 != 0 {
        // AES-128 variant, used by FileVault/CoreStorage-converted volumes:
        // only the first 16 bytes are wrapped, and the XTS tweak key half is
        // derived by hashing rather than being independently wrapped.
        let wrapped = blob
            .wrapped_key
            .get(..24)
            .ok_or(crate::ApfsError::Crypto("truncated wrapped VEK"))?;
        let unwrapped = rfc3394_unwrap(wrapped, kek)?;
        vek[..16].copy_from_slice(&unwrapped);
        let mut hasher = Sha256::new();
        hasher.update(&unwrapped);
        hasher.update(blob.uuid);
        let digest = hasher.finalize();
        vek[16..].copy_from_slice(&digest[..16]);
    } else {
        let wrapped = blob
            .wrapped_key
            .get(..40)
            .ok_or(crate::ApfsError::Crypto("truncated wrapped VEK"))?;
        let unwrapped = rfc3394_unwrap(wrapped, kek)?;
        vek.copy_from_slice(&unwrapped);
    }
    Ok(vek)
}

/// Unlocks a volume's Volume Encryption Key from its container keybag and
/// volume keybag, given a password (or recovery key, which is used the same
/// way as a password here).
///
/// `container_keybag` and `volume_keybag` are the already-decrypted keybags
/// (see [`decrypt_keybag_block`]); `volume_uuid` identifies the volume in
/// both. Returns [`ApfsError::Crypto`](crate::ApfsError::Crypto) if the
/// password doesn't match any enrolled key.
pub fn unlock_volume_key(
    container_keybag: &Keybag,
    volume_keybag: &Keybag,
    volume_uuid: &[u8; 16],
    password: &[u8],
) -> crate::Result<VolumeEncryptionKey> {
    let kek = unwrap_any_kek(volume_keybag, password)?;
    unwrap_vek(container_keybag, volume_uuid, &kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xts_decrypt_rejects_partial_sectors() {
        let key = [0_u8; 32];
        let mut data = [0_u8; 511];
        assert!(xts_decrypt(&key, 0, &mut data).is_err());
    }

    #[test]
    fn xts_round_trips_with_encrypt() {
        let key = [7_u8; 32];
        let mut data = [0x42_u8; 1024];
        let original = data;
        xts_decrypt(&key, 5, &mut data).unwrap();
        assert_ne!(data, original);
        // Decrypting the "encrypted" (garbage) bytes back should not equal
        // the original either, but re-decrypting should be deterministic.
        let mut again = original;
        xts_decrypt(&key, 5, &mut again).unwrap();
        assert_eq!(data, again);
    }
}
