//! Layout and encoding of a new, empty, single-volume APFS container.
//!
//! The container is laid out like the out-of-tree `mkapfs` writer's: block 0
//! and the checkpoint descriptor and data areas first, then the space manager
//! bookkeeping, the object maps and the volume's trees, with everything at
//! transaction 1 and every metadata block allocated back to back.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hadris_fs::{DateTime, ErrorKind};

use super::{
    BLOCK, btree, drec_key, entry, fs_cmp, key, object, omap, omap_entry, seal, timestamp, w16,
    w32, w64,
};
use crate::types::OwnedEntry;
use crate::{ApfsError, Result};

const XID: u64 = 1;
const DESC_BASE: u64 = 1;
const DESC_BLOCKS: u32 = 8;
const DATA_BLOCKS: u32 = 52;
const DATA_BASE: u64 = DESC_BASE + DESC_BLOCKS as u64;
const FIRST_FREE: u64 = DATA_BASE + DATA_BLOCKS as u64;

const OID_SPACEMAN: u64 = 0x400;
const OID_REAPER: u64 = 0x401;
const OID_VOLUME: u64 = 0x402;
const OID_FS_ROOT: u64 = 0x403;

const ROOT_PARENT_ID: u64 = 1;
const ROOT_DIR_ID: u64 = 2;
const PRIVATE_DIR_ID: u64 = 3;
const FIRST_USER_ID: u64 = 16;

const DT_DIR: u16 = 4;
const S_IFDIR: u16 = 0o040000;
const INODE_IS_APFS_PRIVATE: u64 = 1;
const INO_EXT_TYPE_NAME: u8 = 4;
const XF_DO_NOT_COPY: u8 = 2;
const INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 8;

const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OBJ_EPHEMERAL: u32 = 0x8000_0000;

const BLOCKS_PER_CHUNK: u64 = (BLOCK * 8) as u64;
const CHUNKS_PER_CIB: u64 = ((BLOCK - 40) / 32) as u64;
const SPACEMAN_STRUCT_SIZE: usize = 2520;
const SPACEMAN_ADDR_OFFSET: usize = 2528;
const MAX_CIBS: u64 = ((BLOCK - SPACEMAN_ADDR_OFFSET) / 8) as u64;

/// The fewest blocks a container can have: the fixed areas plus room for the
/// space manager, the trees and a few blocks to write into.
pub(crate) const MIN_BLOCKS: u64 = FIRST_FREE + 32;

/// Options for formatting a new APFS container.
///
/// The container holds one unencrypted volume that stores directory entries
/// as normalization-insensitive hashed keys by default, the layout the
/// out-of-tree `mkapfs` writer produces and the writable driver accepts.
#[derive(Debug, Clone)]
pub struct ApfsOptions {
    pub(crate) label: String,
    pub(crate) size: Option<u64>,
    pub(crate) time: DateTime,
    pub(crate) seed: Option<u64>,
    pub(crate) container_uuid: Option<[u8; 16]>,
    pub(crate) volume_uuid: Option<[u8; 16]>,
    pub(crate) normalization_insensitive: bool,
}

impl Default for ApfsOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ApfsOptions {
    /// Options for a volume named `Untitled` that fills the device, stamped
    /// with the Unix epoch and with identifiers derived from them.
    pub fn new() -> Self {
        Self {
            label: String::from("Untitled"),
            size: None,
            time: DateTime::UNIX_EPOCH,
            seed: None,
            container_uuid: None,
            volume_uuid: None,
            normalization_insensitive: true,
        }
    }

    /// Sets the volume name: 1 to 255 bytes of UTF-8 without a NUL.
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = String::from(label);
        self
    }

    /// Sets the container size in bytes instead of filling the device. It
    /// must be a multiple of 4096. A device that cannot hold it fails the
    /// format with `ErrorKind::NoSpace`, unless it grows when written past
    /// its end.
    pub const fn with_size(mut self, bytes: u64) -> Self {
        self.size = Some(bytes);
        self
    }

    /// Sets the time the volume, its root directory and its checkpoint are
    /// stamped with. It must not be before 1970.
    pub const fn with_time(mut self, time: DateTime) -> Self {
        self.time = time;
        self
    }

    /// Sets the seed the container and volume UUIDs derive from.
    ///
    /// Without a seed or explicit UUIDs they derive from the time, label and
    /// size, so formatting twice with the same options gives the same
    /// identifiers. Give volumes that must stay distinguishable distinct
    /// seeds or UUIDs.
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Sets the container UUID instead of deriving it.
    pub const fn with_container_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.container_uuid = Some(uuid);
        self
    }

    /// Sets the volume UUID instead of deriving it.
    pub const fn with_volume_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.volume_uuid = Some(uuid);
        self
    }

    /// Chooses how the volume compares names. On, the default, the volume is
    /// normalization-insensitive and stores directory entries under hashed
    /// keys; off, it is normalization-sensitive and uses plain keys. Both are
    /// case-sensitive.
    pub const fn with_normalization_insensitive(mut self, insensitive: bool) -> Self {
        self.normalization_insensitive = insensitive;
        self
    }
}

/// What `format` created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Formatted {
    /// The container's size in 4096-byte blocks.
    pub block_count: u64,
    /// The container UUID.
    pub container_uuid: [u8; 16],
    /// The volume UUID.
    pub volume_uuid: [u8; 16],
}

fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A version-4-shaped UUID derived from `material` and distinguished by `tag`.
fn derive_uuid(material: &[u8], tag: u8) -> [u8; 16] {
    let low = fnv(0xcbf2_9ce4_8422_2325 ^ u64::from(tag), material);
    let high = fnv(0x8422_2325_cbf2_9ce4 ^ (u64::from(tag) << 32), material);
    let mut uuid = [0; 16];
    uuid[..8].copy_from_slice(&low.to_le_bytes());
    uuid[8..].copy_from_slice(&high.to_le_bytes());
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

fn once(oid: u64, block: u64) -> impl FnMut() -> Result<(u64, u64)> {
    let mut slot = Some((oid, block));
    move || {
        slot.take()
            .ok_or(ApfsError::InvalidValue("APFS format tree needs one node"))
    }
}

/// Where every block of a new container goes, and the bytes that go there.
pub(crate) struct Plan {
    pub(crate) block_count: u64,
    pub(crate) chunk_count: u64,
    cib_count: u64,
    cib_start: u64,
    pub(crate) bitmap_start: u64,
    cont_omap: u64,
    cont_tree: u64,
    apsb: u64,
    vol_omap: u64,
    vol_tree: u64,
    extentref: u64,
    snapmeta: u64,
    fs_tree: u64,
    /// Blocks `0..used` are allocated; everything after is free.
    pub(crate) used: u64,
    hashed: bool,
    time_ns: u64,
    label: Vec<u8>,
    container_uuid: [u8; 16],
    volume_uuid: [u8; 16],
}

impl Plan {
    /// Plans a container of `bytes` bytes. Nothing is written.
    pub(crate) fn new(options: &ApfsOptions, bytes: u64) -> core::result::Result<Self, ErrorKind> {
        if bytes % BLOCK as u64 != 0 {
            return Err(ErrorKind::InvalidInput);
        }
        let block_count = bytes / BLOCK as u64;
        if block_count < MIN_BLOCKS {
            return Err(ErrorKind::NoSpace);
        }
        let label = options.label.as_bytes();
        if label.is_empty() || label.len() > 255 || label.contains(&0) {
            return Err(ErrorKind::InvalidInput);
        }
        let time_ns = timestamp::<core::convert::Infallible>(options.time)
            .map_err(|_| ErrorKind::InvalidInput)?;
        let chunk_count = block_count.div_ceil(BLOCKS_PER_CHUNK);
        let cib_count = chunk_count.div_ceil(CHUNKS_PER_CIB);
        if cib_count > MAX_CIBS {
            return Err(ErrorKind::LimitExceeded);
        }

        let mut next = FIRST_FREE;
        let mut take = |count: u64| {
            let at = next;
            next += count;
            at
        };
        let cib_start = take(cib_count);
        let bitmap_start = take(chunk_count);
        let cont_omap = take(1);
        let cont_tree = take(1);
        let apsb = take(1);
        let vol_omap = take(1);
        let vol_tree = take(1);
        let extentref = take(1);
        let snapmeta = take(1);
        let fs_tree = take(1);
        let used = next;

        let mut material = Vec::new();
        material.extend_from_slice(&options.seed.unwrap_or(0).to_le_bytes());
        material.extend_from_slice(&time_ns.to_le_bytes());
        material.extend_from_slice(&block_count.to_le_bytes());
        material.extend_from_slice(label);
        Ok(Self {
            block_count,
            chunk_count,
            cib_count,
            cib_start,
            bitmap_start,
            cont_omap,
            cont_tree,
            apsb,
            vol_omap,
            vol_tree,
            extentref,
            snapmeta,
            fs_tree,
            used,
            hashed: options.normalization_insensitive,
            time_ns,
            label: label.to_vec(),
            container_uuid: options
                .container_uuid
                .unwrap_or_else(|| derive_uuid(&material, 1)),
            volume_uuid: options
                .volume_uuid
                .unwrap_or_else(|| derive_uuid(&material, 2)),
        })
    }

    pub(crate) fn formatted(&self) -> Formatted {
        Formatted {
            block_count: self.block_count,
            container_uuid: self.container_uuid,
            volume_uuid: self.volume_uuid,
        }
    }

    /// The last block of the container, which a growable device must reach.
    pub(crate) fn last_block(&self) -> u64 {
        self.block_count - 1
    }

    /// How many leading chunks have an allocated block; later bitmaps are zero.
    pub(crate) fn used_chunks(&self) -> u64 {
        self.used.div_ceil(BLOCKS_PER_CHUNK)
    }

    /// The checkpoint descriptor and data areas, which a format zeroes so
    /// that no older checkpoint survives in them.
    pub(crate) fn areas(&self) -> core::ops::Range<u64> {
        DESC_BASE..FIRST_FREE
    }

    /// The block holding the container superblock of the one checkpoint.
    pub(crate) fn checkpoint_block(&self) -> u64 {
        DESC_BASE + 1
    }

    fn inode_value(&self, id: u64, internal_flags: u64, name: &str) -> Vec<u8> {
        let mut value = vec![0; 92];
        w64(&mut value, 0, ROOT_PARENT_ID);
        w64(&mut value, 8, id);
        for at in [16, 24, 32, 40] {
            w64(&mut value, at, self.time_ns);
        }
        w64(&mut value, 48, internal_flags);
        w16(&mut value, 80, S_IFDIR | 0o755);
        let mut data = name.as_bytes().to_vec();
        data.push(0);
        let length = data.len();
        data.resize(length.div_ceil(8) * 8, 0);
        value.extend_from_slice(&1_u16.to_le_bytes());
        value.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
        value.push(INO_EXT_TYPE_NAME);
        value.push(XF_DO_NOT_COPY);
        value.extend_from_slice(&(length as u16).to_le_bytes());
        value.extend_from_slice(&data);
        value
    }

    fn directory_record(&self, name: &str, file_id: u64) -> OwnedEntry {
        let mut value = vec![0; 18];
        w64(&mut value, 0, file_id);
        w64(&mut value, 8, self.time_ns);
        w16(&mut value, 16, DT_DIR);
        entry(drec_key(ROOT_PARENT_ID, name, self.hashed), value)
    }

    fn filesystem_records(&self) -> Vec<OwnedEntry> {
        let mut records = vec![
            self.directory_record("root", ROOT_DIR_ID),
            self.directory_record("private-dir", PRIVATE_DIR_ID),
            entry(
                key(ROOT_DIR_ID, 3),
                self.inode_value(ROOT_DIR_ID, 0, "root"),
            ),
            entry(
                key(PRIVATE_DIR_ID, 3),
                self.inode_value(PRIVATE_DIR_ID, INODE_IS_APFS_PRIVATE, "private-dir"),
            ),
        ];
        let hashed = self.hashed;
        records.sort_by(|a, b| fs_cmp(&a.key, &b.key, hashed));
        records
    }

    /// The container superblock of the one checkpoint.
    pub(crate) fn superblock(&self) -> Vec<u8> {
        let mut nx = object(1, XID, OBJ_EPHEMERAL | 1, 0);
        nx[32..36].copy_from_slice(b"NXSB");
        w32(&mut nx, 36, BLOCK as u32);
        w64(&mut nx, 40, self.block_count);
        w64(&mut nx, 64, 0x2);
        nx[72..88].copy_from_slice(&self.container_uuid);
        w64(&mut nx, 88, OID_FS_ROOT + 1);
        w64(&mut nx, 96, XID + 1);
        w32(&mut nx, 104, DESC_BLOCKS);
        w32(&mut nx, 108, DATA_BLOCKS);
        w64(&mut nx, 112, DESC_BASE);
        w64(&mut nx, 120, DATA_BASE);
        w32(&mut nx, 128, 2);
        w32(&mut nx, 132, 2);
        w32(&mut nx, 136, 0);
        w32(&mut nx, 140, 2);
        w32(&mut nx, 144, 0);
        w32(&mut nx, 148, 2);
        w64(&mut nx, 152, OID_SPACEMAN);
        w64(&mut nx, 160, self.cont_omap);
        w64(&mut nx, 168, OID_REAPER);
        w32(&mut nx, 180, 1);
        w64(&mut nx, 184, OID_VOLUME);
        seal(&mut nx);
        nx
    }

    /// The allocation bitmap of `chunk`: blocks below `used` are set.
    pub(crate) fn bitmap(&self, chunk: u64) -> Vec<u8> {
        let start = chunk * BLOCKS_PER_CHUNK;
        let used = self
            .used
            .saturating_sub(start)
            .min(self.block_count - start)
            .min(BLOCKS_PER_CHUNK);
        let mut bitmap = vec![0; BLOCK];
        let full = (used / 8) as usize;
        bitmap[..full].fill(0xff);
        if used % 8 != 0 {
            bitmap[full] = (1_u8 << (used % 8)) - 1;
        }
        bitmap
    }

    /// Every block except the bitmaps, the container superblock and the
    /// zeroed rest of the checkpoint areas.
    pub(crate) fn blocks(&self) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut out = Vec::new();

        let records = self.filesystem_records();
        let fs = btree::build(
            &records,
            XID,
            14,
            false,
            None,
            &mut once(OID_FS_ROOT, self.fs_tree),
        )?;
        let extentref = btree::build(
            &[],
            XID,
            15,
            true,
            None,
            &mut once(self.extentref, self.extentref),
        )?;
        let snapmeta = btree::build(
            &[],
            XID,
            16,
            true,
            None,
            &mut once(self.snapmeta, self.snapmeta),
        )?;
        let mappings: Vec<OwnedEntry> = fs
            .mappings
            .iter()
            .map(|&(oid, block)| omap_entry(oid, block, XID))
            .collect();
        let vol_tree = btree::build(
            &mappings,
            XID,
            11,
            true,
            Some((16, 16)),
            &mut once(self.vol_tree, self.vol_tree),
        )?;
        let cont_tree = btree::build(
            &[omap_entry(OID_VOLUME, self.apsb, XID)],
            XID,
            11,
            true,
            Some((16, 16)),
            &mut once(self.cont_tree, self.cont_tree),
        )?;
        let fs_root = fs.root_oid;
        let (extentref_oid, snapmeta_oid) = (extentref.root_oid, snapmeta.root_oid);
        let vol_tree_root = vol_tree.root_block;
        let cont_tree_root = cont_tree.root_block;
        for tree in [fs, extentref, snapmeta, vol_tree, cont_tree] {
            out.extend(tree.nodes);
        }
        out.push((self.vol_omap, omap(self.vol_omap, vol_tree_root, XID, 0)));
        out.push((self.cont_omap, omap(self.cont_omap, cont_tree_root, XID, 1)));

        // The volume's own blocks: its superblock, object map and four trees.
        let volume_blocks = 6;
        let mut volume = object(OID_VOLUME, XID, 13, 0);
        volume[32..36].copy_from_slice(b"APSB");
        let incompatible = if self.hashed {
            INCOMPAT_NORMALIZATION_INSENSITIVE
        } else {
            0
        };
        w64(&mut volume, 56, incompatible);
        w64(&mut volume, 88, volume_blocks);
        w32(&mut volume, 116, 2);
        w32(&mut volume, 120, OBJ_PHYSICAL | 2);
        w32(&mut volume, 124, OBJ_PHYSICAL | 2);
        w64(&mut volume, 128, self.vol_omap);
        w64(&mut volume, 136, fs_root);
        w64(&mut volume, 144, extentref_oid);
        w64(&mut volume, 152, snapmeta_oid);
        w64(&mut volume, 176, FIRST_USER_ID);
        w64(&mut volume, 224, volume_blocks);
        volume[240..256].copy_from_slice(&self.volume_uuid);
        w64(&mut volume, 256, self.time_ns);
        w64(&mut volume, 264, 1);
        for at in [272, 320] {
            volume[at..at + 6].copy_from_slice(b"hadris");
            w64(&mut volume, at + 32, self.time_ns);
            w64(&mut volume, at + 40, XID);
        }
        volume[704..704 + self.label.len()].copy_from_slice(&self.label);
        w32(&mut volume, 960, 3);
        seal(&mut volume);
        out.push((self.apsb, volume));

        for index in 0..self.cib_count {
            let first = index * CHUNKS_PER_CIB;
            let last = (first + CHUNKS_PER_CIB).min(self.chunk_count);
            let block = self.cib_start + index;
            let mut cib = object(block, XID, OBJ_PHYSICAL | 7, 0);
            w32(&mut cib, 32, index as u32);
            w32(&mut cib, 36, (last - first) as u32);
            for (slot, chunk) in (first..last).enumerate() {
                let start = chunk * BLOCKS_PER_CHUNK;
                let count = (self.block_count - start).min(BLOCKS_PER_CHUNK);
                let used = self.used.saturating_sub(start).min(count);
                let at = 40 + slot * 32;
                w64(&mut cib, at, XID);
                w64(&mut cib, at + 8, start);
                w32(&mut cib, at + 16, count as u32);
                w32(&mut cib, at + 20, (count - used) as u32);
                w64(&mut cib, at + 24, self.bitmap_start + chunk);
            }
            seal(&mut cib);
            out.push((block, cib));
        }

        let mut spaceman = object(OID_SPACEMAN, XID, OBJ_EPHEMERAL | 5, 0);
        w32(&mut spaceman, 32, BLOCK as u32);
        w32(&mut spaceman, 36, BLOCKS_PER_CHUNK as u32);
        w32(&mut spaceman, 40, CHUNKS_PER_CIB as u32);
        w32(&mut spaceman, 44, ((BLOCK - 40) / 8) as u32);
        w64(&mut spaceman, 48, self.block_count);
        w64(&mut spaceman, 56, self.chunk_count);
        w32(&mut spaceman, 64, self.cib_count as u32);
        w32(&mut spaceman, 68, 0);
        w64(&mut spaceman, 72, self.block_count - self.used);
        w32(&mut spaceman, 80, SPACEMAN_ADDR_OFFSET as u32);
        w32(&mut spaceman, 336, 1);
        w32(&mut spaceman, 340, SPACEMAN_STRUCT_SIZE as u32);
        for index in 0..self.cib_count {
            w64(
                &mut spaceman,
                SPACEMAN_ADDR_OFFSET + index as usize * 8,
                self.cib_start + index,
            );
        }
        seal(&mut spaceman);
        out.push((DATA_BASE, spaceman));

        let mut reaper = object(OID_REAPER, XID, OBJ_EPHEMERAL | 17, 0);
        w64(&mut reaper, 32, 1);
        w64(&mut reaper, 40, 1);
        w32(&mut reaper, 64, 1);
        w32(&mut reaper, 108, (BLOCK - 112) as u32);
        seal(&mut reaper);
        out.push((DATA_BASE + 1, reaper));

        let mut map = object(DESC_BASE, XID, OBJ_PHYSICAL | 12, 0);
        w32(&mut map, 32, 1);
        w32(&mut map, 36, 2);
        for (index, (kind, oid, block)) in [
            (OBJ_EPHEMERAL | 5, OID_SPACEMAN, DATA_BASE),
            (OBJ_EPHEMERAL | 17, OID_REAPER, DATA_BASE + 1),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 40 + index * 40;
            w32(&mut map, at, kind);
            w32(&mut map, at + 8, BLOCK as u32);
            w64(&mut map, at + 24, oid);
            w64(&mut map, at + 32, block);
        }
        seal(&mut map);
        out.push((DESC_BASE, map));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(blocks: u64) -> Plan {
        Plan::new(&ApfsOptions::new(), blocks * BLOCK as u64).unwrap()
    }

    #[test]
    fn emitted_blocks_tile_exactly_the_used_prefix() {
        let plan = plan(4096);
        let blocks = plan.blocks().unwrap();
        assert!(blocks.iter().all(|(_, bytes)| bytes.len() == BLOCK));
        let mut emitted: Vec<u64> = blocks.iter().map(|(block, _)| *block).collect();
        let before = emitted.len();
        emitted.sort_unstable();
        emitted.dedup();
        assert_eq!(emitted.len(), before, "a block is emitted twice");
        let mut covered = emitted;
        covered.push(0);
        covered.extend(plan.areas());
        covered.extend(plan.bitmap_start..plan.bitmap_start + plan.chunk_count);
        covered.sort_unstable();
        covered.dedup();
        assert_eq!(covered, (0..plan.used).collect::<Vec<_>>());
    }

    #[test]
    fn bitmap_marks_exactly_the_used_prefix() {
        let plan = plan(40_000);
        assert_eq!(plan.chunk_count, 2);
        let first = plan.bitmap(0);
        let used = plan.used as usize;
        for bit in 0..BLOCK * 8 {
            let set = first[bit / 8] & (1 << (bit % 8)) != 0;
            assert_eq!(set, bit < used, "bit {bit}");
        }
        assert!(plan.bitmap(1).iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sizes_outside_the_supported_range_are_rejected() {
        let options = ApfsOptions::new();
        assert_eq!(
            Plan::new(&options, 4097).err(),
            Some(ErrorKind::InvalidInput)
        );
        assert_eq!(
            Plan::new(&options, (MIN_BLOCKS - 1) * BLOCK as u64).err(),
            Some(ErrorKind::NoSpace)
        );
        let too_big = (MAX_CIBS * CHUNKS_PER_CIB * BLOCKS_PER_CHUNK + 1) * BLOCK as u64;
        assert_eq!(
            Plan::new(&options, too_big).err(),
            Some(ErrorKind::LimitExceeded)
        );
        for label in ["", "a\0b", &"x".repeat(256)] {
            assert_eq!(
                Plan::new(&ApfsOptions::new().with_label(label), 4096 * 4096).err(),
                Some(ErrorKind::InvalidInput)
            );
        }
    }

    #[test]
    fn identifiers_derive_from_the_inputs() {
        let base = ApfsOptions::new();
        let a = plan(4096).formatted();
        assert_eq!(a, plan(4096).formatted());
        assert_ne!(a.container_uuid, a.volume_uuid);
        let seeded = Plan::new(&base.clone().with_seed(7), 4096 * 4096)
            .unwrap()
            .formatted();
        assert_ne!(seeded.volume_uuid, a.volume_uuid);
        assert_eq!(a.volume_uuid[6] >> 4, 4);
        assert_eq!(a.volume_uuid[8] >> 6, 2);
        let fixed = Plan::new(&base.with_volume_uuid([9; 16]), 4096 * 4096)
            .unwrap()
            .formatted();
        assert_eq!(fixed.volume_uuid, [9; 16]);
    }
}
