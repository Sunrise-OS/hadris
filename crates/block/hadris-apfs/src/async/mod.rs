//! Asynchronous APFS readers.

use crate::read::ContainerInfo;
use crate::types::checksum::verify_object;
use crate::types::container::ContainerSuperblock;
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::types::container::{CheckpointMapBlock, CheckpointMapping};
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::types::object_map::ObjectMapBlock;
#[cfg(any(feature = "alloc", feature = "std"))]
use crate::types::{
    FileExtentRecord, FileSystemKey, InodeRecord, ObjectMapKey, ObjectMapValue, OwnedBTreeNode,
    OwnedDirectoryEntryRecord, OwnedEntry, SnapshotMetadataRecord, VolumeSuperblock,
};
use hadris_storage::BlockIndex;
use hadris_storage::r#async::BlockDevice;

/// Maps a block-device read error to an APFS error.
fn map_read_error<E: hadris_io::IoError>(error: hadris_storage::Error<E>) -> crate::ApfsError {
    match error {
        hadris_storage::Error::InvalidBufferLength { .. } => {
            crate::ApfsError::InvalidValue("read buffer length")
        }
        hadris_storage::Error::OutOfBounds { .. } => {
            crate::ApfsError::InvalidValue("block is outside the device")
        }
        hadris_storage::Error::AddressOverflow => crate::ApfsError::AddressOverflow,
        hadris_storage::Error::InvalidView { .. } => {
            crate::ApfsError::InvalidValue("partition view")
        }
        hadris_storage::Error::Io(error) => crate::ApfsError::Io(error.kind()),
    }
}

/// Asynchronous APFS container reader over a Hadris block device.
#[derive(Debug)]
pub struct Container<D> {
    device: D,
    info: ContainerInfo,
    device_block_size: u32,
    /// Full leaf-entry walk of the most recently used object map, keyed by
    /// its tree OID. [`Container::object_map_lookup`] resolves many virtual
    /// OIDs against the same object map in a row (e.g. once per non-leaf
    /// node while walking a large filesystem tree in
    /// [`Container::virtual_btree_leaf_entries`]); without this cache each
    /// resolution re-walks the entire object-map B-tree from disk, which for
    /// a busy, multi-million-file volume is slow enough that a live,
    /// concurrently-written container can rotate checkpoints and reclaim
    /// blocks mid-walk, turning a performance bug into a correctness one.
    #[cfg(any(feature = "alloc", feature = "std"))]
    object_map_cache: Option<(u64, alloc::vec::Vec<(ObjectMapKey, ObjectMapValue)>)>,
}

impl<D> Container<D>
where
    D: BlockDevice,
{
    /// Opens an APFS container whose block 0 is at device block 0.
    pub async fn open(mut device: D) -> crate::Result<Self> {
        let sector_size = device.geometry().logical_block_size.get() as usize;
        if sector_size > 4096 || !4096_usize.is_multiple_of(sector_size) {
            return Err(crate::ApfsError::InvalidValue("device block size"));
        }
        let mut header = [0_u8; 4096];
        device
            .read_blocks(BlockIndex(0), &mut header)
            .await
            .map_err(map_read_error)?;
        // The Fletcher-64 checksum covers the whole APFS block, which can be
        // up to 64 KiB, not just the first 4096 bytes. Peek the block size
        // (unauthenticated) before deciding whether a second, full-block read
        // and verification is required.
        let probe = ContainerSuperblock::parse(&header)?;
        let superblock = if probe.block_size as usize == header.len() {
            verify_object(&header)?;
            probe
        } else {
            if probe.block_size as usize % sector_size != 0 {
                return Err(crate::ApfsError::InvalidValue(
                    "APFS block size is not device-block aligned",
                ));
            }
            let mut full =
                [0_u8; crate::types::container::CONTAINER_MAXIMUM_BLOCK_SIZE_BYTES as usize];
            let buffer = full
                .get_mut(..probe.block_size as usize)
                .ok_or(crate::ApfsError::InvalidValue("container block size"))?;
            device
                .read_blocks(BlockIndex(0), buffer)
                .await
                .map_err(map_read_error)?;
            verify_object(buffer)?;
            ContainerSuperblock::parse(buffer)?
        };
        if superblock.block_size % sector_size as u32 != 0 {
            return Err(crate::ApfsError::InvalidValue(
                "APFS block size is not device-block aligned",
            ));
        }
        Ok(Self {
            device,
            info: ContainerInfo { superblock },
            device_block_size: sector_size as u32,
            #[cfg(any(feature = "alloc", feature = "std"))]
            object_map_cache: None,
        })
    }

    /// Returns container metadata parsed during open.
    pub const fn info(&self) -> &ContainerInfo {
        &self.info
    }

    /// Returns the block-zero superblock.
    pub const fn superblock(&self) -> &ContainerSuperblock {
        &self.info.superblock
    }

    /// Reads one APFS container block by APFS physical block number.
    pub async fn read_apfs_block(&mut self, block: u64, buffer: &mut [u8]) -> crate::Result<()> {
        if buffer.len() != self.info.superblock.block_size as usize {
            return Err(crate::ApfsError::InvalidValue("APFS block buffer length"));
        }
        let device_block = block
            .checked_mul(u64::from(
                self.info.superblock.block_size / self.device_block_size,
            ))
            .ok_or(crate::ApfsError::AddressOverflow)?;
        self.device
            .read_blocks(BlockIndex(device_block), buffer)
            .await
            .map_err(map_read_error)
    }

    /// Reads an APFS container block into an owned buffer.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn read_apfs_block_vec(&mut self, block: u64) -> crate::Result<alloc::vec::Vec<u8>> {
        let mut buffer = alloc::vec![0_u8; self.info.superblock.block_size as usize];
        self.read_apfs_block(block, &mut buffer).await?;
        Ok(buffer)
    }

    /// Drops the cached object-map walk so the next lookup re-reads it from
    /// disk.
    ///
    /// On a live, actively-mounted container every walk this reader performs
    /// (checkpoint -> object map -> B-tree nodes) races the filesystem's own
    /// copy-on-write churn: a concurrent transaction can free and reallocate
    /// any block between when its address was learned and when it is read,
    /// which surfaces as a checksum mismatch or a wrong-object-type error
    /// partway through the walk. Those failures are not corruption — the
    /// consistent recovery is to invalidate this cache, re-read the newest
    /// checkpoint superblock via [`Self::latest_superblock`], and restart the
    /// whole operation from that fresh root.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn invalidate_object_map_cache(&mut self) {
        self.object_map_cache = None;
    }

    /// Scans the checkpoint descriptor area for container superblocks, newest first.
    ///
    /// The block-zero superblock's own `checkpoint_descriptor_area_start_index`
    /// and `checkpoint_descriptor_area_length` describe the checkpoint that was
    /// active when block zero was last written, which for a container that
    /// wasn't cleanly unmounted (e.g. a live, mounted volume) is stale — macOS
    /// only rewrites block zero on clean unmount. Using that stale window to
    /// bound the ring scan can miss the current checkpoint entirely and fall
    /// back to a block-zero superblock whose `object_map_oid` and other object
    /// identifiers point at blocks a later transaction has since freed and
    /// reused, producing spurious "invalid object type" errors downstream.
    /// Instead, scan every block in the descriptor ring
    /// (`0..checkpoint_descriptor_area_block_count`) for valid, checksummed
    /// superblocks and keep the one with the highest transaction identifier.
    /// Blocks in the ring that aren't currently in use hold stale data from a
    /// previous checkpoint, so parse/checksum failures there are expected and
    /// simply skipped rather than treated as fatal.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn superblocks_sorted(
        &mut self,
    ) -> crate::Result<alloc::vec::Vec<ContainerSuperblock>> {
        let mut superblocks = alloc::vec::Vec::new();
        let base = self.info.superblock.checkpoint_descriptor_area_block;
        if base & (1_u64 << 63) != 0
            || self.info.superblock.checkpoint_descriptor_area_block_count & (1_u32 << 31) != 0
        {
            return Err(crate::ApfsError::InvalidValue(
                "checkpoint descriptor area is stored as a B-tree",
            ));
        }
        let count = self.info.superblock.checkpoint_descriptor_area_block_count;
        if count == 0 {
            return if self.info.superblock.checkpoint_descriptor_area_length == 0 {
                Ok(superblocks)
            } else {
                Err(crate::ApfsError::InvalidValue(
                    "zero checkpoint descriptor area block count",
                ))
            };
        }
        for i in 0..count {
            let block = base
                .checked_add(u64::from(i))
                .ok_or(crate::ApfsError::AddressOverflow)?;
            let Ok(data) = self.read_apfs_block_vec(block).await else {
                continue;
            };
            let Ok(object) = crate::types::ObjectHeader::parse(&data) else {
                continue;
            };
            if object.kind() == crate::types::ObjectType::ContainerSuperblock as u16
                && verify_object(&data).is_ok()
                && let Ok(superblock) = ContainerSuperblock::parse(&data)
            {
                superblocks.push(superblock);
            }
        }
        superblocks.sort_by(|a, b| {
            b.object
                .transaction_identifier
                .cmp(&a.object.transaction_identifier)
        });
        Ok(superblocks)
    }

    /// Returns the newest checkpoint superblock, falling back to block zero when no checkpoint is present.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn latest_superblock(&mut self) -> crate::Result<ContainerSuperblock> {
        Ok(self
            .superblocks_sorted()
            .await?
            .into_iter()
            .next()
            .unwrap_or_else(|| self.info.superblock.clone()))
    }

    /// Reads checkpoint map blocks referenced by a superblock.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn checkpoint_map_blocks(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<alloc::vec::Vec<CheckpointMapBlock>> {
        let mut maps = alloc::vec::Vec::new();
        let base = superblock.checkpoint_descriptor_area_block;
        if base & (1_u64 << 63) != 0
            || superblock.checkpoint_descriptor_area_block_count & (1_u32 << 31) != 0
        {
            return Err(crate::ApfsError::InvalidValue(
                "checkpoint descriptor area is stored as a B-tree",
            ));
        }
        let count = superblock.checkpoint_descriptor_area_block_count;
        if count == 0 {
            return if superblock.checkpoint_descriptor_area_length == 0 {
                Ok(maps)
            } else {
                Err(crate::ApfsError::InvalidValue(
                    "zero checkpoint descriptor area block count",
                ))
            };
        }
        for i in 0..superblock.checkpoint_descriptor_area_length {
            let index = superblock
                .checkpoint_descriptor_area_start_index
                .checked_add(i)
                .ok_or(crate::ApfsError::AddressOverflow)?
                % count;
            let block = base
                .checked_add(u64::from(index))
                .ok_or(crate::ApfsError::AddressOverflow)?;
            let data = self.read_apfs_block_vec(block).await?;
            let object = crate::types::ObjectHeader::parse(&data)?;
            if object.kind() == crate::types::ObjectType::CheckpointMap as u16 {
                verify_object(&data)?;
                maps.push(CheckpointMapBlock::parse(&data)?);
            }
        }
        Ok(maps)
    }

    /// Returns flattened checkpoint mappings for a superblock.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn checkpoint_mappings(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<alloc::vec::Vec<CheckpointMapping>> {
        let mut mappings = alloc::vec::Vec::new();
        for map in self.checkpoint_map_blocks(superblock).await? {
            mappings.extend(map.mappings);
        }
        Ok(mappings)
    }

    /// Finds the checkpoint mapping for an ephemeral object identifier.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn find_ephemeral_object_mapping(
        &mut self,
        superblock: &ContainerSuperblock,
        oid: u64,
    ) -> crate::Result<Option<CheckpointMapping>> {
        Ok(self
            .checkpoint_mappings(superblock)
            .await?
            .into_iter()
            .find(|mapping| mapping.container_identifier == oid))
    }

    /// Reads the container object map block referenced by a superblock.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn object_map(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<ObjectMapBlock> {
        let direct_data = self.read_apfs_block_vec(superblock.object_map_oid).await;
        if let Ok(data) = direct_data
            && verify_object(&data).is_ok()
            && let Ok(object_map) = ObjectMapBlock::parse(&data)
        {
            return Ok(object_map);
        }
        if let Some(mapping) = self
            .find_ephemeral_object_mapping(superblock, superblock.object_map_oid)
            .await?
        {
            let data = self.read_apfs_block_vec(mapping.address).await?;
            verify_object(&data)?;
            ObjectMapBlock::parse(&data)
        } else {
            let data = self.read_apfs_block_vec(superblock.object_map_oid).await?;
            verify_object(&data)?;
            ObjectMapBlock::parse(&data)
        }
    }

    /// Reads the owned root node of the container object-map B-tree.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn object_map_owned_root_node(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<(ObjectMapBlock, OwnedBTreeNode)> {
        let object_map = self.object_map(superblock).await?;
        let root = self.read_btree_node(object_map.tree_oid).await?;
        Ok((object_map, root))
    }

    /// Walks the object-map B-tree and returns parsed leaf values.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn object_map_values(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<alloc::vec::Vec<(ObjectMapKey, ObjectMapValue)>> {
        let object_map = self.object_map(superblock).await?;
        self.object_map_values_for(object_map).await
    }

    /// Resolves volume OIDs by walking the object-map B-tree.
    ///
    /// An object map can contain multiple recorded versions of the same
    /// volume OID (e.g. across snapshots or prior transactions). For each
    /// volume OID this returns only the mapping with the highest transaction
    /// identifier not exceeding the container superblock's own transaction
    /// identifier, matching the resolution rule used by
    /// [`Self::object_map_lookup`]. Returning every matching version instead
    /// would make [`Self::volume_superblocks`] read (and callers iterate)
    /// duplicate/stale copies of the same volume.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn volume_object_map_values(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<alloc::vec::Vec<(ObjectMapKey, ObjectMapValue)>> {
        let values = self.object_map_values(superblock).await?;
        let max_xid = superblock.object.transaction_identifier;
        Ok(superblock
            .volumes()
            .filter_map(|oid| {
                values
                    .iter()
                    .filter(|(key, _)| {
                        (key.oid == oid || (key.oid & 0x0fff_ffff_ffff_ffff) == oid)
                            && key.xid <= max_xid
                    })
                    .max_by_key(|(key, _)| key.xid)
                    .map(|(key, value)| (*key, *value))
            })
            .collect())
    }

    /// Reads volume superblocks referenced by the container superblock.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn volume_superblocks(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<alloc::vec::Vec<VolumeSuperblock>> {
        let mut volumes = alloc::vec::Vec::new();
        for (_key, value) in self.volume_object_map_values(superblock).await? {
            let data = self.read_apfs_block_vec(value.address).await?;
            verify_object(&data)?;
            volumes.push(VolumeSuperblock::parse(&data)?);
        }
        Ok(volumes)
    }

    /// Finds the mapping for an object identifier in an object map with the
    /// largest transaction identifier that does not exceed `max_transaction_id`.
    ///
    /// Passing a transaction identifier bound (rather than always taking the
    /// globally newest mapping) is required for correctness: an object map can
    /// contain multiple versions of the same virtual OID (e.g. across
    /// snapshots), and resolving unconditionally to the newest one can return
    /// an object from a later filesystem state than the one being read.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn object_map_lookup(
        &mut self,
        object_map: ObjectMapBlock,
        oid: u64,
        max_transaction_id: u64,
    ) -> crate::Result<Option<ObjectMapValue>> {
        Ok(self
            .object_map_values_for(object_map)
            .await?
            .into_iter()
            .filter(|(key, _)| {
                (key.oid == oid || (key.oid & 0x0fff_ffff_ffff_ffff) == oid)
                    && key.xid <= max_transaction_id
            })
            .max_by_key(|(key, _)| key.xid)
            .map(|(_, value)| value))
    }

    /// Resolves a virtual object identifier through a volume object map,
    /// bounded to the volume superblock's own transaction identifier.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn resolve_volume_object(
        &mut self,
        volume: &VolumeSuperblock,
        oid: u64,
    ) -> crate::Result<Option<ObjectMapValue>> {
        let object_map = self.object_map_at(volume.object_map_oid).await?;
        self.object_map_lookup(object_map, oid, volume.default_read_transaction_id())
            .await
    }

    /// Reads an object map block at a physical APFS block address.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn object_map_at(&mut self, physical_block: u64) -> crate::Result<ObjectMapBlock> {
        let data = self.read_apfs_block_vec(physical_block).await?;
        verify_object(&data)?;
        ObjectMapBlock::parse(&data)
    }

    /// Reads the container's space manager summary (free/used block counts).
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn space_manager_summary(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<crate::types::SpaceManagerSummary> {
        let data = self.space_manager_block_data(superblock).await?;
        crate::types::SpaceManagerSummary::parse(&data)
    }

    /// Reads the raw bytes of the container's space manager block, resolving
    /// the ephemeral object mapping when the OID isn't a direct physical
    /// block address.
    #[cfg(any(feature = "alloc", feature = "std"))]
    async fn space_manager_block_data(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<alloc::vec::Vec<u8>> {
        let direct = match self.read_apfs_block_vec(superblock.space_manager_oid).await {
            Ok(data) => verify_object(&data).map(|_| data),
            Err(error) => Err(error),
        };
        match direct {
            Ok(data) => Ok(data),
            Err(direct_error) => {
                if let Some(mapping) = self
                    .find_ephemeral_object_mapping(superblock, superblock.space_manager_oid)
                    .await?
                {
                    let data = self.read_apfs_block_vec(mapping.address).await?;
                    verify_object(&data)?;
                    Ok(data)
                } else {
                    Err(direct_error)
                }
            }
        }
    }

    /// Walks the main device's `chunk_info_block_t` blocks and returns all
    /// parsed `chunk_info_t` entries. Only supports the common case where
    /// chunk info addresses are stored inline (no `chunk_info_address_block_t`
    /// indirection).
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn space_manager_chunk_infos(
        &mut self,
        superblock: &ContainerSuperblock,
    ) -> crate::Result<alloc::vec::Vec<crate::types::ChunkInfo>> {
        let block_data = self.space_manager_block_data(superblock).await?;
        let summary = crate::types::SpaceManagerSummary::parse(&block_data)?;
        let addresses = summary.main_device_chunk_info_block_addresses(&block_data)?;
        let mut entries = alloc::vec::Vec::new();
        for address in addresses {
            let data = self.read_apfs_block_vec(address).await?;
            verify_object(&data)?;
            entries.extend(crate::types::parse_chunk_info_block(&data)?);
        }
        Ok(entries)
    }

    /// Returns the full leaf-entry walk of `object_map`, from the per-tree
    /// cache when available (see [`Container::object_map_cache`]).
    #[cfg(any(feature = "alloc", feature = "std"))]
    async fn object_map_values_for(
        &mut self,
        object_map: ObjectMapBlock,
    ) -> crate::Result<alloc::vec::Vec<(ObjectMapKey, ObjectMapValue)>> {
        if let Some((cached_tree_oid, values)) = &self.object_map_cache
            && *cached_tree_oid == object_map.tree_oid
        {
            return Ok(values.clone());
        }
        let values = self.object_map_values_for_uncached(object_map).await?;
        self.object_map_cache = Some((object_map.tree_oid, values.clone()));
        Ok(values)
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    async fn object_map_values_for_uncached(
        &mut self,
        object_map: ObjectMapBlock,
    ) -> crate::Result<alloc::vec::Vec<(ObjectMapKey, ObjectMapValue)>> {
        let entries = self.btree_leaf_entries(object_map.tree_oid).await?;
        let mut values = alloc::vec::Vec::new();
        for entry in entries {
            let oid_bytes = entry.key.get(0..8).ok_or(crate::ApfsError::InputTooSmall)?;
            let xid_bytes = entry
                .key
                .get(8..16)
                .ok_or(crate::ApfsError::InputTooSmall)?;
            let key = ObjectMapKey {
                oid: u64::from_le_bytes(oid_bytes.try_into().expect("checked length")),
                xid: u64::from_le_bytes(xid_bytes.try_into().expect("checked length")),
            };
            values.push((key, ObjectMapValue::parse(&entry.value)?));
        }
        Ok(values)
    }

    /// Walks a B-tree and returns owned leaf entries in traversal order.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn btree_leaf_entries(
        &mut self,
        root_physical_block: u64,
    ) -> crate::Result<alloc::vec::Vec<OwnedEntry>> {
        let root = self.read_btree_node(root_physical_block).await?;
        let info = root.tree_info()?;
        let mut leaves = alloc::vec::Vec::new();
        let mut stack = alloc::vec![root];
        while let Some(node) = stack.pop() {
            let is_leaf = node.is_leaf()?;
            let entries = node.owned_entries(Some(info))?;
            if is_leaf {
                leaves.extend(entries);
            } else {
                for entry in entries.into_iter().rev() {
                    let child_oid_bytes = entry
                        .value
                        .get(0..8)
                        .ok_or(crate::ApfsError::InputTooSmall)?;
                    let child_oid =
                        u64::from_le_bytes(child_oid_bytes.try_into().expect("checked length"));
                    stack.push(self.read_btree_node(child_oid).await?);
                }
            }
        }
        Ok(leaves)
    }

    /// Walks a "virtual" B-tree — one whose non-leaf child pointers are
    /// virtual object identifiers that must be resolved through an object
    /// map, rather than physical block addresses — and returns owned leaf
    /// entries in traversal order.
    ///
    /// The container object map's own tree stores physical child addresses
    /// directly (see [`Self::btree_leaf_entries`]), but volume filesystem
    /// trees (and other per-volume trees reachable through a volume object
    /// map) store virtual OIDs so that copy-on-write snapshots can share
    /// unmodified subtrees. Treating those virtual OIDs as physical block
    /// numbers reads unrelated blocks and typically fails with an "invalid
    /// object type" error on any filesystem tree with more than one node.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn virtual_btree_leaf_entries(
        &mut self,
        root_virtual_oid: u64,
        object_map: ObjectMapBlock,
        max_transaction_id: u64,
    ) -> crate::Result<alloc::vec::Vec<OwnedEntry>> {
        let root_value = self
            .object_map_lookup(object_map, root_virtual_oid, max_transaction_id)
            .await?
            .ok_or(crate::ApfsError::InvalidValue(
                "virtual B-tree root object not found",
            ))?;
        let root = self.read_btree_node(root_value.address).await?;
        let info = root.tree_info()?;
        let mut leaves = alloc::vec::Vec::new();
        let mut stack = alloc::vec![root];
        while let Some(node) = stack.pop() {
            let is_leaf = node.is_leaf()?;
            let entries = node.owned_entries(Some(info))?;
            if is_leaf {
                leaves.extend(entries);
            } else {
                for entry in entries.into_iter().rev() {
                    let child_oid_bytes = entry
                        .value
                        .get(0..8)
                        .ok_or(crate::ApfsError::InputTooSmall)?;
                    let child_virtual_oid =
                        u64::from_le_bytes(child_oid_bytes.try_into().expect("checked length"));
                    let child_value = self
                        .object_map_lookup(object_map, child_virtual_oid, max_transaction_id)
                        .await?
                        .ok_or(crate::ApfsError::InvalidValue(
                            "virtual B-tree child object not found",
                        ))?;
                    stack.push(self.read_btree_node(child_value.address).await?);
                }
            }
        }
        Ok(leaves)
    }

    /// Returns owned raw key/value entries from the volume filesystem root tree.
    ///
    /// The filesystem root tree's non-leaf nodes store virtual object
    /// identifiers, so this walks it through the volume's own object map
    /// (see [`Self::virtual_btree_leaf_entries`]) rather than treating
    /// `root_tree_oid` as a single physical block address to read directly.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn filesystem_root_owned_entries(
        &mut self,
        volume: &VolumeSuperblock,
    ) -> crate::Result<alloc::vec::Vec<OwnedEntry>> {
        self.filesystem_root_owned_entries_as_of(volume, volume.default_read_transaction_id())
            .await
    }

    /// Returns owned raw key/value entries from the volume filesystem root
    /// tree as it existed at `max_transaction_id`.
    ///
    /// Passing a snapshot's [`SnapshotMetadataRecord::transaction_id`] instead
    /// of the volume's current transaction identifier resolves every virtual
    /// OID in the walk against the object-map version recorded at (or before)
    /// that snapshot, reconstructing the filesystem tree as it was when the
    /// snapshot was taken. This relies on the volume's object map retaining
    /// the pre-snapshot versions of any block a later transaction
    /// copy-on-write reallocated, which APFS guarantees for as long as the
    /// snapshot exists.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn filesystem_root_owned_entries_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        max_transaction_id: u64,
    ) -> crate::Result<alloc::vec::Vec<OwnedEntry>> {
        let object_map = self.object_map_at(volume.object_map_oid).await?;
        self.virtual_btree_leaf_entries(volume.root_tree_oid, object_map, max_transaction_id)
            .await
    }

    /// Lists the volume's snapshots by walking its snapshot metadata tree.
    ///
    /// The snapshot metadata tree's OID (`apfs_superblock_t.apfs_snap_meta_tree_oid`)
    /// is a virtual OID resolved through the volume's own object map, just
    /// like the filesystem root tree (see [`Self::virtual_btree_leaf_entries`]).
    ///
    /// Unlike [`Self::filesystem_root_owned_entries`], a volume with no
    /// snapshots can have `snapshot_metadata_tree_oid` set but no
    /// corresponding entry in the object map (the tree is only materialized
    /// once a snapshot is taken), and on a live, mounted container this
    /// lookup can also lose a race with a concurrent transaction. Either way
    /// that means "no snapshots to report", not a fatal error.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn volume_snapshots(
        &mut self,
        volume: &VolumeSuperblock,
    ) -> crate::Result<alloc::vec::Vec<SnapshotMetadataRecord>> {
        if volume.snapshot_metadata_tree_oid == 0 {
            return Ok(alloc::vec::Vec::new());
        }
        let object_map = self.object_map_at(volume.object_map_oid).await?;
        let root_value = self
            .object_map_lookup(
                object_map,
                volume.snapshot_metadata_tree_oid,
                volume.default_read_transaction_id(),
            )
            .await?;
        let Some(root_value) = root_value else {
            return Ok(alloc::vec::Vec::new());
        };
        let root = self.read_btree_node(root_value.address).await?;
        let info = root.tree_info()?;
        let mut leaves = alloc::vec::Vec::new();
        let mut stack = alloc::vec![root];
        while let Some(node) = stack.pop() {
            let is_leaf = node.is_leaf()?;
            let entries = node.owned_entries(Some(info))?;
            if is_leaf {
                leaves.extend(entries);
            } else {
                for entry in entries.into_iter().rev() {
                    let child_oid_bytes = entry
                        .value
                        .get(0..8)
                        .ok_or(crate::ApfsError::InputTooSmall)?;
                    let child_virtual_oid =
                        u64::from_le_bytes(child_oid_bytes.try_into().expect("checked length"));
                    let child_value = self
                        .object_map_lookup(
                            object_map,
                            child_virtual_oid,
                            volume.default_read_transaction_id(),
                        )
                        .await?;
                    if let Some(child_value) = child_value {
                        stack.push(self.read_btree_node(child_value.address).await?);
                    }
                }
            }
        }
        Ok(crate::types::parse_snapshot_metadata_records(leaves))
    }

    /// Finds a volume snapshot by name.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn find_volume_snapshot(
        &mut self,
        volume: &VolumeSuperblock,
        name: &str,
    ) -> crate::Result<Option<SnapshotMetadataRecord>> {
        Ok(self
            .volume_snapshots(volume)
            .await?
            .into_iter()
            .find(|snapshot| snapshot.name == name))
    }

    /// Lists owned entries for a directory inode.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn directory_owned_entries(
        &mut self,
        volume: &VolumeSuperblock,
        directory_id: u64,
    ) -> crate::Result<alloc::vec::Vec<OwnedDirectoryEntryRecord>> {
        self.directory_owned_entries_as_of(
            volume,
            directory_id,
            volume.default_read_transaction_id(),
        )
        .await
    }

    /// Lists owned entries for a directory inode as of `max_transaction_id`.
    ///
    /// Pass a [`SnapshotMetadataRecord::transaction_id`] to list a directory
    /// as it existed at that snapshot.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn directory_owned_entries_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        directory_id: u64,
        max_transaction_id: u64,
    ) -> crate::Result<alloc::vec::Vec<OwnedDirectoryEntryRecord>> {
        let hashed =
            crate::types::filesystem::uses_hashed_directory_keys(volume.incompatible_features);
        Ok(crate::types::filesystem::parse_owned_directory_entries(
            self.filesystem_root_owned_entries_as_of(volume, max_transaction_id)
                .await?,
            directory_id,
            hashed,
        ))
    }

    /// Finds an owned entry by name in a directory inode.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn directory_owned_entry(
        &mut self,
        volume: &VolumeSuperblock,
        directory_id: u64,
        name: &str,
    ) -> crate::Result<Option<OwnedDirectoryEntryRecord>> {
        self.directory_owned_entry_as_of(
            volume,
            directory_id,
            name,
            volume.default_read_transaction_id(),
        )
        .await
    }

    /// Finds an owned entry by name in a directory inode as of `max_transaction_id`.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn directory_owned_entry_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        directory_id: u64,
        name: &str,
        max_transaction_id: u64,
    ) -> crate::Result<Option<OwnedDirectoryEntryRecord>> {
        Ok(self
            .directory_owned_entries_as_of(volume, directory_id, max_transaction_id)
            .await?
            .into_iter()
            .find(|entry| entry.name == name))
    }

    /// Resolves a slash-separated path from the volume root directory.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn resolve_path(
        &mut self,
        volume: &VolumeSuperblock,
        path: &str,
    ) -> crate::Result<Option<OwnedDirectoryEntryRecord>> {
        self.resolve_path_as_of(volume, path, volume.default_read_transaction_id())
            .await
    }

    /// Resolves a slash-separated path from the volume root directory as of
    /// `max_transaction_id`.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn resolve_path_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        path: &str,
        max_transaction_id: u64,
    ) -> crate::Result<Option<OwnedDirectoryEntryRecord>> {
        let mut parent = crate::types::filesystem::INODE_ROOT_DIRECTORY;
        let mut current = None;
        for component in path.split('/').filter(|part| !part.is_empty()) {
            let entry = match self
                .directory_owned_entry_as_of(volume, parent, component, max_transaction_id)
                .await?
            {
                Some(entry) => entry,
                None => return Ok(None),
            };
            parent = entry.file_id;
            current = Some(entry);
        }
        Ok(current)
    }

    /// Lists owned entries in a volume's root directory when the filesystem root tree is a leaf/root node.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn root_directory_owned_entries(
        &mut self,
        volume: &VolumeSuperblock,
    ) -> crate::Result<alloc::vec::Vec<OwnedDirectoryEntryRecord>> {
        self.directory_owned_entries(volume, crate::types::filesystem::INODE_ROOT_DIRECTORY)
            .await
    }

    /// Lists owned entries in a volume's root directory as of `max_transaction_id`.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn root_directory_owned_entries_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        max_transaction_id: u64,
    ) -> crate::Result<alloc::vec::Vec<OwnedDirectoryEntryRecord>> {
        self.directory_owned_entries_as_of(
            volume,
            crate::types::filesystem::INODE_ROOT_DIRECTORY,
            max_transaction_id,
        )
        .await
    }

    /// Finds an owned root-directory entry by name.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn root_directory_owned_entry(
        &mut self,
        volume: &VolumeSuperblock,
        name: &str,
    ) -> crate::Result<Option<OwnedDirectoryEntryRecord>> {
        self.directory_owned_entry(volume, crate::types::filesystem::INODE_ROOT_DIRECTORY, name)
            .await
    }

    /// Finds an inode record by inode identifier in the root filesystem tree.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn inode_record(
        &mut self,
        volume: &VolumeSuperblock,
        inode: u64,
    ) -> crate::Result<Option<InodeRecord>> {
        self.inode_record_as_of(volume, inode, volume.default_read_transaction_id())
            .await
    }

    /// Finds an inode record by inode identifier in the root filesystem tree
    /// as of `max_transaction_id`.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn inode_record_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        inode: u64,
        max_transaction_id: u64,
    ) -> crate::Result<Option<InodeRecord>> {
        Ok(self
            .filesystem_root_owned_entries_as_of(volume, max_transaction_id)
            .await?
            .into_iter()
            .filter_map(|entry| {
                let key = FileSystemKey::parse(&entry.key).ok()?;
                (key.id == inode && key.record_type == crate::types::filesystem::FS_TYPE_INODE)
                    .then(|| InodeRecord::parse(&entry.key, &entry.value).ok())
                    .flatten()
            })
            .next())
    }

    /// Finds file extents for an inode/private data-stream identifier in the root filesystem tree.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn file_extents(
        &mut self,
        volume: &VolumeSuperblock,
        id: u64,
    ) -> crate::Result<alloc::vec::Vec<FileExtentRecord>> {
        self.file_extents_as_of(volume, id, volume.default_read_transaction_id())
            .await
    }

    /// Finds file extents for an inode/private data-stream identifier in the
    /// root filesystem tree as of `max_transaction_id`.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn file_extents_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        id: u64,
        max_transaction_id: u64,
    ) -> crate::Result<alloc::vec::Vec<FileExtentRecord>> {
        let mut extents: alloc::vec::Vec<FileExtentRecord> = self
            .filesystem_root_owned_entries_as_of(volume, max_transaction_id)
            .await?
            .into_iter()
            .filter_map(|entry| FileExtentRecord::parse(&entry.key, &entry.value).ok())
            .filter(|extent| extent.id == id)
            .collect();
        extents.sort_by_key(|extent| extent.logical_address);
        Ok(extents)
    }

    /// Returns the effective file size: the inode's exact data-stream size when
    /// present, then the inode's uncompressed size when set, otherwise the sum
    /// of the data stream's extent lengths.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn file_size(&mut self, volume: &VolumeSuperblock, inode: u64) -> crate::Result<u64> {
        self.file_size_as_of(volume, inode, volume.default_read_transaction_id())
            .await
    }

    /// Returns the effective file size as of `max_transaction_id`. See
    /// [`Self::file_size`].
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn file_size_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        inode: u64,
        max_transaction_id: u64,
    ) -> crate::Result<u64> {
        let inode = self
            .inode_record_as_of(volume, inode, max_transaction_id)
            .await?
            .ok_or(crate::ApfsError::InvalidValue("inode record not found"))?;
        if let Some(size) = inode.data_stream_size {
            return Ok(size);
        }
        if inode.uncompressed_size != 0 {
            return Ok(inode.uncompressed_size);
        }
        // Sum extent lengths, not their end offsets, would undercount a
        // sparse file (one with unallocated holes not covered by any
        // extent record): the logical byte range still includes the holes,
        // but no extent bytes exist for them. The highest logical end
        // offset among all extents is the correct fallback size.
        Ok(self
            .file_extents_as_of(volume, inode.private_id, max_transaction_id)
            .await?
            .iter()
            .map(|extent| extent.logical_address.saturating_add(extent.length))
            .max()
            .unwrap_or(0))
    }

    /// Reads file bytes for a small uncompressed file described by filesystem extents.
    ///
    /// Extents are placed at their recorded `logical_address` rather than
    /// concatenated in extent order: a sparse file can have logical byte
    /// ranges ("holes") not covered by any extent record, and simply
    /// concatenating extent data shifts all bytes after a hole down by the
    /// hole's size instead of leaving it zero-filled.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn read_file(
        &mut self,
        volume: &VolumeSuperblock,
        inode: u64,
        max_bytes: usize,
    ) -> crate::Result<alloc::vec::Vec<u8>> {
        self.read_file_as_of(
            volume,
            inode,
            max_bytes,
            volume.default_read_transaction_id(),
        )
        .await
    }

    /// Reads file bytes as of `max_transaction_id`. See [`Self::read_file`].
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn read_file_as_of(
        &mut self,
        volume: &VolumeSuperblock,
        inode: u64,
        max_bytes: usize,
        max_transaction_id: u64,
    ) -> crate::Result<alloc::vec::Vec<u8>> {
        let inode = self
            .inode_record_as_of(volume, inode, max_transaction_id)
            .await?
            .ok_or(crate::ApfsError::InvalidValue("inode record not found"))?;
        let known_size = inode.data_stream_size.filter(|size| *size != 0).or({
            if inode.uncompressed_size != 0 {
                Some(inode.uncompressed_size)
            } else {
                None
            }
        });
        let extents = self
            .file_extents_as_of(volume, inode.private_id, max_transaction_id)
            .await?;
        let extents_end = extents
            .iter()
            .map(|extent| extent.logical_address.saturating_add(extent.length))
            .max()
            .unwrap_or(0) as usize;
        let limit = match known_size {
            Some(size) => max_bytes.min(size as usize),
            // With no recorded size, cap output at the data actually covered
            // by extents rather than eagerly allocating up to `max_bytes`
            // (which callers may pass as a large ceiling, e.g. 1 GiB).
            None => max_bytes.min(extents_end),
        };
        let mut output = alloc::vec![0_u8; limit];
        for extent in extents {
            let start = extent.logical_address as usize;
            if start >= limit {
                continue;
            }
            let mut remaining = extent.length as usize;
            let mut block = extent.physical_block;
            let mut pos = start;
            while remaining > 0 && pos < limit {
                let data = self.read_apfs_block_vec(block).await?;
                let take = remaining.min(data.len()).min(limit - pos);
                output[pos..pos + take].copy_from_slice(&data[..take]);
                remaining -= take;
                pos += take;
                block = block
                    .checked_add(1)
                    .ok_or(crate::ApfsError::AddressOverflow)?;
            }
        }
        Ok(output)
    }

    /// Reads an owned B-tree node at a physical APFS block address.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub async fn read_btree_node(&mut self, physical_block: u64) -> crate::Result<OwnedBTreeNode> {
        let data = self.read_apfs_block_vec(physical_block).await?;
        verify_object(&data)?;
        OwnedBTreeNode::parse(data)
    }

    /// Consumes the reader and returns the wrapped device.
    pub fn into_inner(self) -> D {
        self.device
    }
}
