use super::Container;
use super::FileSystem;
use super::storage::BlockDevice;
use crate::types::filesystem::{
    self, DirectoryEntryRecord, FileExtentRecord, XattrRecord, stream_size,
};
use crate::types::{ContainerSuperblock, InodeRecord, VolumeSuperblock};
use crate::{Detail, VolumeSelector};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use hadris_fs::{
    Capabilities, CaseRule, Charset, DateTime, DirCursor, DirEntry, Error, ErrorKind, Field,
    FileType, FsResult, FsStats, Metadata, MountError, MountOptions, Name, NameError, NodeId,
    OpenMode, Owner, Permissions, Stored,
};
#[cfg(feature = "write")]
use hadris_fs::{RenameMode, SetAttr};

#[cfg(feature = "write")]
#[derive(Debug, Default)]
struct NodeUse {
    pins: u64,
    opens: u64,
    removed: bool,
}

fn file_type<E>(inode: &InodeRecord) -> FsResult<FileType, E> {
    match inode.mode & 0o170000 {
        0o100000 => Ok(FileType::File),
        0o040000 => Ok(FileType::Dir),
        0o120000 => Ok(FileType::Symlink),
        0o020000 => Ok(FileType::CharDevice),
        0o060000 => Ok(FileType::BlockDevice),
        0o010000 => Ok(FileType::Fifo),
        0o140000 => Ok(FileType::Socket),
        _ => Err(Error::new(ErrorKind::Corrupt, "invalid APFS inode mode")),
    }
}

/// The directory entry type an inode's mode implies (`DT_*`).
const fn entry_type(kind: FileType) -> u16 {
    match kind {
        FileType::File => 8,
        FileType::Dir => 4,
        FileType::Symlink => 10,
        FileType::CharDevice => 2,
        FileType::BlockDevice => 6,
        FileType::Fifo => 1,
        FileType::Socket => 12,
        _ => 0,
    }
}

/// The metadata listed for an entry whose node cannot be described: the
/// type its directory record holds and nothing else.
fn damaged(flags: u16) -> Metadata {
    let kind = match flags & filesystem::DREC_TYPE_MASK {
        4 => FileType::Dir,
        10 => FileType::Symlink,
        2 => FileType::CharDevice,
        6 => FileType::BlockDevice,
        1 => FileType::Fifo,
        12 => FileType::Socket,
        _ => FileType::File,
    };
    Metadata::new(kind, Permissions::new(0))
}

fn timestamp<E>(nanoseconds: u64) -> FsResult<DateTime, E> {
    Ok(
        DateTime::from_unix_seconds((nanoseconds / 1_000_000_000) as i64)?
            .with_nanoseconds((nanoseconds % 1_000_000_000) as u32)?,
    )
}

fn selection_error<E>(kind: ErrorKind, message: &'static str) -> Error<E> {
    Error::new(kind, message).with_detail(Detail::VolumeSelection.code())
}

/// Whether an error reports a resource failure rather than a record that
/// cannot be used. Such an error reaches the caller instead of being reported
/// as a damaged node.
fn is_resource(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::Io | ErrorKind::LimitExceeded)
}

/// One directory record; `name` holds the on-disk bytes.
#[derive(Debug)]
struct Entry {
    file_id: u64,
    flags: u16,
    name: Vec<u8>,
}

/// The reason a directory entry cannot describe the inode it names, or
/// `None`: the type the entry records must agree with the inode's mode, and a
/// directory's own parent must be the directory the entry appears in.
fn entry_damage(parent: u64, flags: u16, inode: &InodeRecord) -> Option<&'static str> {
    let Ok(kind) = file_type::<()>(inode) else {
        return None;
    };
    let recorded = flags & filesystem::DREC_TYPE_MASK;
    if recorded != 0 && recorded != entry_type(kind) {
        return Some("APFS directory entry type disagrees with inode");
    }
    if kind.is_dir() && (inode.parent_id != parent || inode.id == parent) {
        return Some("APFS directory parent disagrees with inode");
    }
    None
}

/// Node records read on demand and kept for the nodes in use.
///
/// A record that cannot be used damages only the node it describes: such a
/// node stays listed and fails `stat`, `read`, `open` and `readlink` with the
/// reason in `damaged`. `limit` caps how many nodes may be held at once; an
/// operation that needs one more fails with `LimitExceeded`.
#[derive(Debug, Default)]
struct Nodes {
    limit: Option<usize>,
    inodes: BTreeMap<u64, InodeRecord>,
    damaged: BTreeMap<u64, &'static str>,
    directories: BTreeMap<u64, Vec<Entry>>,
    extents: BTreeMap<u64, Vec<FileExtentRecord>>,
    symlinks: BTreeMap<u64, Option<(u16, Vec<u8>)>>,
}

impl Nodes {
    fn new(limit: Option<usize>) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Records why a node cannot be used.
    fn record(&mut self, node: u64, reason: &'static str) {
        self.damaged.insert(node, reason);
    }

    /// Records why a node cannot be used and returns the error to report.
    fn damage<E>(&mut self, node: u64, reason: &'static str) -> Error<E> {
        self.record(node, reason);
        Error::new(ErrorKind::Corrupt, reason)
    }

    /// Fails with `LimitExceeded` when reading a node's records would hold
    /// more nodes than `limit` allows.
    fn reserve<E>(&self, node: u64) -> FsResult<(), E> {
        if self.inodes.contains_key(&node) || self.damaged.contains_key(&node) {
            return Ok(());
        }
        match self.limit {
            Some(limit) if self.inodes.len() + self.damaged.len() >= limit => {
                Err(ErrorKind::LimitExceeded.into())
            }
            _ => Ok(()),
        }
    }

    /// Drops everything held for `node`.
    fn release(&mut self, node: u64) {
        if let Some(inode) = self.inodes.remove(&node) {
            self.extents.remove(&inode.private_id);
        }
        self.directories.remove(&node);
        self.extents.remove(&node);
        self.symlinks.remove(&node);
        self.damaged.remove(&node);
    }

    fn entries(&self, dir: u64) -> &[Entry] {
        self.directories.get(&dir).map_or(&[], Vec::as_slice)
    }

    fn extents(&self, stream: u64) -> &[FileExtentRecord] {
        self.extents.get(&stream).map_or(&[], Vec::as_slice)
    }

    /// Returns a symlink target recorded for `inode`.
    fn target<E>(&self, inode: u64) -> FsResult<&[u8], E> {
        symlink_target(self.symlinks.get(&inode).and_then(Option::as_ref))
    }
}

/// The target a symlink's attribute holds.
fn symlink_target<E>(attribute: Option<&(u16, Vec<u8>)>) -> FsResult<&[u8], E> {
    let (flags, data) =
        attribute.ok_or_else(|| Error::new(ErrorKind::Corrupt, "APFS symlink target missing"))?;
    if flags & filesystem::XATTR_DATA_EMBEDDED == 0 {
        return Err(crate::ApfsError::Unsupported("symlink target stored in a data stream").into());
    }
    let target = data.strip_suffix(&[0]).unwrap_or(data);
    if target.contains(&0) {
        return Err(Error::new(
            ErrorKind::Corrupt,
            "APFS symlink target contains NUL",
        ));
    }
    Ok(target)
}

/// A file's size and the bytes its extents allocate.
fn extent_sizes<E>(inode: &InodeRecord, extents: &[FileExtentRecord]) -> FsResult<(u64, u64), E> {
    let allocated = extents
        .iter()
        .filter(|extent| extent.physical_block != 0)
        .try_fold(0u64, |total, extent| total.checked_add(extent.length))
        .ok_or(ErrorKind::Corrupt)?;
    Ok((stream_size(inode, extents), allocated))
}

io_transform! {

/// APFS volume driver implementing the shared filesystem contract.
///
/// Node identifiers are stable APFS inode identifiers. The driver owns one
/// container and selects one volume from its newest checkpoint. It reads a
/// node's records when an operation first needs them and keeps them for the
/// nodes in use, so mounting a large volume does not read the whole
/// filesystem tree. File data is read with one APFS block of scratch space
/// regardless of file length. `MountOptions::with_node_limit` caps how many
/// nodes may be held; an operation that needs one more fails with
/// `LimitExceeded`. Compression, encryption and snapshots remain unsupported.
///
/// A record that cannot be used damages only its node: the entry is listed
/// with the type its directory record holds, and `stat`, `open`, `read` and
/// `readlink` on the node return the error. Names are exposed as their
/// on-disk bytes, without UTF-8 validation or a 255-byte limit.
///
/// The usual mount constructors remain read-only. With `write`, explicit
/// writable mounts validate the supported single-volume, unencrypted layout.
/// Each mutation publishes a durable checkpoint before returning.
#[derive(Debug)]
#[non_exhaustive]
pub struct ApfsFs<D> {
    container: Container<D>,
    checkpoint: ContainerSuperblock,
    volume: VolumeSuperblock,
    nodes: Nodes,
    #[cfg(feature = "write")]
    writable: bool,
    #[cfg(feature = "write")]
    uses: BTreeMap<u64, NodeUse>,
}

impl<D: BlockDevice> ApfsFs<D> {
    /// Mounts the sole volume in the container's newest checkpoint.
    ///
    /// Containers with no volumes fail with `NotFound`; multiple volumes
    /// require [`Self::mount_volume`] and fail with `InvalidInput`. Container
    /// or selected-volume incompatible features this reader cannot read fail
    /// with `Unsupported` and [`Detail::Feature`]; see
    /// [`ContainerSuperblock::check_incompatible_features`] and
    /// [`VolumeSuperblock::check_incompatible_features`].
    /// Mount failures return the device for inspection or retry.
    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all))]
    pub async fn mount(device: D, options: MountOptions) -> Result<Self, MountError<D, D::Error>> {
        Self::mount_selected(device, options, None, None, false).await
    }

    /// Mounts exactly one volume selected by index, object identifier, UUID or
    /// exact name. Missing selectors fail with `NotFound`; duplicate matches
    /// fail with `InvalidInput`. Names are case sensitive for selection.
    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all))]
    pub async fn mount_volume(
        device: D,
        options: MountOptions,
        selector: VolumeSelector<'_>,
    ) -> Result<Self, MountError<D, D::Error>> {
        Self::mount_selected(device, options, Some(selector), None, false).await
    }

    /// Mounts the sole supported volume for experimental existing-volume writes.
    ///
    /// Unsupported container layouts fail before any writes. `read_only`
    /// options are rejected rather than silently granting write access.
    #[cfg(feature = "write")]
    pub async fn mount_writable(
        device: D,
        options: MountOptions,
    ) -> Result<Self, MountError<D, D::Error>> {
        Self::mount_selected(device, options, None, None, true).await
    }

    /// Mounts an explicitly selected volume for experimental writes.
    #[cfg(feature = "write")]
    pub async fn mount_volume_writable(
        device: D,
        options: MountOptions,
        selector: VolumeSelector<'_>,
    ) -> Result<Self, MountError<D, D::Error>> {
        Self::mount_selected(device, options, Some(selector), None, true).await
    }

    /// Mounts the sole software-encrypted, single-key volume using a password.
    ///
    /// `crypto_user` selects a crypto-user UUID, or `None` searches supported
    /// password records. Wrong credentials return `InvalidInput` with
    /// [`Detail::Credentials`], preserving
    /// the device. Passwords are borrowed only during mounting. See
    /// [`Container::unlock_volume`] for supported encryption and resource limits.
    #[cfg(feature = "encryption")]
    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all))]
    pub async fn mount_with_password(
        device: D,
        options: MountOptions,
        password: &[u8],
        crypto_user: Option<[u8; 16]>,
    ) -> Result<Self, MountError<D, D::Error>> {
        Self::mount_selected(device, options, None, Some((password, crypto_user)), false).await
    }

    /// Mounts an explicitly selected software-encrypted volume using a password.
    ///
    /// Volume selection is independent of the optional crypto-user UUID.
    /// Credentials and limits behave as in [`Self::mount_with_password`].
    #[cfg(feature = "encryption")]
    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all))]
    pub async fn mount_volume_with_password(
        device: D,
        options: MountOptions,
        selector: VolumeSelector<'_>,
        password: &[u8],
        crypto_user: Option<[u8; 16]>,
    ) -> Result<Self, MountError<D, D::Error>> {
        Self::mount_selected(device, options, Some(selector), Some((password, crypto_user)), false).await
    }

    async fn mount_selected(
        device: D,
        options: MountOptions,
        selector: Option<VolumeSelector<'_>>,
        credentials: Option<(&[u8], Option<[u8; 16]>)>,
        writable: bool,
    ) -> Result<Self, MountError<D, D::Error>> {
        if writable && options.is_read_only() {
            return Err(MountError::new(ErrorKind::InvalidInput.into(), device));
        }
        let mut container = Container::try_open(device).await?;
        let selected = match Self::select_volume(&mut container, selector, credentials).await {
            Ok(selected) => selected,
            Err(error) => return Err(MountError::new(error, container.into_inner())),
        };
        let (checkpoint, volume) = selected;
        let mut fs = Self {
            container,
            checkpoint,
            volume,
            nodes: Nodes::new(options.node_limit()),
            #[cfg(feature = "write")]
            writable,
            #[cfg(feature = "write")]
            uses: BTreeMap::new(),
        };
        let _ = writable;
        #[cfg(feature = "write")]
        if fs.writable {
            if let Err(error) = fs.container.validate_write(&fs.checkpoint, &fs.volume).await {
                return Err(MountError::new(error, fs.container.into_inner()));
            }
        }
        match fs.check_root().await {
            Ok(()) => Ok(fs),
            Err(error) => Err(MountError::new(error, fs.container.into_inner())),
        }
    }

    async fn select_volume(
        container: &mut Container<D>,
        selector: Option<VolumeSelector<'_>>,
        credentials: Option<(&[u8], Option<[u8; 16]>)>,
    ) -> FsResult<(ContainerSuperblock, VolumeSuperblock), D::Error> {
        let checkpoint = container.latest_superblock().await?;
        checkpoint.check_incompatible_features()?;
        let volumes = container.volume_superblocks(&checkpoint).await?;
        let mut selected = None;
        for volume in volumes {
            let matches = match selector {
                None => true,
                Some(VolumeSelector::Index(index)) => volume.fs_index == index,
                Some(VolumeSelector::ObjectId(oid)) => volume.object.identifier == oid,
                Some(VolumeSelector::Uuid(uuid)) => volume.volume_id == uuid,
                Some(VolumeSelector::Name(name)) => volume.name()? == name,
            };
            if matches {
                if selected.is_some() {
                    return Err(selection_error(ErrorKind::InvalidInput, "APFS volume selection is ambiguous"));
                }
                selected = Some(volume);
            }
        }
        let volume = selected.ok_or_else(|| selection_error(ErrorKind::NotFound, "APFS volume not found"))?;
        volume.check_incompatible_features()?;
        if checkpoint.flags & 4 != 0 && volume.flags & crate::types::volume::APFS_FS_UNENCRYPTED == 0 {
            if volume.flags & crate::types::volume::APFS_FS_ONEKEY == 0 {
                return Err(crate::ApfsError::Unsupported("APFS per-file-key encryption").into());
            }
            if credentials.is_none() {
                return Err(crate::ApfsError::Unsupported("encrypted APFS volume requires credentials").into());
            }
        }
        if let Some((password, crypto_user)) = credentials {
            #[cfg(feature = "encryption")]
            container.unlock_selected(&checkpoint, &volume, password, crypto_user).await?;
            #[cfg(not(feature = "encryption"))]
            {
                let _ = (password, crypto_user);
                return Err(ErrorKind::Unsupported.into());
            }
        }
        Ok((checkpoint, volume))
    }

    /// Reads the root inode and the directory entries that name it, so that a
    /// volume whose root cannot be read fails at mount.
    async fn check_root(&mut self) -> FsResult<(), D::Error> {
        let root = self.root();
        let inode = match self.inode(root).await {
            Ok(inode) => inode,
            Err(error) if error.kind() == ErrorKind::InvalidHandle => {
                return Err(Error::new(ErrorKind::Corrupt, "APFS root inode missing"));
            }
            Err(error) => return Err(error),
        };
        if !file_type::<D::Error>(&inode)?.is_dir() {
            return Err(Error::new(ErrorKind::Corrupt, "APFS root is not a directory"));
        }
        Ok(())
    }

    /// The selected volume superblock, including its UUID, name and slot.
    pub const fn volume_superblock(&self) -> &VolumeSuperblock {
        &self.volume
    }

    /// The checkpoint from which the selected volume was opened.
    pub const fn checkpoint(&self) -> &ContainerSuperblock {
        &self.checkpoint
    }

    /// The container reader for native metadata inspection.
    pub const fn container(&self) -> &Container<D> {
        &self.container
    }

    /// Borrows the container reader for native metadata inspection.
    pub fn container_mut(&mut self) -> &mut Container<D> {
        &mut self.container
    }

    /// Returns the container for continued native inspection.
    pub fn into_container(self) -> Container<D> {
        self.container
    }

    /// Returns the owned device without issuing I/O.
    pub fn into_inner(self) -> D {
        self.container.into_inner()
    }

    /// Unmounts the driver and returns its device after flushing a writable mount.
    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all))]
    pub async fn unmount(mut self) -> Result<D, MountError<D, D::Error>> {
        if let Err(error) = self.sync().await {
            return Err(MountError::new(error, self.container.into_inner()));
        }
        Ok(self.container.into_inner())
    }

    /// Returns a node's inode record, reading it and the directory entries
    /// that name it on first use. A record that cannot be used damages the
    /// node, which fails here from then on.
    async fn inode(&mut self, node: NodeId) -> FsResult<InodeRecord, D::Error> {
        let id = node.get();
        #[cfg(feature = "write")]
        if self.uses.get(&id).is_some_and(|state| state.removed) {
            return Err(ErrorKind::NotFound.into());
        }
        if let Some(reason) = self.nodes.damaged.get(&id) {
            return Err(Error::new(ErrorKind::Corrupt, reason));
        }
        if let Some(inode) = self.nodes.inodes.get(&id) {
            return Ok(*inode);
        }
        self.nodes.reserve(id)?;
        let inode = self.read_inode(id).await?;
        if let Some(reason) = self.entry_damage(inode.parent_id, id, &inode).await? {
            return Err(self.nodes.damage(id, reason));
        }
        self.nodes.inodes.insert(id, inode);
        Ok(inode)
    }

    /// The reason a directory entry in `parent` cannot describe `inode`, as
    /// the mount reported for every record at once; see [`entry_damage`].
    async fn entry_damage(
        &mut self,
        parent: u64,
        id: u64,
        inode: &InodeRecord,
    ) -> FsResult<Option<&'static str>, D::Error> {
        Ok(self
            .directory_entries(parent)
            .await?
            .iter()
            .filter(|entry| entry.file_id == id)
            .find_map(|entry| entry_damage(parent, entry.flags, inode)))
    }

    /// Reads a directory's entries in key order on first use, skipping records
    /// that do not parse and names the entry type cannot carry.
    async fn directory_entries(&mut self, dir: u64) -> FsResult<&[Entry], D::Error> {
        if !self.nodes.directories.contains_key(&dir) {
            self.nodes.reserve(dir)?;
            let layout = self.volume.directory_key_layout();
            let mut entries = alloc::vec::Vec::new();
            for entry in self
                .container
                .filesystem_records(&self.volume, dir, filesystem::FS_TYPE_DIRECTORY_RECORD)
                .await?
            {
                let Ok(record) = DirectoryEntryRecord::parse(&entry.key, &entry.value, layout)
                else {
                    continue;
                };
                if Name::new(record.name).check().is_err() {
                    continue;
                }
                entries.push(Entry {
                    file_id: record.file_id,
                    flags: record.flags,
                    name: record.name.to_vec(),
                });
            }
            self.nodes.directories.insert(dir, entries);
        }
        Ok(self.nodes.entries(dir))
    }

    /// Reads a data stream's extents and checks them, as the mount did for
    /// every stream at once. A stream that fails damages the node the
    /// extents belong to.
    async fn read_extents(&mut self, inode: &InodeRecord) -> FsResult<alloc::vec::Vec<FileExtentRecord>, D::Error> {
        let stream = inode.private_id;
        let mut extents = alloc::vec::Vec::new();
        let mut reason = None;
        for entry in self
            .container
            .filesystem_records(&self.volume, stream, filesystem::FS_TYPE_FILE_EXTENT)
            .await?
        {
            match FileExtentRecord::parse(&entry.key, &entry.value) {
                Ok(extent) => extents.push(extent),
                Err(_) => reason = Some("damaged APFS file extents"),
            }
        }
        extents.extend(self.container.sealed_stream_extents(&self.volume, stream).await?);
        extents.sort_by_key(|extent| extent.logical_address);
        let block_size = u64::from(self.checkpoint.block_size);
        let mut end = 0;
        for extent in &extents {
            let Some(extent_end) = extent.logical_address.checked_add(extent.length) else {
                reason = Some("damaged APFS file extents");
                continue;
            };
            if extent.logical_address < end {
                reason = Some("damaged APFS file extents");
            }
            end = extent_end;
            if extent.physical_block != 0
                && extent
                    .physical_block
                    .checked_add(extent.length.div_ceil(block_size))
                    .is_none_or(|end| end > self.checkpoint.block_count)
            {
                reason = Some("APFS file extent outside container");
            }
        }
        if let Some(reason) = reason {
            return Err(self.nodes.damage(inode.id, reason));
        }
        Ok(extents)
    }

    /// Reads a data stream's extents on first use and holds them for the node.
    async fn load_extents(&mut self, inode: &InodeRecord) -> FsResult<(), D::Error> {
        if self.nodes.extents.contains_key(&inode.private_id) {
            return Ok(());
        }
        let extents = self.read_extents(inode).await?;
        self.nodes.extents.insert(inode.private_id, extents);
        Ok(())
    }

    /// Reads a symlink's target attribute. A duplicated target damages the
    /// node.
    async fn read_symlink(&mut self, inode: u64) -> FsResult<Option<(u16, Vec<u8>)>, D::Error> {
        let mut target: Option<(u16, Vec<u8>)> = None;
        let mut duplicate = false;
        for entry in self
            .container
            .filesystem_records(&self.volume, inode, filesystem::FS_TYPE_XATTR)
            .await?
        {
            let Ok(xattr) = XattrRecord::parse(&entry.key, &entry.value) else {
                continue;
            };
            if xattr.name != filesystem::SYMLINK_XATTR_NAME {
                continue;
            }
            if target.is_some() {
                duplicate = true;
                continue;
            }
            target = Some((xattr.flags, xattr.data.to_vec()));
        }
        if duplicate {
            return Err(self.nodes.damage(inode, "duplicate APFS symlink target"));
        }
        Ok(target)
    }

    /// Reads a symlink's target attribute on first use and holds it for the
    /// node.
    async fn load_symlink(&mut self, inode: u64) -> FsResult<(), D::Error> {
        if self.nodes.symlinks.contains_key(&inode) {
            return Ok(());
        }
        self.nodes.reserve(inode)?;
        let target = self.read_symlink(inode).await?;
        self.nodes.symlinks.insert(inode, target);
        Ok(())
    }

    async fn directory(&mut self, node: NodeId) -> FsResult<InodeRecord, D::Error> {
        let inode = self.inode(node).await?;
        if !file_type::<D::Error>(&inode)?.is_dir() {
            return Err(ErrorKind::NotADirectory.into());
        }
        Ok(inode)
    }

    /// Reads a node's inode record without holding it. A record that cannot
    /// be used damages the node.
    async fn read_inode(&mut self, id: u64) -> FsResult<InodeRecord, D::Error> {
        let records = self
            .container
            .filesystem_records(&self.volume, id, filesystem::FS_TYPE_INODE)
            .await?;
        match records.len() {
            0 => Err(ErrorKind::InvalidHandle.into()),
            1 => InodeRecord::parse(&records[0].key, &records[0].value)
                .map_err(|_| self.nodes.damage(id, "malformed APFS inode record")),
            _ => Err(self.nodes.damage(id, "duplicate APFS inode")),
        }
    }

    /// The metadata of a child a listing reports. A node already held uses
    /// its records; any other is read and dropped, so listing a directory
    /// neither fills the node limit nor keeps every child's records.
    async fn listed_metadata(&mut self, dir: u64, id: u64, flags: u16) -> FsResult<Metadata, D::Error> {
        let node = NodeId::new(id).ok_or(ErrorKind::Corrupt)?;
        let held = self.nodes.inodes.contains_key(&id) || self.nodes.damaged.contains_key(&id);
        let inode = if held {
            self.inode(node).await?
        } else {
            self.read_inode(id).await?
        };
        if let Some(reason) = entry_damage(dir, flags, &inode) {
            return Err(self.nodes.damage(id, reason));
        }
        self.metadata(&inode, held).await
    }

    /// Builds a node's metadata. With `keep`, the extents or symlink target
    /// it reads stay held for the node; without, they are dropped.
    async fn metadata(&mut self, inode: &InodeRecord, keep: bool) -> FsResult<Metadata, D::Error> {
        let kind = file_type::<D::Error>(inode)?;
        let mut metadata = Metadata::new(kind, Permissions::new(u32::from(inode.mode & 0o7777)))
            .with_owner(Owner::new(inode.owner, inode.group))
            .with_created(timestamp::<D::Error>(inode.create_time_ns)?)
            .with_modified(timestamp::<D::Error>(inode.modification_time_ns)?)
            .with_changed(timestamp::<D::Error>(inode.change_time_ns)?)
            .with_accessed(timestamp::<D::Error>(inode.access_time_ns)?)
            .with_nlink(if kind.is_dir() { 1 } else { u64::try_from(inode.link_or_child_count).map_err(|_| ErrorKind::Corrupt)?.max(1) });
        if kind.is_file() {
            let (len, allocated) = if keep {
                self.load_extents(inode).await?;
                extent_sizes(inode, self.nodes.extents(inode.private_id))?
            } else {
                let extents = self.read_extents(inode).await?;
                extent_sizes(inode, &extents)?
            };
            metadata = metadata.with_len(len).with_allocated(allocated);
        } else if kind.is_symlink() {
            let len = if keep {
                self.load_symlink(inode.id).await?;
                self.nodes.target::<D::Error>(inode.id)?.len()
            } else {
                let attribute = self.read_symlink(inode.id).await?;
                symlink_target::<D::Error>(attribute.as_ref())?.len()
            };
            metadata = metadata.with_len(len as u64);
        }
        Ok(metadata)
    }
}

impl<D: BlockDevice> ApfsFs<D> {

    /// Performs the [`FileSystem::capabilities`] operation.
    pub fn capabilities(&self) -> Capabilities {
        let case = if self.volume.is_case_insensitive() { CaseRule::InsensitivePreserving } else { CaseRule::Sensitive };
        let max_name = match self.volume.directory_key_layout() {
            filesystem::DirectoryKeyLayout::Hashed => 0x3ff - 1,
            filesystem::DirectoryKeyLayout::Plain => u16::MAX as usize - 1,
        };
        let mut capabilities = Capabilities::new(case, Charset::Unicode, max_name)
            .with_symlinks().with_hard_links().with_timestamp_resolution_ns(1);
        for field in [Field::Created, Field::Modified, Field::Changed, Field::Accessed, Field::Permissions, Field::Owner] {
            capabilities = capabilities.with_stored(field, Stored::Yes);
        }
        #[cfg(feature = "write")]
        if self.writable {
            capabilities = capabilities.with_writable();
        }
        capabilities
    }

    /// Performs the [`FileSystem::root`] operation.
    pub fn root(&self) -> NodeId {
        NodeId::new(crate::types::filesystem::INODE_ROOT_DIRECTORY).unwrap()
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all))]
    /// Performs the [`FileSystem::statfs`] operation.
    pub async fn statfs(&mut self) -> FsResult<FsStats, D::Error> {
        let summary = self.container.space_manager_summary(&self.checkpoint).await?;
        if summary.main_device.free_count > summary.main_device.block_count {
            return Err(Error::new(ErrorKind::Corrupt, "APFS free count exceeds container"));
        }
        if summary.tier2_device.is_some() {
            return Err(Error::new(ErrorKind::Unsupported, "APFS Fusion containers"));
        }
        let files = self.volume.number_files.checked_add(self.volume.number_directories)
            .and_then(|count| count.checked_add(self.volume.number_symlinks)).ok_or(ErrorKind::Corrupt)?;
        Ok(FsStats::new(summary.main_device.block_count, summary.main_device.free_count, self.checkpoint.block_size)
            .with_file_count(files))
    }

    /// Performs the [`FileSystem::label`] operation.
    pub async fn label<'b>(&mut self, buf: &'b mut [u8]) -> FsResult<Option<&'b str>, D::Error> {
        let name = self.volume.name()?;
        if name.is_empty() { return Ok(None); }
        let target = buf.get_mut(..name.len()).ok_or(ErrorKind::LimitExceeded)?;
        target.copy_from_slice(name.as_bytes());
        Ok(Some(core::str::from_utf8(target).map_err(|_| ErrorKind::Corrupt)?))
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(dir = ?dir)))]
    /// Performs the [`FileSystem::lookup`] operation.
    pub async fn lookup(&mut self, dir: NodeId, name: &Name) -> FsResult<NodeId, D::Error> {
        let (file_id, flags) = self.find_entry(dir, name).await?.ok_or(ErrorKind::NotFound)?;
        let node = NodeId::new(file_id).ok_or(ErrorKind::Corrupt)?;
        // Reading the node records the damage its entry implies, so that a
        // later `stat` fails for it without reading the directory again.
        match self.inode(node).await {
            Ok(inode) => {
                if let Some(reason) = entry_damage(dir.get(), flags, &inode) {
                    self.nodes.record(file_id, reason);
                }
            }
            Err(error) if error.kind() == ErrorKind::InvalidHandle => {
                self.nodes.record(file_id, "APFS directory entry inode missing");
            }
            Err(error) if is_resource(error.kind()) => return Err(error),
            Err(_) => {}
        }
        #[cfg(feature = "write")]
        self.pin(node)?;
        Ok(node)
    }

    /// Performs the [`FileSystem::forget`] operation. The node's records are
    /// dropped, so they stop counting against
    /// [`MountOptions::with_node_limit`].
    pub fn forget(&mut self, node: NodeId, count: u64) {
        if node == self.root() {
            return;
        }
        #[cfg(feature = "write")]
        {
            if let Some(state) = self.uses.get_mut(&node.get()) {
                state.pins = state.pins.saturating_sub(count);
                if state.pins != 0 || state.opens != 0 {
                    return;
                }
            }
            self.uses.remove(&node.get());
        }
        let _ = count;
        self.nodes.release(node.get());
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(dir = ?dir)))]
    /// Performs the [`FileSystem::parent`] operation.
    pub async fn parent(&mut self, dir: NodeId) -> FsResult<NodeId, D::Error> {
        let inode = self.directory(dir).await?;
        if dir == self.root() { return Ok(dir); }
        let parent = NodeId::new(inode.parent_id).ok_or(ErrorKind::Corrupt)?;
        self.directory(parent).await?;
        #[cfg(feature = "write")]
        self.pin(parent)?;
        Ok(parent)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(node = ?node)))]
    /// Performs the [`FileSystem::stat`] operation.
    pub async fn stat(&mut self, node: NodeId) -> FsResult<Metadata, D::Error> {
        let inode = self.inode(node).await?;
        self.metadata(&inode, true).await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(dir = ?dir)))]
    /// Performs the [`FileSystem::readdir`] operation.
    pub async fn readdir(&mut self, dir: NodeId, from: DirCursor) -> FsResult<Option<DirEntry>, D::Error> {
        self.directory(dir).await?;
        if from.into_raw() > DirCursor::MAX_RAW { return Err(ErrorKind::InvalidInput.into()); }
        let index = usize::try_from(from.into_raw()).map_err(|_| ErrorKind::InvalidInput)?;
        let found = {
            let entries = self.directory_entries(dir.get()).await?;
            entries.get(index).map(|entry| (entry.file_id, entry.flags, entry.name.clone()))
        };
        let Some((file_id, flags, name)) = found else {
            return Ok(None);
        };
        let next = from.into_raw().checked_add(1).filter(|value| *value <= DirCursor::MAX_RAW)
            .ok_or(ErrorKind::LimitExceeded)?;
        let node = NodeId::new(file_id).ok_or(ErrorKind::Corrupt)?;
        let metadata = self.listed_metadata(dir.get(), file_id, flags).await;
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) if is_resource(error.kind()) => return Err(error),
            Err(_) => damaged(flags),
        };
        DirEntry::new(Name::new(&name), node, metadata, DirCursor::from_raw(next))
            .map(Some)
            .map_err(|error| match error {
                NameError::TooLong => ErrorKind::NameTooLong.into(),
                error => error.into(),
            })
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(node = ?node, bytes = buf.len())))]
    /// Performs the [`FileSystem::readlink`] operation.
    pub async fn readlink<'b>(&mut self, node: NodeId, buf: &'b mut [u8]) -> FsResult<&'b [u8], D::Error> {
        let inode = self.inode(node).await?;
        if !file_type::<D::Error>(&inode)?.is_symlink() { return Err(ErrorKind::InvalidInput.into()); }
        self.load_symlink(node.get()).await?;
        let target = self.nodes.target::<D::Error>(node.get())?;
        let output = buf.get_mut(..target.len()).ok_or(ErrorKind::LimitExceeded)?;
        output.copy_from_slice(target);
        Ok(output)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(node = ?node)))]
    /// Performs the [`FileSystem::open`] operation.
    pub async fn open(&mut self, node: NodeId, mode: OpenMode) -> FsResult<(), D::Error> {
        let inode = self.inode(node).await?;
        match file_type::<D::Error>(&inode)? {
            FileType::Dir => return Err(ErrorKind::IsADirectory.into()),
            FileType::Symlink => return Err(ErrorKind::Symlink.into()),
            FileType::File => {},
            _ => return Err(ErrorKind::Unsupported.into()),
        }
        if mode == OpenMode::Write {
            #[cfg(feature = "write")]
            self.require_writable()?;
            #[cfg(not(feature = "write"))]
            return Err(ErrorKind::ReadOnly.into());
        }
        if inode.is_compressed() { return Err(crate::ApfsError::Unsupported("compressed file data").into()); }
        #[cfg(feature = "write")]
        {
            let state = self.uses.entry(node.get()).or_default();
            state.opens = state.opens.checked_add(1).ok_or(ErrorKind::LimitExceeded)?;
        }
        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(node = ?node)))]
    /// Performs the [`FileSystem::close`] operation.
    pub async fn close(&mut self, node: NodeId) -> FsResult<(), D::Error> {
        #[cfg(feature = "write")]
        {
            if let Some(state) = self.uses.get_mut(&node.get()) {
                state.opens = state.opens.saturating_sub(1);
                if state.pins == 0 && state.opens == 0 {
                    self.uses.remove(&node.get());
                    self.nodes.release(node.get());
                }
            }
        }
        let _ = node;
        Ok(())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all, fields(node = ?node, offset = offset, bytes = buf.len())))]
    /// Performs the [`FileSystem::read`] operation.
    pub async fn read(&mut self, node: NodeId, offset: u64, buf: &mut [u8]) -> FsResult<usize, D::Error> {
        #[cfg(feature = "encryption")]
        self.container.check_unlocked_volume(&self.volume)?;
        let inode = self.inode(node).await?;
        match file_type::<D::Error>(&inode)? {
            FileType::Dir => return Err(ErrorKind::IsADirectory.into()),
            FileType::Symlink => return Err(ErrorKind::Symlink.into()),
            FileType::File => {},
            _ => return Err(ErrorKind::Unsupported.into()),
        }
        if inode.is_compressed() { return Err(crate::ApfsError::Unsupported("compressed file data").into()); }
        self.load_extents(&inode).await?;
        let extents = self.nodes.extents(inode.private_id);
        // `load_extents` checked these extents, so only the range is read.
        self.container
            .read_checked_extents_at(extents, stream_size(&inode, extents), offset, buf)
            .await
    }
}

impl<D: BlockDevice> ApfsFs<D> {
    async fn find_entry(&mut self, dir: NodeId, name: &Name) -> FsResult<Option<(u64, u16)>, D::Error> {
        name.check()?;
        self.directory(dir).await?;
        let comparison = self.volume.name_comparison();
        let entries = self.directory_entries(dir.get()).await?;
        Ok(entries.iter().find(|entry| entry.name == name.as_bytes()).or_else(|| {
            let wanted = name.to_str().ok()?;
            entries.iter().find(|entry| {
                core::str::from_utf8(&entry.name)
                    .is_ok_and(|stored| comparison.matches(stored, wanted))
            })
        }).map(|entry| (entry.file_id, entry.flags)))
    }

    #[cfg(feature = "write")]
    /// Flushes the device on a writable mount; read-only mounts have no changes.
    pub async fn sync(&mut self) -> FsResult<(), D::Error> {
        if self.writable {
            self.container.flush_write().await?;
        }
        Ok(())
    }
}

#[cfg(feature = "write")]
impl<D: BlockDevice> ApfsFs<D> {
    fn require_writable(&self) -> FsResult<(), D::Error> {
        if self.writable { Ok(()) } else { Err(ErrorKind::ReadOnly.into()) }
    }

    fn pin(&mut self, node: NodeId) -> FsResult<(), D::Error> {
        if node != self.root() {
            let state = self.uses.entry(node.get()).or_default();
            state.pins = state.pins.checked_add(1).ok_or(ErrorKind::LimitExceeded)?;
        }
        Ok(())
    }

    fn reserve_created_node(&self) -> FsResult<(), D::Error> {
        let Some(limit) = self.nodes.limit else {
            return Ok(());
        };
        let cached = |node: &u64| {
            self.nodes.inodes.contains_key(node) || self.nodes.damaged.contains_key(node)
        };
        let active = self.uses.iter()
            .filter(|(node, state)| (state.pins != 0 || state.opens != 0) && !cached(node))
            .count();
        let root = self.root().get();
        let root_missing = usize::from(!cached(&root));
        let held = self.nodes.inodes.len()
            .checked_add(self.nodes.damaged.len())
            .and_then(|count| count.checked_add(active))
            .and_then(|count| count.checked_add(root_missing))
            .ok_or(ErrorKind::LimitExceeded)?;
        if held >= limit {
            return Err(ErrorKind::LimitExceeded.into());
        }
        Ok(())
    }

    fn mutation_name(&self, name: &Name) -> FsResult<(), D::Error> {
        name.check()?;
        name.to_str().map_err(|_| ErrorKind::InvalidInput)?;
        if name.as_bytes().len() > self.capabilities().max_name_bytes() {
            return Err(ErrorKind::NameTooLong.into());
        }
        Ok(())
    }

    fn check_removal(&self, inode: &InodeRecord) -> FsResult<(), D::Error> {
        if inode.link_or_child_count <= 1
            && self.uses.get(&inode.id).is_some_and(|state| state.opens != 0)
        {
            return Err(ErrorKind::Busy.into());
        }
        Ok(())
    }

    fn removed(&mut self, node: u64) {
        if let Some(state) = self.uses.get_mut(&node) {
            if state.pins != 0 {
                state.removed = true;
            } else {
                self.uses.remove(&node);
            }
        }
    }

    async fn mutate(&mut self, operation: crate::write::WriteOperation<'_>) -> FsResult<Option<u64>, D::Error> {
        let result = self.container.mutate(&mut self.checkpoint, &mut self.volume, operation).await;
        self.nodes = Nodes::new(self.nodes.limit);
        result
    }

    async fn writable_file(&mut self, node: NodeId) -> FsResult<(), D::Error> {
        self.require_writable()?;
        let inode = self.inode(node).await?;
        match file_type::<D::Error>(&inode)? {
            FileType::File => {}
            FileType::Dir => return Err(ErrorKind::IsADirectory.into()),
            FileType::Symlink => return Err(ErrorKind::Symlink.into()),
            _ => return Err(ErrorKind::Unsupported.into()),
        }
        if inode.is_compressed() {
            return Err(crate::ApfsError::Unsupported("compressed file data").into());
        }
        Ok(())
    }

    /// Persists supported inode times, permissions and ownership.
    pub async fn setattr(&mut self, node: NodeId, changes: &SetAttr) -> FsResult<(), D::Error> {
        self.require_writable()?;
        self.inode(node).await?;
        self.mutate(crate::write::WriteOperation::SetAttr { node: node.get(), attrs: changes }).await?;
        Ok(())
    }

    /// Writes file data, zero-filling a gap and growing the file as needed.
    pub async fn write(&mut self, node: NodeId, offset: u64, buf: &[u8]) -> FsResult<usize, D::Error> {
        self.writable_file(node).await?;
        let len = u64::try_from(buf.len()).map_err(|_| ErrorKind::LimitExceeded)?;
        offset.checked_add(len).ok_or(ErrorKind::LimitExceeded)?;
        if buf.is_empty() {
            return Ok(0);
        }
        self.mutate(crate::write::WriteOperation::Write { node: node.get(), offset, data: buf }).await?;
        Ok(buf.len())
    }

    /// Truncates or zero-extends a file.
    pub async fn truncate(&mut self, node: NodeId, len: u64) -> FsResult<(), D::Error> {
        self.writable_file(node).await?;
        self.mutate(crate::write::WriteOperation::Truncate { node: node.get(), len }).await?;
        Ok(())
    }

    /// Flushes a node's already-published checkpoint and the device.
    pub async fn fsync(&mut self, node: NodeId) -> FsResult<(), D::Error> {
        self.inode(node).await?;
        self.sync().await
    }

    async fn create_node(&mut self, dir: NodeId, name: &Name, attrs: &SetAttr, directory: bool) -> FsResult<NodeId, D::Error> {
        self.require_writable()?;
        self.mutation_name(name)?;
        if self.find_entry(dir, name).await?.is_some() {
            return Err(ErrorKind::AlreadyExists.into());
        }
        self.reserve_created_node()?;
        let id = self.mutate(crate::write::WriteOperation::Create {
            parent: dir.get(), name: name.as_bytes(), directory, attrs,
        }).await?.ok_or(ErrorKind::Corrupt)?;
        let node = NodeId::new(id).ok_or(ErrorKind::Corrupt)?;
        self.pin(node)?;
        Ok(node)
    }

    /// Creates and pins an empty file.
    pub async fn create(&mut self, dir: NodeId, name: &Name, attrs: &SetAttr) -> FsResult<NodeId, D::Error> {
        self.create_node(dir, name, attrs, false).await
    }

    /// Creates and pins an empty directory.
    pub async fn mkdir(&mut self, dir: NodeId, name: &Name, attrs: &SetAttr) -> FsResult<NodeId, D::Error> {
        self.create_node(dir, name, attrs, true).await
    }

    async fn remove_node(&mut self, dir: NodeId, name: &Name, directory: bool) -> FsResult<(), D::Error> {
        self.require_writable()?;
        self.mutation_name(name)?;
        let (id, _) = self.find_entry(dir, name).await?.ok_or(ErrorKind::NotFound)?;
        let node = NodeId::new(id).ok_or(ErrorKind::Corrupt)?;
        let inode = self.inode(node).await?;
        let kind = file_type::<D::Error>(&inode)?;
        if directory {
            if !kind.is_dir() {
                return Err(ErrorKind::NotADirectory.into());
            }
            if !self.directory_entries(id).await?.is_empty() {
                return Err(ErrorKind::DirectoryNotEmpty.into());
            }
        } else if kind.is_dir() {
            return Err(ErrorKind::IsADirectory.into());
        }
        self.check_removal(&inode)?;
        self.mutate(crate::write::WriteOperation::Remove {
            parent: dir.get(), name: name.as_bytes(), directory,
        }).await?;
        if directory || inode.link_or_child_count <= 1 {
            self.removed(id);
        }
        Ok(())
    }

    /// Removes a non-directory entry, refusing the last name of an open file.
    pub async fn unlink(&mut self, dir: NodeId, name: &Name) -> FsResult<(), D::Error> {
        self.remove_node(dir, name, false).await
    }

    /// Removes an empty directory.
    pub async fn rmdir(&mut self, dir: NodeId, name: &Name) -> FsResult<(), D::Error> {
        self.remove_node(dir, name, true).await
    }

    /// Moves a node without changing its id, optionally replacing the target.
    pub async fn rename(
        &mut self,
        from_dir: NodeId,
        from: &Name,
        to_dir: NodeId,
        to: &Name,
        mode: RenameMode,
    ) -> FsResult<(), D::Error> {
        self.require_writable()?;
        self.mutation_name(from)?;
        self.mutation_name(to)?;
        let replace = match mode {
            RenameMode::Replace => true,
            RenameMode::NoReplace => false,
            _ => return Err(ErrorKind::Unsupported.into()),
        };
        let (source, _) = self.find_entry(from_dir, from).await?.ok_or(ErrorKind::NotFound)?;
        let source_node = NodeId::new(source).ok_or(ErrorKind::Corrupt)?;
        let inode = self.inode(source_node).await?;
        let source_is_dir = file_type::<D::Error>(&inode)?.is_dir();
        let target = self.find_entry(to_dir, to).await?;
        let mut removed = None;
        if let Some((target, _)) = target {
            if !replace {
                return Err(ErrorKind::AlreadyExists.into());
            }
            if target != source {
                let target_inode = self.inode(NodeId::new(target).ok_or(ErrorKind::Corrupt)?).await?;
                let target_is_dir = file_type::<D::Error>(&target_inode)?.is_dir();
                if source_is_dir && !target_is_dir {
                    return Err(ErrorKind::NotADirectory.into());
                }
                if !source_is_dir && target_is_dir {
                    return Err(ErrorKind::IsADirectory.into());
                }
                if target_is_dir && !self.directory_entries(target).await?.is_empty() {
                    return Err(ErrorKind::DirectoryNotEmpty.into());
                }
                self.check_removal(&target_inode)?;
                if target_is_dir || target_inode.link_or_child_count <= 1 {
                    removed = Some(target);
                }
            } else if from_dir != to_dir || from.as_bytes() == to.as_bytes() {
                return Ok(());
            }
        }
        if source_is_dir {
            let mut ancestor = to_dir;
            let mut remaining = self.volume.number_directories.checked_add(1).ok_or(ErrorKind::Corrupt)?;
            loop {
                if ancestor == source_node {
                    return Err(ErrorKind::InvalidInput.into());
                }
                if ancestor == self.root() {
                    break;
                }
                if remaining == 0 {
                    return Err(ErrorKind::Corrupt.into());
                }
                remaining -= 1;
                let parent = self.directory(ancestor).await?.parent_id;
                ancestor = NodeId::new(parent).ok_or(ErrorKind::Corrupt)?;
            }
        }
        self.mutate(crate::write::WriteOperation::Rename {
            from_parent: from_dir.get(), from: from.as_bytes(),
            to_parent: to_dir.get(), to: to.as_bytes(), replace,
        }).await?;
        if let Some(target) = removed {
            self.removed(target);
        }
        Ok(())
    }
}
#[cfg(not(feature = "write"))]
hadris_fs::__forward_filesystem! {
    async fn ApfsFs<D: BlockDevice> as FileSystem { read }
}
#[cfg(feature = "write")]
hadris_fs::__forward_filesystem! {
    async fn ApfsFs<D: BlockDevice> as FileSystem { read write }
}

send_filesystem! {
#[cfg(not(feature = "write"))]
hadris_fs::__forward_filesystem! {
    async fn ApfsFs<D: hadris_storage::async_::SendBlockDevice> as hadris_fs::async_::FileSystem { read }
}
#[cfg(feature = "write")]
hadris_fs::__forward_filesystem! {
    async fn ApfsFs<D: hadris_storage::async_::SendBlockDevice> as hadris_fs::async_::FileSystem { read write }
}
}

}
