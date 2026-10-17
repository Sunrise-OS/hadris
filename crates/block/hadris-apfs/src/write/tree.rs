//! The files a new container holds, and the filesystem records that encode them.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use hadris_fs::ErrorKind;

use super::{BLOCK, drec_key, entry, extent_ref, fs_cmp, key, set_xfield, w16, w32, w64};
use crate::types::OwnedEntry;
use crate::types::filesystem::{SYMLINK_XATTR_NAME, XATTR_DATA_EMBEDDED};

pub(crate) const ROOT_PARENT_ID: u64 = 1;
pub(crate) const ROOT_DIR_ID: u64 = 2;
pub(crate) const PRIVATE_DIR_ID: u64 = 3;
pub(crate) const FIRST_USER_ID: u64 = 16;

const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
const DT_LNK: u16 = 10;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const INODE_IS_APFS_PRIVATE: u64 = 1;
const INO_EXT_TYPE_NAME: u8 = 4;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const XF_DO_NOT_COPY: u8 = 2;
const XF_SYSTEM_FIELD: u8 = 0x20;
const MAX_NAME: usize = 255;
const MAX_SYMLINK: usize = 1024;

/// A directory, regular file or symbolic link of a container being formatted.
///
/// Build a tree with [`ApfsNode::directory`], [`ApfsNode::file`] and
/// [`ApfsNode::symlink`], join nodes with [`ApfsNode::add`], and hand the
/// root to `ApfsOptions::with_root`. A file's bytes are held in memory until
/// the format has written them.
#[derive(Debug, Clone)]
pub struct ApfsNode {
    pub(crate) kind: Kind,
    pub(crate) mode: u16,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[derive(Debug, Clone)]
pub(crate) enum Kind {
    Directory(Vec<(String, ApfsNode)>),
    File(Vec<u8>),
    Symlink(String),
}

impl ApfsNode {
    fn new(kind: Kind, mode: u16) -> Self {
        Self {
            kind,
            mode,
            uid: 0,
            gid: 0,
        }
    }

    /// An empty directory with mode `0o755`, owned by user and group 0.
    pub fn directory() -> Self {
        Self::new(Kind::Directory(Vec::new()), 0o755)
    }

    /// A regular file holding `data`, with mode `0o644`. An empty file has no
    /// data blocks.
    pub fn file(data: impl Into<Vec<u8>>) -> Self {
        Self::new(Kind::File(data.into()), 0o644)
    }

    /// A symbolic link to `target`, with mode `0o755`. The target must be 1
    /// to 1024 bytes of UTF-8 without a NUL; the format rejects any other.
    pub fn symlink(target: &str) -> Self {
        Self::new(Kind::Symlink(String::from(target)), 0o755)
    }

    /// Sets the permission bits, of which only the low twelve are kept.
    pub const fn with_mode(mut self, mode: u16) -> Self {
        self.mode = mode & 0o7777;
        self
    }

    /// Sets the owning user and group.
    pub const fn with_owner(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Adds `node` to this directory under `name`.
    ///
    /// Fails with `NotADirectory` when this node is not a directory, with
    /// `InvalidInput` for a name that is empty, `.`, `..` or contains `/` or
    /// NUL, with `NameTooLong` for more than 255 bytes, and with
    /// `AlreadyExists` when the directory already holds that exact name.
    /// Names that differ only in Unicode normalization are rejected when the
    /// container is formatted, if its volume compares names that way.
    pub fn add(&mut self, name: &str, node: ApfsNode) -> Result<(), ErrorKind> {
        let Kind::Directory(children) = &mut self.kind else {
            return Err(ErrorKind::NotADirectory);
        };
        if name.is_empty() || name == "." || name == ".." || name.contains(['\0', '/']) {
            return Err(ErrorKind::InvalidInput);
        }
        if name.len() > MAX_NAME {
            return Err(ErrorKind::NameTooLong);
        }
        if children.iter().any(|(existing, _)| existing == name) {
            return Err(ErrorKind::AlreadyExists);
        }
        children.push((String::from(name), node));
        Ok(())
    }

    /// Adds `node` under `name` and returns this directory, for chaining.
    /// Fails like [`ApfsNode::add`].
    pub fn with_child(mut self, name: &str, node: ApfsNode) -> Result<Self, ErrorKind> {
        self.add(name, node)?;
        Ok(self)
    }
}

/// One inode of the flattened tree.
pub(crate) struct Flat<'a> {
    pub id: u64,
    pub parent: u64,
    pub name: &'a str,
    pub node: &'a ApfsNode,
    pub children: Vec<usize>,
    /// First data block of a nonempty file, set once the layout is known.
    pub data_block: u64,
}

impl Flat<'_> {
    /// The file's data length in bytes, or 0 for anything but a regular file.
    pub fn size(&self) -> u64 {
        match &self.node.kind {
            Kind::File(data) => data.len() as u64,
            _ => 0,
        }
    }

    pub fn data_blocks(&self) -> u64 {
        self.size().div_ceil(BLOCK as u64)
    }
}

/// Numbers the tree's inodes depth first, starting at the root.
///
/// Fails with `InvalidInput` when the root is not a directory or a symlink
/// target is unusable, and with `AlreadyExists` when a directory holds two
/// names the volume would compare equal.
pub(crate) fn flatten(root: &ApfsNode, hashed: bool) -> Result<Vec<Flat<'_>>, ErrorKind> {
    if !matches!(root.kind, Kind::Directory(_)) {
        return Err(ErrorKind::InvalidInput);
    }
    let mut out = Vec::new();
    let mut next = FIRST_USER_ID;
    walk(
        root,
        "root",
        ROOT_DIR_ID,
        ROOT_PARENT_ID,
        hashed,
        &mut next,
        &mut out,
    )?;
    Ok(out)
}

fn fold(name: &str, hashed: bool) -> String {
    if hashed {
        icu_normalizer::DecomposingNormalizerBorrowed::new_nfd()
            .normalize(name)
            .into_owned()
    } else {
        String::from(name)
    }
}

fn walk<'a>(
    node: &'a ApfsNode,
    name: &'a str,
    id: u64,
    parent: u64,
    hashed: bool,
    next: &mut u64,
    out: &mut Vec<Flat<'a>>,
) -> Result<(), ErrorKind> {
    let index = out.len();
    out.push(Flat {
        id,
        parent,
        name,
        node,
        children: Vec::new(),
        data_block: 0,
    });
    match &node.kind {
        Kind::Directory(children) => {
            let mut seen = BTreeSet::new();
            for (child_name, child) in children {
                if !seen.insert(fold(child_name, hashed)) {
                    return Err(ErrorKind::AlreadyExists);
                }
                let child_id = *next;
                *next = child_id
                    .checked_add(1)
                    .filter(|id| *id < 1 << 60)
                    .ok_or(ErrorKind::LimitExceeded)?;
                let child_index = out.len();
                out[index].children.push(child_index);
                walk(child, child_name, child_id, id, hashed, next, out)?;
            }
        }
        Kind::Symlink(target) => {
            if target.is_empty() || target.len() > MAX_SYMLINK || target.contains('\0') {
                return Err(ErrorKind::InvalidInput);
            }
        }
        Kind::File(_) => {}
    }
    Ok(())
}

struct Inode<'a> {
    parent: u64,
    id: u64,
    flags: u64,
    nlink: u32,
    mode: u16,
    uid: u32,
    gid: u32,
    time: u64,
    name: Option<&'a str>,
    stream: Option<(u64, u64)>,
}

fn inode_value(inode: &Inode<'_>) -> Vec<u8> {
    let mut value = vec![0; 92];
    w64(&mut value, 0, inode.parent);
    w64(&mut value, 8, inode.id);
    for at in [16, 24, 32, 40] {
        w64(&mut value, at, inode.time);
    }
    w64(&mut value, 48, inode.flags);
    w32(&mut value, 56, inode.nlink);
    w32(&mut value, 72, inode.uid);
    w32(&mut value, 76, inode.gid);
    w16(&mut value, 80, inode.mode);
    if let Some(name) = inode.name {
        let mut data = name.as_bytes().to_vec();
        data.push(0);
        set_xfield::<Infallible>(&mut value, INO_EXT_TYPE_NAME, XF_DO_NOT_COPY, Some(data))
            .unwrap_or_else(|_| unreachable!("a short name fits the inode"));
    }
    if let Some((size, allocated)) = inode.stream {
        let mut data = vec![0; 40];
        w64(&mut data, 0, size);
        w64(&mut data, 8, allocated);
        w64(&mut data, 24, size);
        set_xfield::<Infallible>(
            &mut value,
            INO_EXT_TYPE_DSTREAM,
            XF_SYSTEM_FIELD,
            Some(data),
        )
        .unwrap_or_else(|_| unreachable!("a data stream fits the inode"));
    }
    value
}

fn directory_record(
    parent: u64,
    name: &str,
    id: u64,
    kind: u16,
    time: u64,
    hashed: bool,
) -> OwnedEntry {
    let mut value = vec![0; 18];
    w64(&mut value, 0, id);
    w64(&mut value, 8, time);
    w16(&mut value, 16, kind);
    entry(drec_key(parent, name, hashed), value)
}

/// The records of a flattened tree, with how many of each inode kind it has.
pub(crate) struct Built {
    /// Filesystem-tree records in key order.
    pub fs: Vec<OwnedEntry>,
    /// Extent-reference tree records in key order.
    pub refs: Vec<OwnedEntry>,
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub next_id: u64,
}

/// Encodes every inode, directory entry, extent and symlink target, plus the
/// private directory APFS keeps beside the root, stamped with `time`.
pub(crate) fn records(flat: &[Flat<'_>], time: u64, hashed: bool) -> Built {
    let next_id = FIRST_USER_ID + flat.len() as u64 - 1;
    let mut fs = vec![
        directory_record(ROOT_PARENT_ID, "root", ROOT_DIR_ID, DT_DIR, time, hashed),
        directory_record(
            ROOT_PARENT_ID,
            "private-dir",
            PRIVATE_DIR_ID,
            DT_DIR,
            time,
            hashed,
        ),
        entry(
            key(PRIVATE_DIR_ID, 3),
            inode_value(&Inode {
                parent: ROOT_PARENT_ID,
                id: PRIVATE_DIR_ID,
                flags: INODE_IS_APFS_PRIVATE,
                nlink: 0,
                mode: S_IFDIR | 0o755,
                uid: 0,
                gid: 0,
                time,
                name: Some("private-dir"),
                stream: None,
            }),
        ),
    ];
    let mut refs = Vec::new();
    let (mut files, mut directories, mut symlinks) = (0, 0, 0);
    for inode in flat {
        let node = inode.node;
        let mut spec = Inode {
            parent: inode.parent,
            id: inode.id,
            flags: 0,
            nlink: 1,
            mode: node.mode,
            uid: node.uid,
            gid: node.gid,
            time,
            name: None,
            stream: None,
        };
        let kind = match &node.kind {
            Kind::Directory(_) => {
                if inode.id != ROOT_DIR_ID {
                    directories += 1;
                } else {
                    spec.name = Some("root");
                }
                spec.mode |= S_IFDIR;
                spec.nlink = inode.children.len() as u32;
                DT_DIR
            }
            Kind::File(data) => {
                files += 1;
                spec.mode |= S_IFREG;
                if !data.is_empty() {
                    let allocated = inode.data_blocks() * BLOCK as u64;
                    spec.stream = Some((data.len() as u64, allocated));
                    fs.push(entry(key(inode.id, 6), 1u32.to_le_bytes().to_vec()));
                    let mut extent_key = key(inode.id, 8);
                    extent_key.extend_from_slice(&0u64.to_le_bytes());
                    let mut extent = vec![0; 24];
                    w64(&mut extent, 0, allocated);
                    w64(&mut extent, 8, inode.data_block);
                    fs.push(entry(extent_key, extent));
                    refs.push(extent_ref(inode.data_block, inode.data_blocks(), inode.id));
                }
                DT_REG
            }
            Kind::Symlink(target) => {
                symlinks += 1;
                spec.mode |= S_IFLNK;
                let mut attribute_key = key(inode.id, 4);
                attribute_key
                    .extend_from_slice(&(SYMLINK_XATTR_NAME.len() as u16 + 1).to_le_bytes());
                attribute_key.extend_from_slice(SYMLINK_XATTR_NAME.as_bytes());
                attribute_key.push(0);
                let mut attribute = XATTR_DATA_EMBEDDED.to_le_bytes().to_vec();
                attribute.extend_from_slice(&(target.len() as u16 + 1).to_le_bytes());
                attribute.extend_from_slice(target.as_bytes());
                attribute.push(0);
                fs.push(entry(attribute_key, attribute));
                DT_LNK
            }
        };
        fs.push(entry(key(inode.id, 3), inode_value(&spec)));
        if inode.id != ROOT_DIR_ID {
            fs.push(directory_record(
                inode.parent,
                inode.name,
                inode.id,
                kind,
                time,
                hashed,
            ));
        }
    }
    fs.sort_by(|a, b| fs_cmp(&a.key, &b.key, hashed));
    refs.sort_by_key(|e| {
        u64::from_le_bytes(e.key[..8].try_into().expect("eight-byte key")) & 0x0fff_ffff_ffff_ffff
    });
    Built {
        fs,
        refs,
        files,
        directories,
        symlinks,
        next_id,
    }
}

/// The data of every nonempty file in the order `flatten` numbers them.
pub(crate) fn file_data<'a>(node: &'a ApfsNode, out: &mut Vec<&'a [u8]>) {
    match &node.kind {
        Kind::Directory(children) => {
            for (_, child) in children {
                file_data(child, out);
            }
        }
        Kind::File(data) if !data.is_empty() => out.push(data),
        Kind::File(_) | Kind::Symlink(_) => {}
    }
}
