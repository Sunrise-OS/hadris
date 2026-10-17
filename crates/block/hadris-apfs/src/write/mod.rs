use crate::types::filesystem::{
    DirectoryEntryRecord, FS_TYPE_DIRECTORY_RECORD, FS_TYPE_FILE_EXTENT, FS_TYPE_INODE,
};
use crate::types::{FileExtentRecord, FileSystemKey, InodeRecord, OwnedEntry, VolumeSuperblock};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::cmp::Ordering;
use hadris_fs::{Error, ErrorKind, FsResult, SetAttr};

pub(crate) mod btree;
pub(crate) mod mkfs;
pub(crate) mod tree;
pub(crate) const BLOCK: usize = 4096;

pub(crate) enum WriteOperation<'a> {
    Write {
        node: u64,
        offset: u64,
        data: &'a [u8],
    },
    Truncate {
        node: u64,
        len: u64,
    },
    Create {
        parent: u64,
        name: &'a [u8],
        directory: bool,
        attrs: &'a SetAttr,
    },
    Remove {
        parent: u64,
        name: &'a [u8],
        directory: bool,
    },
    Rename {
        from_parent: u64,
        from: &'a [u8],
        to_parent: u64,
        to: &'a [u8],
        replace: bool,
    },
    SetAttr {
        node: u64,
        attrs: &'a SetAttr,
    },
}

pub(crate) fn w16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn w32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn w64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn seal(b: &mut [u8]) {
    let sum = crate::types::checksum::fletcher64(b).expect("whole APFS object block");
    w64(b, 0, sum);
}
pub(crate) fn object(oid: u64, xid: u64, kind: u32, subtype: u32) -> Vec<u8> {
    let mut b = vec![0; BLOCK];
    w64(&mut b, 8, oid);
    w64(&mut b, 16, xid);
    w32(&mut b, 24, kind);
    w32(&mut b, 28, subtype);
    b
}
pub(crate) fn key(id: u64, kind: u8) -> Vec<u8> {
    (id | (u64::from(kind) << 60)).to_le_bytes().to_vec()
}
pub(crate) fn entry(key: Vec<u8>, value: Vec<u8>) -> OwnedEntry {
    OwnedEntry { key, value }
}
pub(crate) fn omap_entry(oid: u64, block: u64, xid: u64) -> OwnedEntry {
    let mut k = oid.to_le_bytes().to_vec();
    k.extend_from_slice(&xid.to_le_bytes());
    let mut v = vec![0; 16];
    w32(&mut v, 4, BLOCK as u32);
    w64(&mut v, 8, block);
    entry(k, v)
}
pub(crate) fn extent_ref(block: u64, count: u64, owner: u64) -> OwnedEntry {
    let mut v = vec![0; 20];
    w64(&mut v, 0, count | (1 << 60));
    w64(&mut v, 8, owner);
    w32(&mut v, 16, 1);
    entry(key(block, 1), v)
}
pub(crate) fn omap(block: u64, root: u64, xid: u64, flags: u32) -> Vec<u8> {
    let mut b = object(block, xid, 0x4000_000b, 0);
    w32(&mut b, 32, flags);
    w32(&mut b, 40, 0x4000_0002);
    w32(&mut b, 44, 0x4000_0002);
    w64(&mut b, 48, root);
    seal(&mut b);
    b
}
fn raw64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("validated key"))
}

pub(crate) fn fs_cmp(a: &[u8], b: &[u8], hashed: bool) -> Ordering {
    let ha = raw64(a, 0);
    let hb = raw64(b, 0);
    (ha & 0x0fff_ffff_ffff_ffff)
        .cmp(&(hb & 0x0fff_ffff_ffff_ffff))
        .then((ha >> 60).cmp(&(hb >> 60)))
        .then_with(|| match ha >> 60 {
            8 => raw64(a, 8).cmp(&raw64(b, 8)),
            9 if hashed => {
                let h = |k: &[u8]| {
                    u32::from_le_bytes(k[8..12].try_into().expect("validated directory key")) >> 10
                };
                h(a).cmp(&h(b)).then_with(|| a[12..].cmp(&b[12..]))
            }
            9 | 4 => a[10..].cmp(&b[10..]),
            _ => Ordering::Equal,
        })
}

fn name<E>(bytes: &[u8]) -> FsResult<&str, E> {
    let text = core::str::from_utf8(bytes).map_err(|_| ErrorKind::InvalidInput)?;
    if text.is_empty() || text == "." || text == ".." || text.contains(['\0', '/']) {
        return Err(ErrorKind::InvalidInput.into());
    }
    if text.len() > 255 {
        return Err(ErrorKind::NameTooLong.into());
    }
    Ok(text)
}
fn name_hash(text: &str) -> u32 {
    let normal = icu_normalizer::DecomposingNormalizerBorrowed::new_nfd().normalize(text);
    let mut crc = u32::MAX;
    for c in normal.chars() {
        for byte in u32::from(c).to_le_bytes() {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
            }
        }
    }
    crc & 0x3f_ffff
}
pub(crate) fn drec_key(parent: u64, text: &str, hashed: bool) -> Vec<u8> {
    let mut k = key(parent, 9);
    if hashed {
        k.extend_from_slice(&((name_hash(text) << 10) | (text.len() as u32 + 1)).to_le_bytes());
    } else {
        k.extend_from_slice(&(text.len() as u16 + 1).to_le_bytes());
    }
    k.extend_from_slice(text.as_bytes());
    k.push(0);
    k
}
pub(crate) fn timestamp<E>(t: hadris_fs::DateTime) -> FsResult<u64, E> {
    u64::try_from(t.unix_seconds())
        .ok()
        .and_then(|v| v.checked_mul(1_000_000_000))
        .and_then(|v| v.checked_add(u64::from(t.nanoseconds())))
        .ok_or_else(|| ErrorKind::LimitExceeded.into())
}
fn attrs<E>(v: &mut [u8], a: &SetAttr, creating: bool) -> FsResult<(), E> {
    if !creating && a.attributes().is_some_and(|v| !v.is_empty()) {
        return Err(ErrorKind::Unsupported.into());
    }
    if let Some(p) = a.permissions() {
        let ty = u16::from_le_bytes([v[80], v[81]]) & 0o170000;
        w16(v, 80, ty | p.bits() as u16);
    }
    if let Some(o) = a.owner() {
        w32(v, 72, o.uid());
        w32(v, 76, o.gid());
    }
    if let Some(t) = a.created() {
        w64(v, 16, timestamp::<E>(t)?);
    }
    if let Some(t) = a.modified() {
        w64(v, 24, timestamp::<E>(t)?);
    }
    if let Some(t) = a.accessed() {
        w64(v, 40, timestamp::<E>(t)?);
    }
    Ok(())
}

pub(crate) struct Records {
    pub entries: Vec<OwnedEntry>,
    pub next_id: u64,
    pub hashed: bool,
}
impl Records {
    pub fn validate<E>(
        &self,
        volume: &VolumeSuperblock,
        blocks: u64,
    ) -> FsResult<Vec<FileExtentRecord>, E> {
        let mut inodes = BTreeMap::new();
        let mut dirs = Vec::new();
        let mut extents = Vec::new();
        let mut streams = BTreeSet::new();
        let mut names: BTreeMap<(u64, u32), Vec<&str>> = BTreeMap::new();
        let mut children: BTreeMap<u64, usize> = BTreeMap::new();
        let mut plain_names = BTreeSet::new();
        let mut xattrs = BTreeSet::new();
        for e in &self.entries {
            let k = FileSystemKey::parse(&e.key)?;
            match k.record_type {
                FS_TYPE_INODE => {
                    let i = InodeRecord::parse(&e.key, &e.value)?;
                    if i.bsd_flags != 0 || i.uncompressed_size != 0 {
                        return Err(unsupported("APFS write BSD inode flags or compressed size"));
                    }
                    if e.key.len() != 8
                        || i.private_id != i.id
                        || i.is_compressed()
                        || !matches!(i.mode & 0o170000, 0o040000 | 0o100000 | 0o120000)
                        || (i.mode & 0o170000 != 0o040000 && i.link_or_child_count != 1)
                        || raw64(&e.value, 48) & !u64::from(i.id == 3) != 0
                    {
                        return Err(unsupported(
                            "APFS write inode flags, clones, links or file type",
                        ));
                    }
                    validate_xfields(&e.value)?;
                    if inodes.insert(i.id, i).is_some() {
                        return Err(ErrorKind::Corrupt.into());
                    }
                }
                4 => {
                    let x = crate::types::XattrRecord::parse(&e.key, &e.value)?;
                    if x.name != crate::types::filesystem::SYMLINK_XATTR_NAME
                        || x.flags != crate::types::filesystem::XATTR_DATA_EMBEDDED
                    {
                        return Err(unsupported("APFS write extended attributes"));
                    }
                    if !xattrs.insert(k.id) {
                        return Err(ErrorKind::Corrupt.into());
                    }
                }
                6 => {
                    if e.key.len() != 8
                        || e.value.len() != 4
                        || crate::types::le_u32(&e.value, 0)? != 1
                        || !streams.insert(k.id)
                    {
                        return Err(unsupported("APFS shared data streams"));
                    }
                }
                FS_TYPE_FILE_EXTENT => {
                    let x = FileExtentRecord::parse(&e.key, &e.value)?;
                    if e.key.len() != 16
                        || e.value.len() != 24
                        || x.flags != 0
                        || x.cryptography_id != 0
                        || x.length == 0
                        || x.length % BLOCK as u64 != 0
                        || x.logical_address % BLOCK as u64 != 0
                        || x.physical_block == 0
                        || x.physical_block
                            .checked_add(x.length / BLOCK as u64)
                            .is_none_or(|end| end > blocks)
                    {
                        return Err(unsupported(
                            "APFS write encrypted, sparse or malformed extents",
                        ));
                    }
                    extents.push(x);
                }
                FS_TYPE_DIRECTORY_RECORD => {
                    let d = DirectoryEntryRecord::parse(
                        &e.key,
                        &e.value,
                        volume.directory_key_layout(),
                    )?;
                    if d.flags & !0xf != 0 {
                        return Err(unsupported("APFS directory record flags"));
                    }
                    let text = name::<E>(d.name)?;
                    let prefix = if self.hashed { 12 } else { 10 };
                    let hash = if self.hashed { name_hash(text) } else { 0 };
                    if e.key.len() != prefix + text.len() + 1
                        || e.key.last() != Some(&0)
                        || (self.hashed
                            && crate::types::le_u32(&e.key, 8)?
                                != ((hash << 10) | (text.len() as u32 + 1)))
                    {
                        return Err(ErrorKind::Corrupt.into());
                    }
                    if self.hashed {
                        let collision = names.entry((d.parent_id, hash)).or_default();
                        if collision
                            .iter()
                            .any(|other| volume.name_comparison().matches(other, text))
                        {
                            return Err(ErrorKind::Corrupt.into());
                        }
                        collision.push(text);
                    } else if !plain_names.insert((d.parent_id, text)) {
                        return Err(ErrorKind::Corrupt.into());
                    }
                    *children.entry(d.parent_id).or_default() += 1;
                    if e.value.len() != 18 {
                        return Err(unsupported("APFS directory extended fields"));
                    }
                    dirs.push((d.parent_id, d.file_id, d.flags));
                }
                _ => return Err(unsupported("APFS filesystem record type for writes")),
            }
        }
        if self.next_id >= 1 << 60
            || inodes
                .get(&2)
                .is_none_or(|i| i.mode & 0o170000 != 0o040000 || i.parent_id != 1)
            || inodes
                .get(&3)
                .is_some_and(|i| i.mode & 0o170000 != 0o040000 || i.parent_id != 1)
            || xattrs
                .iter()
                .any(|id| inodes.get(id).is_none_or(|i| i.mode & 0o170000 != 0o120000))
            || inodes
                .values()
                .any(|i| i.mode & 0o170000 == 0o120000 && !xattrs.contains(&i.id))
        {
            return Err(ErrorKind::Corrupt.into());
        }
        for pair in self.entries.windows(2) {
            if fs_cmp(&pair[0].key, &pair[1].key, self.hashed) != Ordering::Less {
                return Err(ErrorKind::Corrupt.into());
            }
        }
        let mut linked = BTreeSet::new();
        for &(parent, id, flags) in &dirs {
            let child = inodes
                .get(&id)
                .ok_or_else(|| Error::from(ErrorKind::Corrupt))?;
            if !linked.insert(id)
                || child.parent_id != parent
                || (parent == 1 && !matches!(id, 2 | 3))
                || (parent != 1
                    && inodes
                        .get(&parent)
                        .is_none_or(|i| i.mode & 0o170000 != 0o040000))
                || flags & 0xf
                    != match child.mode & 0o170000 {
                        0o040000 => 4,
                        0o100000 => 8,
                        _ => 10,
                    }
            {
                return Err(unsupported("APFS hard links or inconsistent directories"));
            }
        }
        let mut physical = Vec::new();
        for i in inodes.values() {
            if !linked.contains(&i.id) || i.id >= self.next_id {
                return Err(ErrorKind::Corrupt.into());
            }
            let mut ancestors = BTreeSet::new();
            let mut parent = i.parent_id;
            while parent != 1 {
                if !ancestors.insert(parent) {
                    return Err(ErrorKind::Corrupt.into());
                }
                parent = inodes
                    .get(&parent)
                    .ok_or_else(|| Error::from(ErrorKind::Corrupt))?
                    .parent_id;
            }
            if i.mode & 0o170000 == 0o040000 {
                if usize::try_from(i.link_or_child_count).ok()
                    != Some(children.get(&i.id).copied().unwrap_or(0))
                {
                    return Err(ErrorKind::Corrupt.into());
                }
            }
            let first = extents.partition_point(|e| e.id < i.id);
            let end = extents.partition_point(|e| e.id <= i.id);
            let owned = &extents[first..end];
            let mut logical = 0u64;
            for x in owned {
                if x.logical_address != logical {
                    return Err(unsupported("APFS sparse files"));
                }
                logical = logical
                    .checked_add(x.length)
                    .ok_or(crate::ApfsError::AddressOverflow)?;
                physical.push((x.physical_block, x.physical_block + x.length / BLOCK as u64));
            }
            let size = i.data_stream_size.unwrap_or(0);
            if i.mode & 0o170000 == 0o100000 {
                if size
                    .checked_add(BLOCK as u64 - 1)
                    .map(|s| s / BLOCK as u64 * BLOCK as u64)
                    != Some(logical)
                    || (size > 0) != streams.contains(&i.id)
                {
                    return Err(unsupported("APFS file stream layout"));
                }
            } else if !owned.is_empty() || streams.contains(&i.id) {
                return Err(unsupported("APFS nonregular file streams"));
            }
        }
        if extents.iter().any(|x| !inodes.contains_key(&x.id))
            || streams.iter().any(|id| !inodes.contains_key(id))
        {
            return Err(ErrorKind::Corrupt.into());
        }
        physical.sort_unstable();
        if physical.windows(2).any(|p| p[0].1 > p[1].0) {
            return Err(unsupported("APFS cloned extents"));
        }
        Ok(extents)
    }
    pub fn inode_index<E>(&self, id: u64) -> FsResult<usize, E> {
        self.entries
            .iter()
            .position(|e| e.key == key(id, 3))
            .ok_or_else(|| ErrorKind::NotFound.into())
    }
    pub fn inode<E>(&self, id: u64) -> FsResult<InodeRecord, E> {
        let e = &self.entries[self.inode_index::<E>(id)?];
        Ok(InodeRecord::parse(&e.key, &e.value)?)
    }
    fn directory<E>(&self, id: u64) -> FsResult<(), E> {
        if self.inode::<E>(id)?.mode & 0o170000 != 0o040000 {
            Err(ErrorKind::NotADirectory.into())
        } else {
            Ok(())
        }
    }
    fn find<E>(&self, v: &VolumeSuperblock, parent: u64, n: &[u8]) -> FsResult<Option<usize>, E> {
        let n = name::<E>(n)?;
        for (idx, e) in self.entries.iter().enumerate() {
            if FileSystemKey::parse(&e.key)?.record_type == 9 {
                let d = DirectoryEntryRecord::parse(&e.key, &e.value, v.directory_key_layout())?;
                if d.parent_id == parent && v.name_comparison().matches(d.name_str()?, n) {
                    return Ok(Some(idx));
                }
            }
        }
        Ok(None)
    }
    fn count<E>(&mut self, parent: u64, delta: i32) -> FsResult<(), E> {
        let idx = self.inode_index::<E>(parent)?;
        let i = self.inode::<E>(parent)?;
        let n = i
            .link_or_child_count
            .checked_add(delta)
            .filter(|n| *n >= 0)
            .ok_or_else(|| Error::from(ErrorKind::LimitExceeded))?;
        w32(&mut self.entries[idx].value, 56, n as u32);
        Ok(())
    }
    fn remove_at<E>(&mut self, idx: usize, directory: bool) -> FsResult<(), E> {
        let id = raw64(&self.entries[idx].value, 0);
        let parent = FileSystemKey::parse(&self.entries[idx].key)?.id;
        let i = self.inode::<E>(id)?;
        let isdir = i.mode & 0o170000 == 0o040000;
        if id <= 3 {
            return Err(ErrorKind::Busy.into());
        }
        if isdir != directory {
            return Err(if isdir {
                ErrorKind::IsADirectory
            } else {
                ErrorKind::NotADirectory
            }
            .into());
        }
        if isdir
            && self.entries.iter().any(|e| {
                FileSystemKey::parse(&e.key).is_ok_and(|k| k.id == id && k.record_type == 9)
            })
        {
            return Err(ErrorKind::DirectoryNotEmpty.into());
        }
        self.entries.remove(idx);
        self.entries
            .retain(|e| FileSystemKey::parse(&e.key).is_ok_and(|k| k.id != id));
        self.count::<E>(parent, -1)
    }
    pub fn metadata<E>(
        &mut self,
        v: &VolumeSuperblock,
        op: WriteOperation<'_>,
    ) -> FsResult<Option<u64>, E> {
        let result = match op {
            WriteOperation::Create {
                parent,
                name: n,
                directory,
                attrs: a,
            } => {
                self.directory::<E>(parent)?;
                let n = name::<E>(n)?;
                if self.find::<E>(v, parent, n.as_bytes())?.is_some() {
                    return Err(ErrorKind::AlreadyExists.into());
                }
                let id = self.next_id;
                self.next_id = id
                    .checked_add(1)
                    .filter(|id| *id < 1 << 60)
                    .ok_or_else(|| Error::from(ErrorKind::LimitExceeded))?;
                let mut val = vec![0; 92];
                w64(&mut val, 0, parent);
                w64(&mut val, 8, id);
                w32(&mut val, 56, u32::from(!directory));
                w16(&mut val, 80, if directory { 0o040755 } else { 0o100644 });
                attrs::<E>(&mut val, a, true)?;
                self.entries.push(entry(key(id, 3), val));
                let mut d = vec![0; 18];
                w64(&mut d, 0, id);
                w16(&mut d, 16, if directory { 4 } else { 8 });
                self.entries
                    .push(entry(drec_key(parent, n, self.hashed), d));
                self.count::<E>(parent, 1)?;
                Some(id)
            }
            WriteOperation::Remove {
                parent,
                name: n,
                directory,
            } => {
                self.directory::<E>(parent)?;
                let idx = self
                    .find::<E>(v, parent, n)?
                    .ok_or_else(|| Error::from(ErrorKind::NotFound))?;
                self.remove_at::<E>(idx, directory)?;
                None
            }
            WriteOperation::Rename {
                from_parent,
                from,
                to_parent,
                to,
                replace,
            } => {
                self.directory::<E>(from_parent)?;
                self.directory::<E>(to_parent)?;
                let text = name::<E>(to)?;
                let src = self
                    .find::<E>(v, from_parent, from)?
                    .ok_or_else(|| Error::from(ErrorKind::NotFound))?;
                let id = raw64(&self.entries[src].value, 0);
                if id <= 3 {
                    return Err(ErrorKind::Busy.into());
                }
                let directory = self.inode::<E>(id)?.mode & 0o170000 == 0o040000;
                if directory {
                    let mut p = to_parent;
                    let mut seen = BTreeSet::new();
                    while p != 1 {
                        if p == id || !seen.insert(p) {
                            return Err(ErrorKind::InvalidInput.into());
                        }
                        p = self.inode::<E>(p)?.parent_id;
                    }
                }
                if let Some(dst) = self.find::<E>(v, to_parent, to)? {
                    if dst != src {
                        if !replace {
                            return Err(ErrorKind::AlreadyExists.into());
                        }
                        self.remove_at::<E>(dst, directory)?;
                    }
                }
                let src = self
                    .find::<E>(v, from_parent, from)?
                    .ok_or_else(|| Error::from(ErrorKind::NotFound))?;
                self.entries[src].key = drec_key(to_parent, text, self.hashed);
                let idx = self.inode_index::<E>(id)?;
                w64(&mut self.entries[idx].value, 0, to_parent);
                set_xfield(
                    &mut self.entries[idx].value,
                    4,
                    2,
                    Some({
                        let mut b = text.as_bytes().to_vec();
                        b.push(0);
                        b
                    }),
                )?;
                if from_parent != to_parent {
                    self.count::<E>(from_parent, -1)?;
                    self.count::<E>(to_parent, 1)?;
                }
                None
            }
            WriteOperation::SetAttr { node, attrs: a } => {
                let idx = self.inode_index::<E>(node)?;
                attrs::<E>(&mut self.entries[idx].value, a, false)?;
                None
            }
            _ => return Err(ErrorKind::InvalidInput.into()),
        };
        self.sort();
        Ok(result)
    }
    pub fn replace_extents<E>(
        &mut self,
        id: u64,
        size: u64,
        extents: &[FileExtentRecord],
    ) -> FsResult<(), E> {
        let idx = self.inode_index::<E>(id)?;
        let allocated = extents
            .iter()
            .try_fold(0u64, |n, e| n.checked_add(e.length))
            .ok_or(crate::ApfsError::AddressOverflow)?;
        let mut stream = vec![0; 40];
        w64(&mut stream, 0, size);
        w64(&mut stream, 8, allocated);
        w64(&mut stream, 24, size);
        set_xfield(
            &mut self.entries[idx].value,
            8,
            0x20,
            if size > 0 { Some(stream) } else { None },
        )?;
        self.entries.retain(|e| {
            FileSystemKey::parse(&e.key)
                .is_ok_and(|k| k.id != id || !matches!(k.record_type, 6 | 8))
        });
        if size > 0 {
            self.entries
                .push(entry(key(id, 6), 1u32.to_le_bytes().to_vec()));
        }
        for e in extents {
            let mut k = key(id, 8);
            k.extend_from_slice(&e.logical_address.to_le_bytes());
            let mut val = vec![0; 24];
            w64(&mut val, 0, e.length);
            w64(&mut val, 8, e.physical_block);
            self.entries.push(entry(k, val));
        }
        self.sort();
        Ok(())
    }
    pub fn sort(&mut self) {
        let hashed = self.hashed;
        self.entries.sort_by(|a, b| fs_cmp(&a.key, &b.key, hashed));
    }
}
pub(crate) fn unsupported<E>(message: &'static str) -> Error<E> {
    Error::new(ErrorKind::Unsupported, message)
}
fn validate_xfields<E>(v: &[u8]) -> FsResult<(), E> {
    visit_xfields(v, |_, _, _| Ok(()))
}
fn visit_xfields<E>(
    v: &[u8],
    mut visit: impl FnMut(u8, u8, &[u8]) -> FsResult<(), E>,
) -> FsResult<(), E> {
    if v.len() == 92 {
        return Ok(());
    }
    let n = usize::from(u16::from_le_bytes(crate::types::take(v, 92)?));
    let used = usize::from(u16::from_le_bytes(crate::types::take(v, 94)?));
    if n > 2 || used != v.len() - 96 {
        return Err(unsupported("APFS inode extended-field layout"));
    }
    let mut at = 96 + n * 4;
    let mut seen = 0u16;
    for idx in 0..n {
        let h = v
            .get(96 + idx * 4..100 + idx * 4)
            .ok_or(crate::ApfsError::InputTooSmall)?;
        let len = usize::from(u16::from_le_bytes([h[2], h[3]]));
        if !matches!(h[0], 4 | 8)
            || seen & (1 << h[0]) != 0
            || (h[0] == 8 && (len != 40 || h[1] != 0x20))
            || (h[0] == 4 && h[1] != 2)
        {
            return Err(unsupported("APFS inode extended field"));
        }
        seen |= 1 << h[0];
        let end = at
            .checked_add(len)
            .ok_or(crate::ApfsError::AddressOverflow)?;
        let data = v.get(at..end).ok_or(crate::ApfsError::InputTooSmall)?;
        if h[0] == 8 && raw64(data, 16) != 0 {
            return Err(unsupported("APFS encrypted stream"));
        }
        if h[0] == 4 {
            let text = data
                .strip_suffix(&[0])
                .ok_or(crate::ApfsError::InvalidValue("APFS inode name terminator"))?;
            name::<E>(text)?;
        }
        visit(h[0], h[1], data)?;
        at = end
            .checked_add((8 - len % 8) % 8)
            .ok_or(crate::ApfsError::AddressOverflow)?;
    }
    if at != v.len() {
        return Err(ErrorKind::Corrupt.into());
    }
    Ok(())
}
fn xfields<E>(v: &[u8]) -> FsResult<Vec<(u8, u8, Vec<u8>)>, E> {
    let mut out = Vec::new();
    visit_xfields(v, |ty, flags, data| {
        out.push((ty, flags, data.to_vec()));
        Ok(())
    })?;
    Ok(out)
}
fn set_xfield<E>(v: &mut Vec<u8>, ty: u8, flags: u8, data: Option<Vec<u8>>) -> FsResult<(), E> {
    let mut fields = xfields::<E>(v)?;
    fields.retain(|f| f.0 != ty);
    if let Some(data) = data {
        fields.push((ty, flags, data));
    }
    fields.sort_by_key(|f| f.0);
    v.truncate(92);
    if fields.is_empty() {
        return Ok(());
    }
    let data_len: usize = fields.iter().map(|f| f.2.len().div_ceil(8) * 8).sum();
    let used = fields.len() * 4 + data_len;
    if used > u16::MAX as usize {
        return Err(ErrorKind::LimitExceeded.into());
    }
    v.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    v.extend_from_slice(&(used as u16).to_le_bytes());
    for (ty, flags, data) in &fields {
        v.push(*ty);
        v.push(*flags);
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    }
    for (_, _, data) in fields {
        let n = data.len();
        v.extend_from_slice(&data);
        v.resize(v.len() + (8 - n % 8) % 8, 0);
    }
    Ok(())
}

pub(crate) struct AllocationChunk {
    pub start: u64,
    pub count: u32,
    pub bitmap: Vec<u8>,
    pub new_bitmap: u64,
}
pub(crate) struct Allocation {
    pub chunks: Vec<AllocationChunk>,
    pub free: u64,
    pub next_oid: u64,
    pub used: u64,
    pub avoid: [u64; 2],
    pub cursor: u64,
}
impl Allocation {
    pub fn allocated(&self, block: u64) -> bool {
        self.chunks
            .iter()
            .find(|c| block >= c.start && block - c.start < u64::from(c.count))
            .is_some_and(|c| {
                let bit = (block - c.start) as usize;
                c.bitmap[bit / 8] & (1 << (bit % 8)) != 0
            })
    }
    pub fn allocate(&mut self) -> crate::Result<u64> {
        for c in &mut self.chunks {
            if c.start + u64::from(c.count) <= self.cursor {
                continue;
            }
            let first = self.cursor.saturating_sub(c.start) as usize;
            for (byte_idx, byte) in c.bitmap.iter_mut().enumerate().skip(first / 8) {
                let mut candidates = !*byte;
                if byte_idx == first / 8 {
                    candidates &= u8::MAX << (first % 8);
                }
                while candidates != 0 {
                    let bit = candidates.trailing_zeros() as usize;
                    candidates &= !(1 << bit);
                    let idx = byte_idx * 8 + bit;
                    if idx >= c.count as usize {
                        break;
                    }
                    let block = c.start + idx as u64;
                    if self.avoid.contains(&block) {
                        continue;
                    }
                    *byte |= 1 << bit;
                    self.free -= 1;
                    self.used += 1;
                    self.cursor = block + 1;
                    return Ok(block);
                }
            }
        }
        Err(crate::ApfsError::InvalidValue("APFS write space exhausted"))
    }
    pub fn node(&mut self, physical: bool) -> crate::Result<(u64, u64)> {
        let block = self.allocate()?;
        let oid = if physical {
            block
        } else {
            let oid = self.next_oid;
            self.next_oid = oid
                .checked_add(1)
                .ok_or(crate::ApfsError::AddressOverflow)?;
            oid
        };
        Ok((oid, block))
    }
}
