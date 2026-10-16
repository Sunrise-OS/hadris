//! Bulk encoding of existing-volume APFS B-trees into sealed 4096-byte nodes.
//!
//! Records must already be sorted in the tree's key order. Separators borrow the
//! first key of each child; index values are always eight-byte child object IDs,
//! including in trees whose fixed leaf values have a different size.

use alloc::vec::Vec;

use super::{BLOCK, object, seal, w16, w32, w64};
use crate::types::OwnedEntry;
use crate::{ApfsError, Result};

const NODE_HEADER: usize = 56;
const INFO_SIZE: usize = 40;
const ROOT: u16 = 1;
const LEAF: u16 = 2;
const FIXED: u16 = 4;
const INVALID_OFFSET: u16 = 0xffff;

/// Encoded blocks and the object-to-block mappings for every emitted node.
#[derive(Debug)]
pub struct BuiltTree {
    pub root_oid: u64,
    pub root_block: u64,
    /// Physical block addresses paired with sealed object bytes, root last.
    pub nodes: Vec<(u64, Vec<u8>)>,
    /// `(object ID, physical block)` pairs, including for physical trees.
    pub mappings: Vec<(u64, u64)>,
}

struct Params {
    xid: u64,
    subtype: u32,
    physical: bool,
    fixed: Option<(usize, usize)>,
}

#[derive(Clone, Copy)]
struct Info {
    longest_key: u32,
    longest_value: u32,
    key_count: u64,
    node_count: u64,
}

// Borrow separator keys instead of cloning records at every index level.
struct Child<'a> {
    key: &'a [u8],
    oid: u64,
}

trait Record {
    fn key(&self) -> &[u8];
    fn value_len(&self) -> usize;
    fn write_value(&self, out: &mut [u8]);
}

impl Record for OwnedEntry {
    fn key(&self) -> &[u8] {
        &self.key
    }

    fn value_len(&self) -> usize {
        self.value.len()
    }

    fn write_value(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.value);
    }
}

impl Record for Child<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }

    fn value_len(&self) -> usize {
        8
    }

    fn write_value(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.oid.to_le_bytes());
    }
}

#[derive(Clone, Copy, Default)]
struct Layout {
    count: usize,
    table: usize,
    keys: usize,
    values: usize,
    used: usize,
}

impl Layout {
    fn add(self, fixed: bool, key: usize, value: usize) -> Result<Self> {
        let count = self
            .count
            .checked_add(1)
            .ok_or(ApfsError::AddressOverflow)?;
        let keys = self
            .keys
            .checked_add(key)
            .ok_or(ApfsError::AddressOverflow)?;
        let values = self
            .values
            .checked_add(value)
            .ok_or(ApfsError::AddressOverflow)?;
        let table = count
            .checked_mul(if fixed { 4 } else { 8 })
            .ok_or(ApfsError::AddressOverflow)?;
        // Fixed-size TOCs are padded to eight bytes, as in the reference encoder.
        let table = if fixed {
            table.checked_add(7).ok_or(ApfsError::AddressOverflow)? & !7
        } else {
            table
        };
        let used = table
            .checked_add(keys)
            .and_then(|n| n.checked_add(values))
            .ok_or(ApfsError::AddressOverflow)?;
        Ok(Self {
            count,
            table,
            keys,
            values,
            used,
        })
    }
}

fn capacity(root: bool) -> usize {
    BLOCK - NODE_HEADER - if root { INFO_SIZE } else { 0 }
}

fn u16_len(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| ApfsError::AddressOverflow)
}

fn u32_len(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| ApfsError::AddressOverflow)
}

fn u64_len(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| ApfsError::AddressOverflow)
}

/// Encodes a sorted, validated record set, allocating leaves before index nodes.
///
/// `alloc` supplies `(object ID, physical block)`; its errors propagate unchanged.
/// Fixed dimensions must be nonzero and match all leaf records. Oversized records
/// and separator keys that cannot form a finite index tree are rejected. Allocation
/// can have occurred before an error; callers must discard the uncommitted result.
pub fn build(
    entries: &[OwnedEntry],
    xid: u64,
    subtype: u32,
    physical: bool,
    fixed: Option<(usize, usize)>,
    alloc: &mut impl FnMut() -> Result<(u64, u64)>,
) -> Result<BuiltTree> {
    if let Some((key, value)) = fixed {
        u32_len(key)?;
        u32_len(value)?;
        if key == 0 || value == 0 {
            return Err(ApfsError::InvalidValue("B-tree fixed record size"));
        }
    }
    let params = Params {
        xid,
        subtype,
        physical,
        fixed,
    };
    let mut layout = Layout::default();
    let mut info = Info {
        longest_key: 0,
        longest_value: 0,
        key_count: u64_len(entries.len())?,
        node_count: 1,
    };
    for entry in entries {
        if let Some((key, value)) = fixed {
            if entry.key.len() != key || entry.value.len() != value {
                return Err(ApfsError::InvalidValue("B-tree fixed record length"));
            }
        }
        let single = Layout::default().add(fixed.is_some(), entry.key.len(), entry.value.len())?;
        if single.used > capacity(false) {
            return Err(ApfsError::InvalidValue("B-tree record too large"));
        }
        layout = layout.add(fixed.is_some(), entry.key.len(), entry.value.len())?;
        info.longest_key = info.longest_key.max(u32_len(entry.key.len())?);
        info.longest_value = info.longest_value.max(u32_len(entry.value.len())?);
    }
    let mut tree = BuiltTree {
        root_oid: 0,
        root_block: 0,
        nodes: Vec::new(),
        mappings: Vec::new(),
    };
    if layout.used <= capacity(true) {
        emit(&params, &mut tree, entries, layout, 0, Some(info), alloc)?;
        return Ok(tree);
    }

    let mut children = Vec::new();
    let mut start = 0;
    while start < entries.len() {
        let layout = pack(&entries[start..], fixed.is_some())?;
        let end = start
            .checked_add(layout.count)
            .ok_or(ApfsError::AddressOverflow)?;
        let oid = emit(
            &params,
            &mut tree,
            &entries[start..end],
            layout,
            0,
            None,
            alloc,
        )?;
        children.push(Child {
            key: &entries[start].key,
            oid,
        });
        start = end;
    }

    let mut height = 1u16;
    loop {
        let mut layout = Layout::default();
        for child in &children {
            layout = layout.add(fixed.is_some(), child.key.len(), 8)?;
        }
        if layout.used <= capacity(true) {
            let node_count = tree
                .nodes
                .len()
                .checked_add(1)
                .ok_or(ApfsError::AddressOverflow)?;
            info.node_count = u64_len(node_count)?;
            emit(
                &params,
                &mut tree,
                &children,
                layout,
                height,
                Some(info),
                alloc,
            )?;
            return Ok(tree);
        }
        let mut next = Vec::new();
        let mut start = 0;
        while start < children.len() {
            let layout = pack(&children[start..], fixed.is_some())?;
            let end = start
                .checked_add(layout.count)
                .ok_or(ApfsError::AddressOverflow)?;
            let oid = emit(
                &params,
                &mut tree,
                &children[start..end],
                layout,
                height,
                None,
                alloc,
            )?;
            next.push(Child {
                key: children[start].key,
                oid,
            });
            start = end;
        }
        // Without a reduction, another level has identical keys and sizes and
        // can never fit a root. This also handles a lone root-sized separator.
        if next.len() >= children.len() {
            return Err(ApfsError::InvalidValue(
                "B-tree index keys prevent branching",
            ));
        }
        children = next;
        height = height.checked_add(1).ok_or(ApfsError::AddressOverflow)?;
    }
}

fn pack<T: Record>(entries: &[T], fixed: bool) -> Result<Layout> {
    let mut layout = Layout::default();
    for entry in entries {
        let next = layout.add(fixed, entry.key().len(), entry.value_len())?;
        if next.used > capacity(false) {
            break;
        }
        layout = next;
    }
    if layout.count == 0 {
        return Err(ApfsError::InvalidValue("B-tree record too large"));
    }
    Ok(layout)
}

fn emit<T: Record>(
    params: &Params,
    tree: &mut BuiltTree,
    entries: &[T],
    layout: Layout,
    level: u16,
    info: Option<Info>,
    alloc: &mut impl FnMut() -> Result<(u64, u64)>,
) -> Result<u64> {
    let root = info.is_some();
    let value_end = NODE_HEADER + capacity(root);
    let free = capacity(root)
        .checked_sub(layout.used)
        .ok_or(ApfsError::InvalidValue("B-tree node overflow"))?;
    let (oid, block) = alloc()?;
    let storage = if params.physical { 0x4000_0000 } else { 0 };
    let mut data = object(
        oid,
        params.xid,
        storage | if root { 2 } else { 3 },
        params.subtype,
    );
    let fixed = params.fixed.is_some();
    let flags = if root { ROOT } else { 0 }
        | if level == 0 { LEAF } else { 0 }
        | if fixed { FIXED } else { 0 };
    w16(&mut data, 32, flags);
    w16(&mut data, 34, level);
    w32(&mut data, 36, u32_len(layout.count)?);
    w16(&mut data, 40, 0);
    w16(&mut data, 42, u16_len(layout.table)?);
    w16(&mut data, 44, u16_len(layout.keys)?);
    w16(&mut data, 46, u16_len(free)?);
    w16(&mut data, 48, INVALID_OFFSET);
    w16(&mut data, 50, 0);
    w16(&mut data, 52, INVALID_OFFSET);
    w16(&mut data, 54, 0);

    // Layout has bounded all following offsets and lengths by a single block.
    let key_start = NODE_HEADER + layout.table;
    let (mut key_offset, mut value_offset) = (0, 0);
    for (i, entry) in entries.iter().enumerate() {
        let key = entry.key();
        let value_len = entry.value_len();
        value_offset += value_len;
        let table = NODE_HEADER + i * if fixed { 4 } else { 8 };
        w16(&mut data, table, u16_len(key_offset)?);
        if fixed {
            w16(&mut data, table + 2, u16_len(value_offset)?);
        } else {
            w16(&mut data, table + 2, u16_len(key.len())?);
            w16(&mut data, table + 4, u16_len(value_offset)?);
            w16(&mut data, table + 6, u16_len(value_len)?);
        }
        let at = key_start + key_offset;
        data[at..at + key.len()].copy_from_slice(key);
        let at = value_end - value_offset;
        entry.write_value(&mut data[at..at + value_len]);
        key_offset += key.len();
    }
    if let Some(info) = info {
        let at = BLOCK - INFO_SIZE;
        let (key, value) = params.fixed.unwrap_or((0, 0));
        w32(&mut data, at, if params.physical { 0x10 } else { 0x40 });
        w32(&mut data, at + 4, u32_len(BLOCK)?);
        w32(&mut data, at + 8, u32_len(key)?);
        w32(&mut data, at + 12, u32_len(value)?);
        w32(&mut data, at + 16, info.longest_key);
        w32(&mut data, at + 20, info.longest_value);
        w64(&mut data, at + 24, info.key_count);
        w64(&mut data, at + 32, info.node_count);
    }
    seal(&mut data);
    if root {
        tree.root_oid = oid;
        tree.root_block = block;
    }
    tree.nodes.push((block, data));
    tree.mappings.push((oid, block));
    Ok(oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BTreeInfo, BTreeNode};
    use alloc::vec;

    fn allocator() -> impl FnMut() -> Result<(u64, u64)> {
        let mut oid = 10u64;
        move || {
            oid += 1;
            Ok((oid, oid + 1000))
        }
    }

    fn root(tree: &BuiltTree) -> BTreeNode<'_> {
        BTreeNode::parse(&tree.nodes.last().unwrap().1).unwrap()
    }

    fn walk(tree: &BuiltTree, oid: u64, info: BTreeInfo, out: &mut Vec<OwnedEntry>) {
        let block = tree.mappings.iter().find(|entry| entry.0 == oid).unwrap().1;
        let data = &tree.nodes.iter().find(|entry| entry.0 == block).unwrap().1;
        let node = BTreeNode::parse(data).unwrap();
        let records = if node.has_fixed_kv() {
            node.fixed_entries(info).unwrap()
        } else {
            node.variable_entries().unwrap()
        };
        for entry in records {
            if node.is_leaf() {
                out.push(OwnedEntry {
                    key: entry.key.to_vec(),
                    value: entry.value.to_vec(),
                });
            } else {
                let child = u64::from_le_bytes(entry.value.try_into().unwrap());
                walk(tree, child, info, out);
            }
        }
    }

    fn roundtrip(
        entries: &[OwnedEntry],
        fixed: Option<(usize, usize)>,
        physical: bool,
    ) -> BuiltTree {
        let tree = build(entries, 7, 14, physical, fixed, &mut allocator()).unwrap();
        let node = root(&tree);
        let info = node.tree_info().unwrap();
        assert_eq!(info.key_count, entries.len() as u64);
        assert_eq!(info.node_count, tree.nodes.len() as u64);
        assert_eq!(info.fixed.flags, if physical { 0x10 } else { 0x40 });
        assert_eq!(tree.nodes.len(), tree.mappings.len());
        let mut decoded = Vec::new();
        walk(&tree, tree.root_oid, info, &mut decoded);
        assert_eq!(decoded, entries);
        tree
    }

    #[test]
    fn empty_and_single_roots() {
        for fixed in [None, Some((8, 16))] {
            let tree = roundtrip(&[], fixed, false);
            assert_eq!(tree.nodes.len(), 1);
            assert!(root(&tree).is_leaf());
            let entry = OwnedEntry {
                key: vec![1; 8],
                value: vec![2; 16],
            };
            let tree = roundtrip(&[entry], fixed, true);
            assert_eq!(tree.nodes.len(), 1);
            assert_eq!(root(&tree).table_length, 8);
        }
    }

    #[test]
    fn fixed_and_variable_multiple_index_levels() {
        let entries: Vec<_> = (0u64..400)
            .map(|i| {
                let mut key = vec![0; 512];
                key[..8].copy_from_slice(&i.to_be_bytes());
                OwnedEntry {
                    key,
                    value: vec![(i % 256) as u8; 24],
                }
            })
            .collect();
        for fixed in [None, Some((512, 24))] {
            let tree = roundtrip(&entries, fixed, false);
            assert!(root(&tree).level >= 2);
        }
    }

    #[test]
    fn root_trailer_can_require_a_parent() {
        let entry = OwnedEntry {
            key: vec![1; 8],
            value: vec![2; 4000],
        };
        let tree = roundtrip(&[entry], None, false);
        assert_eq!(tree.nodes.len(), 2);
        assert_eq!(root(&tree).level, 1);
    }

    #[test]
    fn malformed_and_oversized_records_are_errors() {
        let entry = OwnedEntry {
            key: vec![1; 8],
            value: vec![2; 16],
        };
        assert_eq!(
            build(&[], 1, 0, false, Some((0, 8)), &mut allocator()).unwrap_err(),
            ApfsError::InvalidValue("B-tree fixed record size")
        );
        assert_eq!(
            build(&[entry], 1, 0, false, Some((8, 8)), &mut allocator()).unwrap_err(),
            ApfsError::InvalidValue("B-tree fixed record length")
        );
        let entry = OwnedEntry {
            key: vec![0; BLOCK],
            value: Vec::new(),
        };
        assert_eq!(
            build(&[entry], 1, 0, false, None, &mut allocator()).unwrap_err(),
            ApfsError::InvalidValue("B-tree record too large")
        );
        assert!(matches!(
            Layout::default().add(false, usize::MAX, 1),
            Err(ApfsError::AddressOverflow)
        ));
    }

    #[test]
    fn unbranchable_separators_and_allocator_errors_are_returned() {
        let entries: Vec<_> = (0..2)
            .map(|i| OwnedEntry {
                key: vec![i; 2100],
                value: vec![0; 8],
            })
            .collect();
        assert_eq!(
            build(&entries, 1, 0, false, None, &mut allocator()).unwrap_err(),
            ApfsError::InvalidValue("B-tree index keys prevent branching")
        );
        let mut fail = || Err(ApfsError::Unsupported("allocator failure"));
        assert_eq!(
            build(&[], 1, 0, false, None, &mut fail).unwrap_err(),
            ApfsError::Unsupported("allocator failure")
        );
    }
}
