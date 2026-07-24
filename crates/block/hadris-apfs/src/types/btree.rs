//! Minimal APFS B-tree node parsing.

use crate::types::object::{ObjectHeader, ObjectType};
use crate::types::{le_u32, le_u64};

/// Parsed B-tree fixed info (`btree_info_fixed_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BTreeInfoFixed {
    /// B-tree flags.
    pub flags: u32,
    /// Node size in bytes.
    pub node_size: u32,
    /// Fixed key size, or zero for variable keys.
    pub key_size: u32,
    /// Fixed value size, or zero for variable values.
    pub value_size: u32,
}

/// Parsed B-tree info trailer (`btree_info_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BTreeInfo {
    /// Static tree information.
    pub fixed: BTreeInfoFixed,
    /// Longest key ever stored.
    pub longest_key: u32,
    /// Longest value ever stored.
    pub longest_value: u32,
    /// Number of keys in the tree.
    pub key_count: u64,
    /// Number of nodes in the tree.
    pub node_count: u64,
}

impl BTreeInfo {
    /// Size of `btree_info_t`.
    pub const SIZE: usize = 40;

    /// Parses B-tree info from bytes.
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        Ok(Self {
            fixed: BTreeInfoFixed {
                flags: le_u32(data, 0)?,
                node_size: le_u32(data, 4)?,
                key_size: le_u32(data, 8)?,
                value_size: le_u32(data, 12)?,
            },
            longest_key: le_u32(data, 16)?,
            longest_value: le_u32(data, 20)?,
            key_count: le_u64(data, 24)?,
            node_count: le_u64(data, 32)?,
        })
    }
}

/// Parsed fixed-size B-tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedEntry<'a> {
    /// Key bytes.
    pub key: &'a [u8],
    /// Value bytes.
    pub value: &'a [u8],
}

/// Owned B-tree key/value entry independent of the backing block lifetime.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEntry {
    /// Key bytes.
    pub key: alloc::vec::Vec<u8>,
    /// Value bytes.
    pub value: alloc::vec::Vec<u8>,
}

/// Owned B-tree node block.
#[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedBTreeNode {
    data: alloc::vec::Vec<u8>,
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl OwnedBTreeNode {
    /// Creates an owned node from a full APFS block and validates it parses as a B-tree node.
    pub fn parse(data: alloc::vec::Vec<u8>) -> crate::Result<Self> {
        BTreeNode::parse(&data)?;
        Ok(Self { data })
    }

    /// Borrows the parsed B-tree node header and backing bytes.
    pub fn node(&self) -> crate::Result<BTreeNode<'_>> {
        BTreeNode::parse(&self.data)
    }

    /// Returns the backing APFS block bytes.
    pub fn block(&self) -> &[u8] {
        &self.data
    }

    /// Returns whether this node is a root node.
    pub fn is_root(&self) -> crate::Result<bool> {
        Ok(self.node()?.is_root())
    }

    /// Returns whether this node is a leaf node.
    pub fn is_leaf(&self) -> crate::Result<bool> {
        Ok(self.node()?.is_leaf())
    }

    /// Parses the root-node B-tree info trailer.
    pub fn tree_info(&self) -> crate::Result<BTreeInfo> {
        self.node()?.tree_info()
    }

    /// Returns owned entries from this node.
    pub fn owned_entries(
        &self,
        root_info: Option<BTreeInfo>,
    ) -> crate::Result<alloc::vec::Vec<OwnedEntry>> {
        let node = self.node()?;
        let entries = if node.has_fixed_kv() {
            // `unwrap_or` would evaluate `node.tree_info()?` eagerly on every
            // node, even when `root_info` is already `Some`. The B-tree info
            // trailer only exists on the root node, so calling `tree_info()`
            // on a non-root child fails — silently harmless on single-node
            // trees (the sole node is the root) but fatal on any multi-level
            // tree once the walk descends past the root. Resolve the fixed
            // key/value sizes lazily instead.
            let info = match root_info {
                Some(info) => info,
                None => node.tree_info()?,
            };
            node.fixed_entries(info)?
        } else {
            node.variable_entries()?
        };
        Ok(entries
            .into_iter()
            .map(|entry| OwnedEntry {
                key: entry.key.to_vec(),
                value: entry.value.to_vec(),
            })
            .collect())
    }
}

/// Parsed B-tree node header plus backing bytes.
#[derive(Debug, Clone, Copy)]
pub struct BTreeNode<'a> {
    /// Common object header.
    pub object: ObjectHeader,
    /// Node flags.
    pub flags: u16,
    /// Child levels below this node.
    pub level: u16,
    /// Number of keys.
    pub key_count: u32,
    /// Node payload bytes after the fixed header.
    pub data: &'a [u8],
    /// Table-of-contents offset within [`Self::data`].
    pub table_offset: u16,
    /// Table-of-contents length in bytes.
    pub table_length: u16,
}

impl<'a> BTreeNode<'a> {
    /// Parses a B-tree node from a full APFS block.
    pub fn parse(block: &'a [u8]) -> crate::Result<Self> {
        let object = ObjectHeader::parse(block)?;
        let kind = object.kind();
        if kind != ObjectType::BTreeRoot as u16 && kind != ObjectType::BTreeNode as u16 {
            return Err(crate::ApfsError::InvalidValue("B-tree node object type"));
        }
        Ok(Self {
            object,
            flags: u16::from_le_bytes(crate::types::take(block, 32)?),
            level: u16::from_le_bytes(crate::types::take(block, 34)?),
            key_count: le_u32(block, 36)?,
            table_offset: u16::from_le_bytes(crate::types::take(block, 40)?),
            table_length: u16::from_le_bytes(crate::types::take(block, 42)?),
            data: block.get(56..).ok_or(crate::ApfsError::InputTooSmall)?,
        })
    }

    /// Returns whether this node is a root node.
    pub const fn is_root(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Returns whether this node is a leaf node.
    pub const fn is_leaf(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Returns whether this node uses fixed-size keys and values.
    pub const fn has_fixed_kv(&self) -> bool {
        self.flags & 4 != 0
    }

    /// Parses the root-node B-tree info trailer.
    pub fn tree_info(&self) -> crate::Result<BTreeInfo> {
        if !self.is_root() {
            return Err(crate::ApfsError::NotBTreeRoot {
                object_identifier: self.object.identifier,
                transaction_identifier: self.object.transaction_identifier,
                object_type: self.object.object_type,
                flags: self.flags,
            });
        }
        let start = self
            .data
            .len()
            .checked_sub(BTreeInfo::SIZE)
            .ok_or(crate::ApfsError::InputTooSmall)?;
        BTreeInfo::parse(&self.data[start..])
    }

    /// Iterates fixed-size entries using the supplied root tree info.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn fixed_entries(&self, info: BTreeInfo) -> crate::Result<alloc::vec::Vec<FixedEntry<'a>>> {
        if !self.has_fixed_kv() || info.fixed.key_size == 0 || info.fixed.value_size == 0 {
            return Err(crate::ApfsError::InvalidValue(
                "variable-size B-tree entries",
            ));
        }
        let toc_start = self.table_offset as usize;
        let toc_end = toc_start
            .checked_add(self.table_length as usize)
            .ok_or(crate::ApfsError::AddressOverflow)?;
        let key_space_start = toc_end;
        // Only leaf entries use the tree's declared leaf value size. Non-leaf
        // (index) node entries always store an 8-byte child object identifier,
        // regardless of the leaf value size recorded in `btree_info_t`.
        let value_size = if self.is_leaf() {
            info.fixed.value_size as usize
        } else {
            8
        };
        let mut entries = alloc::vec::Vec::with_capacity(self.key_count as usize);
        for i in 0..self.key_count as usize {
            let off = toc_start + i * 4;
            let key_off = u16::from_le_bytes(crate::types::take(self.data, off)?) as usize;
            let value_off = u16::from_le_bytes(crate::types::take(self.data, off + 2)?) as usize;
            let key_start = key_space_start
                .checked_add(key_off)
                .ok_or(crate::ApfsError::AddressOverflow)?;
            let key_end = key_start
                .checked_add(info.fixed.key_size as usize)
                .ok_or(crate::ApfsError::AddressOverflow)?;
            let value_space_end = if self.is_root() {
                self.data
                    .len()
                    .checked_sub(BTreeInfo::SIZE)
                    .ok_or(crate::ApfsError::InputTooSmall)?
            } else {
                self.data.len()
            };
            let value_start = value_space_end
                .checked_sub(value_off)
                .ok_or(crate::ApfsError::InputTooSmall)?;
            let value_end = value_start
                .checked_add(value_size)
                .ok_or(crate::ApfsError::AddressOverflow)?;
            entries.push(FixedEntry {
                key: self
                    .data
                    .get(key_start..key_end)
                    .ok_or(crate::ApfsError::InputTooSmall)?,
                value: self
                    .data
                    .get(value_start..value_end)
                    .ok_or(crate::ApfsError::InputTooSmall)?,
            });
        }
        Ok(entries)
    }

    /// Iterates variable-size entries from this node.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn variable_entries(&self) -> crate::Result<alloc::vec::Vec<FixedEntry<'a>>> {
        let toc_start = self.table_offset as usize;
        let toc_end = toc_start
            .checked_add(self.table_length as usize)
            .ok_or(crate::ApfsError::AddressOverflow)?;
        let key_space_start = toc_end;
        let mut entries = alloc::vec::Vec::with_capacity(self.key_count as usize);
        for i in 0..self.key_count as usize {
            let off = toc_start + i * 8;
            let key_off = u16::from_le_bytes(crate::types::take(self.data, off)?) as usize;
            let key_len = u16::from_le_bytes(crate::types::take(self.data, off + 2)?) as usize;
            let value_off = u16::from_le_bytes(crate::types::take(self.data, off + 4)?) as usize;
            let value_len = u16::from_le_bytes(crate::types::take(self.data, off + 6)?) as usize;
            let key_start = key_space_start
                .checked_add(key_off)
                .ok_or(crate::ApfsError::AddressOverflow)?;
            let key_end = key_start
                .checked_add(key_len)
                .ok_or(crate::ApfsError::AddressOverflow)?;
            let value_space_end = if self.is_root() {
                self.data
                    .len()
                    .checked_sub(BTreeInfo::SIZE)
                    .ok_or(crate::ApfsError::InputTooSmall)?
            } else {
                self.data.len()
            };
            let value_start = value_space_end
                .checked_sub(value_off)
                .ok_or(crate::ApfsError::InputTooSmall)?;
            let value_end = value_start
                .checked_add(value_len)
                .ok_or(crate::ApfsError::AddressOverflow)?;
            entries.push(FixedEntry {
                key: self
                    .data
                    .get(key_start..key_end)
                    .ok_or(crate::ApfsError::InputTooSmall)?,
                value: self
                    .data
                    .get(value_start..value_end)
                    .ok_or(crate::ApfsError::InputTooSmall)?,
            });
        }
        Ok(entries)
    }
}

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
mod btree_multi_level_tests {
    use super::*;

    /// Builds a minimal non-root, non-leaf, fixed-key/value B-tree node with a
    /// single entry (8-byte key, 8-byte child pointer) and no `btree_info_t`
    /// trailer (which only the root carries).
    fn non_root_fixed_node() -> alloc::vec::Vec<u8> {
        let mut block = alloc::vec![0_u8; 128];
        // obj_phys_t: object type = physically-addressed B-tree node.
        block[24] = ObjectType::BTreeNode as u8;
        block[26] = 0x40; // OBJ_PHYSICAL in the high half of o_type.
        // btn_flags = FIXED_KV only (no ROOT, no LEAF); level = 1 (non-leaf).
        block[32..34].copy_from_slice(&4u16.to_le_bytes());
        block[34..36].copy_from_slice(&1u16.to_le_bytes());
        // btn_nkeys = 1.
        block[36..40].copy_from_slice(&1u32.to_le_bytes());
        // Table of contents: offset 0, length 4 (one fixed 4-byte toc entry).
        block[40..42].copy_from_slice(&0u16.to_le_bytes());
        block[42..44].copy_from_slice(&4u16.to_le_bytes());
        // Payload begins at block[56..]; toc entry is key_off=0, value_off=8.
        let data = 56;
        block[data..data + 2].copy_from_slice(&0u16.to_le_bytes());
        block[data + 2..data + 4].copy_from_slice(&8u16.to_le_bytes());
        // Key sits right after the toc (key space start = toc_end = 4).
        block[data + 4..data + 12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        // Value grows down from the end of the node (non-root: no info trailer).
        let value_start = block.len() - 8;
        block[value_start..].copy_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);
        block
    }

    /// Regression test for the `unwrap_or` eager-evaluation bug: walking a
    /// multi-level tree descends to non-root child nodes, and
    /// [`OwnedBTreeNode::owned_entries`] must use the caller-supplied root
    /// info for them rather than eagerly calling `tree_info()` (which errors
    /// on any non-root node and previously aborted the whole walk).
    #[test]
    fn owned_entries_on_non_root_node_uses_supplied_info() {
        let node = OwnedBTreeNode::parse(non_root_fixed_node()).expect("parse node");
        assert!(!node.is_root().unwrap());
        // Sanity: reading info off this non-root node is an error, so the old
        // eager `unwrap_or(node.tree_info()?)` would have propagated it.
        assert!(matches!(
            node.tree_info(),
            Err(crate::ApfsError::NotBTreeRoot { .. })
        ));
        let info = BTreeInfo {
            fixed: BTreeInfoFixed {
                flags: 0,
                node_size: 128,
                key_size: 8,
                value_size: 8,
            },
            longest_key: 8,
            longest_value: 8,
            key_count: 1,
            node_count: 1,
        };
        let entries = node.owned_entries(Some(info)).expect("owned entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(entries[0].value, [9, 10, 11, 12, 13, 14, 15, 16]);
    }
}
