use core::fmt;

/// APFS operation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApfsError {
    /// Input ended before the requested structure could be parsed.
    InputTooSmall,
    /// The APFS magic value was not present.
    InvalidMagic {
        /// Expected magic bytes.
        expected: [u8; 4],
        /// Actual magic bytes found in input.
        actual: [u8; 4],
    },
    /// A field contained an invalid value.
    InvalidValue(&'static str),
    /// Fletcher checksum verification failed.
    ChecksumMismatch {
        /// Checksum stored in the object header.
        expected: u64,
        /// Checksum computed from the object bytes.
        actual: u64,
    },
    /// Arithmetic overflow while calculating an address or length.
    AddressOverflow,
    /// A B-tree walk expected the node at `object_identifier` to be the root
    /// of its tree (carrying the `btree_info_t` trailer), but its on-disk
    /// flags don't have the root bit set.
    NotBTreeRoot {
        /// The node's `obj_phys_t.o_oid`. For a physically-addressed B-tree
        /// node this is also its physical block address.
        object_identifier: u64,
        /// The node's `obj_phys_t.o_xid`. A value newer than the transaction
        /// that referenced this block indicates the block was reallocated to
        /// a different object (a live-disk race), rather than a real
        /// non-root node in the intended tree.
        transaction_identifier: u64,
        /// Raw APFS object type/subtype from the node's header.
        object_type: u32,
        /// Raw `btn_flags` read from the node.
        flags: u16,
    },
    /// Underlying I/O failed.
    Io(hadris_io::ErrorKind),
    /// Encryption/decryption failed: a malformed keybag or wrapped-key blob,
    /// a wrong password, or a volume that isn't unlocked before an encrypted
    /// block was read.
    #[cfg(feature = "crypto")]
    Crypto(&'static str),
}

/// Result type used by APFS operations.
pub type Result<T> = core::result::Result<T, ApfsError>;

impl ApfsError {
    /// Converts a portable I/O error into an APFS error without retaining the backend type.
    pub fn from_io<E: hadris_io::IoError>(error: hadris_io::Error<E>) -> Self {
        Self::Io(error.kind())
    }
}

impl fmt::Display for ApfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooSmall => f.write_str("APFS input too small"),
            Self::InvalidMagic { expected, actual } => write!(
                f,
                "invalid APFS magic {:?}, expected {:?}",
                actual, expected
            ),
            Self::InvalidValue(name) => write!(f, "invalid APFS value: {name}"),
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "APFS checksum mismatch: expected {expected:#x}, got {actual:#x}"
            ),
            Self::AddressOverflow => f.write_str("APFS address calculation overflowed"),
            Self::NotBTreeRoot {
                object_identifier,
                transaction_identifier,
                object_type,
                flags,
            } => write!(
                f,
                "expected B-tree root at object {object_identifier} (oid {object_identifier:#x}), \
                 found object_type {object_type:#010x} flags {flags:#06x} (root bit {}) xid {transaction_identifier}",
                flags & 1 != 0
            ),
            Self::Io(kind) => write!(f, "APFS I/O error: {kind:?}"),
            #[cfg(feature = "crypto")]
            Self::Crypto(reason) => write!(f, "APFS decryption failed: {reason}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ApfsError {}
