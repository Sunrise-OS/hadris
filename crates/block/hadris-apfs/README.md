# hadris-apfs

`hadris-apfs` is an experimental APFS container reader and filesystem driver.
Ordinary mounts are read-only; the opt-in `write` feature adds formatting of
new containers and restricted existing-volume mutations. It supports
synchronous and asynchronous I/O and can be used in `no_std` environments with
an allocator. Its API is outside the Hadris 3.x stability promise and may
change in a minor release; depend on it with `hadris-apfs = "~3.0"` to take
only compatible updates.

The crate is suitable for inspecting unencrypted APFS images and, with the
`encryption` feature, password-encrypted single-key APFS volumes made by macOS. It
is not a recovery, repair or forensic implementation.

`sync::ApfsFs` and `async_::ApfsFs` implement the V3 `FileSystem` trait,
so generic `Volume` paths, file handles, walks and extraction work on APFS.
Mounting needs an allocator, but not `std`. `Container` retains native container,
checkpoint, object-map and space-manager inspection. I/O errors retain the
backend's error through `hadris_fs::Error<D::Error>`.

A default mount requires exactly one volume. Select another with
`ApfsFs::mount_volume(device, options, VolumeSelector::Index(index))`, or select
by APFS object ID, UUID or name. Failed mounts return the device through
`MountError`. The umbrella's `detect` lists APFS containers without
mounting them; its `unstable-apfs` feature adds mounting of single-volume
containers through `open`, native inspection and explicit volume
selection. The unified CLI provides `hadris apfs` commands.
Enable `hadris`'s `apfs-encryption` feature for password unlocking through its
native re-export. Ordinary format detection does not enable crypto dependencies.

```rust,no_run
use hadris_apfs::sync::ApfsFs;
use hadris_fs::{MountOptions, OpenOptions};
use hadris_fs::sync::Volume;
use hadris_storage::host::FileDevice;
use std::io::Read;

let device = FileDevice::open("container.img")?;
let volume = Volume::new(ApfsFs::mount(device, MountOptions::new())?);
for entry in volume.read_dir("/")? {
    println!("{:?}", entry?.name());
}
let mut contents = Vec::new();
volume.open("/notes.txt", OpenOptions::new().read())?.read_to_end(&mut contents)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The [V3 use cases](../../../docs/apfs-v3-use-cases.md) explain how inspection,
generic file access, VFS operations and volume selection shape this API.

## Supported scope

- Optional software encryption: container and volume keybags, password-based
  PBKDF2-HMAC-SHA256, AES key unwrap and AES-XTS metadata/file reads on
  `APFS_FS_ONEKEY` volumes. Crypto-user selection is independent of volume
  selection; wrong credentials retain the device and report `InvalidInput`
  with `Detail::Credentials`.
- Container superblocks, the checkpoint descriptor ring and checkpoint maps.
  Block zero supplies the geometry and descriptor area; its checksum is not
  required. `latest_superblock` and mounting use the newest descriptor-area
  superblock whose checksum, checkpoint map and object map verify, falling
  back to older checkpoints, then to a verified block zero.
- Container and volume object maps, resolved at the volume's transaction.
- Physical and virtual B-trees, including sealed volumes with hashed index
  entries, nodes stored without object headers and file extents kept in the
  file extent tree.
- Incompatible features: mounting accepts the container feature
  `NX_INCOMPAT_VERSION2` and the volume features `CASE_INSENSITIVE`,
  `NORMALIZATION_INSENSITIVE`, `DATALESS_SNAPS`, `ENC_ROLLED` and
  `SEALED_VOLUME`. Version 1 and Fusion containers, volumes with
  `INCOMPLETE_RESTORE` or the reserved `0x40` bit, and any bit the
  specification does not define fail with `ErrorKind::Unsupported` and
  `Detail::Feature`. Directory keys use the hashed layout
  (`j_drec_hashed_key_t`) on case- or normalization-insensitive volumes and
  the plain layout (`j_drec_key_t`) otherwise.
- Directory listing and path lookup, folded by case and canonical
  decomposition on volumes formatted that way. Path lookup handles `.` and
  `..`, clamps parent traversal at the volume root, and requires directories
  for intermediate components and trailing slashes. Symlinks are returned
  without following them.
- Inode metadata: mode, owner, BSD flags, timestamps and data-stream size.
- Directory names as stored, including names that are not UTF-8 and names
  longer than 255 bytes, up to the key's name-length field (1022 bytes for
  hashed keys). Listings of names longer than `DirEntry::MAX_NAME` fail with
  `NameTooLong` at that entry.
- Damage confined to one node: a directory entry whose inode is missing,
  malformed, of an unknown mode or of another type than the entry records,
  whose extents overlap or leave the container, or whose symlink target is
  stored in a data stream, is listed with the entry's type only. `stat`,
  `read`, `open` and `readlink` on that node return the error.
- File data from extents, with sparse extents and uncovered ranges read as
  zeros.
- Symlink targets and hard links.
- Space manager summaries and chunk-info blocks.

## Experimental writes

Enable `write` (which implies `alloc`) and call `ApfsFs::mount_writable` or
`mount_volume_writable`. Ordinary and password mount constructors remain
read-only even when this feature is enabled. Writable constructors require a
writable device and reject `MountOptions::read_only()`.

The supported layout is deliberately narrow: one unencrypted, case-sensitive
volume with 4096-byte APFS blocks, plain or normalization-hashed directory
keys, ordinary files, directories and embedded symlink targets. Images made
by the out-of-tree XNU `tools/mkapfs` implementation are supported. Existing
snapshots, clones/shared streams, hard links, sparse files, compression,
encryption/sealing, Fusion, additional extended attributes, volume roles or
reserves, and active space-manager internal pools, free queues or allocation
zones are rejected before writing. This is not a general macOS-volume writer.

Supported mutations are `create`, `mkdir`, `write` (including zero-filled
growth), `truncate`, `unlink`, `rmdir`, `rename`, and `setattr` for permissions,
owner and supported timestamps. `fsync`, `sync` and writable unmount flush the
device. Removing the last name of an open node fails with `Busy`.
New names must be valid UTF-8 and no longer than 255 bytes.

Each mutation validates the supported on-disk layout, stages metadata in
memory, copies changed data and rebuilds the filesystem, extent-reference and
object-map trees on free blocks. Allocation bitmaps and chunk-info blocks
are copied too. It writes inactive checkpoint-data and descriptor slots,
flushes the device, publishes a checksummed container superblock, then
flushes again. The previous checkpoint is untouched until publication.
An I/O failure or async cancellation after writes begin disables further
mutations on that mount; reopen the device to select its valid checkpoint.
Publication errors can mean the new checkpoint reached disk despite the error.
Do not retry a mutation blindly.

Old allocations are never reclaimed, including blocks made obsolete by
truncate or unlink. Repeated mutations therefore consume space until
`NoSpace`; this is an experimental correctness-first implementation, not a
bounded-memory or sustained-write design. Back up images before using it.

Persistence, rotating checkpoints, interrupted/torn writes and async
cancellation are covered by regression tests. A modified `mkapfs` image was
also mounted with the independent `apfs-fuse` reader, checking file bytes and
Unicode names. Apple `fsck_apfs` and native macOS write interoperability have
not been qualified.

## Creating a container

With `write`, `sync::format` and `async_::format` turn a writable block device
into a new APFS container holding one empty, unencrypted, case-sensitive
volume. Mount the result with `ApfsFs::mount`, or with `ApfsFs::mount_writable`
to add files.

```text
let mut device = FileDevice::new(file)?;
let options = ApfsOptions::new().with_label("Data").with_size(64 << 20);
let formatted = format(&mut device, &options)?;
let fs = ApfsFs::mount_writable(device, MountOptions::new())?;
```

The container fills the device, rounded down to whole 4096-byte blocks, unless
`ApfsOptions::with_size` asks for another size; a device that grows when
written, such as a host file, is grown to fit. The device's blocks may be 512,
1024, 2048 or 4096 bytes and give the same container. The layout follows the
out-of-tree `mkapfs` writer: an 8-block checkpoint descriptor area, a 52-block
checkpoint data area, then the space manager, object maps and trees, with the
root directory and the private directory APFS keeps beside it. A container
can be about 3 TiB at most.

The label, time and UUIDs are options. Without a seed or explicit UUIDs, the
UUIDs derive from the time, label and size, so two formats with the same
options give the same identifiers; give volumes that must stay distinguishable
distinct seeds or UUIDs. Directory entries use hashed keys, as a
normalization-insensitive volume does, by default;
`with_normalization_insensitive(false)` selects plain keys. Case-insensitive
volumes are not offered, because the writable driver rejects them.

Block 0 and the checkpoint areas are overwritten first, so no older container
or checkpoint on the device survives. The new checkpoint is published after the
metadata is flushed and block 0 is written last, so an interrupted format
leaves a device that does not mount, or, when its first write fails, the
untouched old container, and never a mix of the two. Nothing is written when
an option or the device is invalid.

To fill the volume at format time, build an `ApfsNode` tree and pass it to
`ApfsOptions::with_root`. Directories, regular files and symbolic links are
supported, each with its permission bits, owner and BSD flags (`st_flags`);
names are checked as they are added. A file built with `ApfsNode::file` holds
its bytes in memory until written; one built with `ApfsNode::file_from` takes
a `FileSource` and is read as the format writes it, so a large tree need not
fit in memory.

```text
let mut root = ApfsNode::directory();
root.add("hello.txt", ApfsNode::file(b"hello\n".to_vec()))?;
root.add("latest", ApfsNode::symlink("hello.txt"))?;
root.add("big", ApfsNode::file_from(open_reader("big.bin")?))?;
format(&mut device, &ApfsOptions::new().with_root(root))?;
```

```text
let mut root = ApfsNode::directory().with_flags(SF_RESTRICTED);
root.add("sealed", ApfsNode::directory().with_owner(0, 0))?;
format(&mut device, &ApfsOptions::new().with_root(root))?;
```

The container is built in one pass like `mkapfs` does: each file in one
contiguous extent, then the trees. Nothing is written when the tree does not
fit (`NoSpace`), a directory holds two names the volume compares equal
(`AlreadyExists`) or a symbolic link target is empty, over 1024 bytes or holds
a NUL (`InvalidInput`). Such a container is not limited by the mutation
budget below and stays writable through `mount_writable`.

A new container has a small budget of mutations, because the writable driver
never reclaims blocks and rebuilds the filesystem tree and the allocation
bitmaps on every change. Creating empty files one at a time on a fresh volume
stopped with `NoSpace` after about 20 files in 1 MiB, 270 in 16 MiB, 710 in
64 MiB and 1,600 in 256 MiB, so size a container for the changes it will take.

Evidence is the independent `apfsutil` and `apfs-fuse` readers, which report
the label and UUIDs and read both key layouts empty and after writes, plus
tests of the layout, interrupted formats and byte-identical sync and async
output. Apple `fsck_apfs` and macOS have not been run against a formatted
container.

## Limitations

- Ordinary mounts are read-only, and repairing volumes is not supported.
  Experimental writes and formatting require the `write` feature, and writes
  the explicit constructors and supported layout described above.
- Compressed files (`decmpfs`) are reported as
  `ErrorKind::Unsupported` rather than decoded.
- Software encryption requires the `encryption` feature and a password mount.
  Secure Enclave/hardware encryption, per-file keys and encryption rolling are
  not qualified. Keybags are capped at 1 MiB and 256 records, and the entire
  password-record search is capped at 1,000,000 PBKDF2 iterations.
- Name comparison uses the Unicode default case folding and canonical
  decomposition rather than Apple's unpublished tables, so a name that
  differs only where the two disagree may not match.
- Snapshots, Fusion tier-2 devices, extended attributes other than symlink
  targets, and named data streams are not exposed.
- Native container path lookup walks the filesystem tree; a keyed query reads
  only the nodes whose key range can hold the records it wants. The mounted
  driver reads a node's records when an operation first needs them and keeps
  them for the nodes in use, so mounting a large volume no longer reads the
  whole filesystem tree. `MountOptions::with_node_limit` caps how many nodes
  are held; an operation that needs one more fails with `LimitExceeded`.

Do not rely on this crate alone for recovery or forensic conclusions from
damaged, adversarial, compressed or encrypted volumes.

## Password unlocking

`ApfsFs::mount_with_password(device, options, password, crypto_user)` mounts a
sole encrypted volume. `mount_volume_with_password` also accepts a
`VolumeSelector`. Passwords are borrowed as byte slices; host prompting and
keychain access belong to the caller. `None` for `crypto_user` searches supported
password records; an explicit UUID restricts that search.

The native `Container::unlock_volume` replaces its unlocked volume, including
when unlocking fails. Cancellation leaves a candidate key uninstalled. Retained
keys are wiped on drop and redacted from diagnostics. Native encrypted reads
require volume-scoped APIs: `read_volume_extents_at` and
`read_volume_btree_node_with_flags`; the existing unscoped methods reject
encrypted inputs. Decrypted objects still undergo checksum and bounds checks.

The [encryption qualification guide](../../../docs/apfs-encryption.md) describes
the native Apple oracle, resource limits and separate Asahi hardware path.

## Example

```rust,no_run
use std::fs::File;

use hadris_apfs::sync::Container;
use hadris_storage::sync::StreamDevice;
use hadris_storage::{BlockCount, BlockGeometry, BlockSize};

let file = File::open("container.img")?;
let sectors = file.metadata()?.len() / 512;
let geometry = BlockGeometry::new(BlockSize::new(512).unwrap(), BlockCount::new(sectors));
let mut container = Container::open(StreamDevice::with_block_count(
    hadris_storage::ReadOnly::new(hadris_io::StdIo::new(file)),
    geometry.logical_block_size(), geometry.block_count().get(),
))?;
let latest = container.latest_superblock()?;
for volume in container.volume_superblocks(&latest)? {
    if let Some(entry) = container.resolve_path(&volume, "/notes.txt")? {
        let data = container.read_file(&volume, entry.file_id, 1 << 20)?;
        println!("{}: {} bytes", volume.name()?, data.len());
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The image must start with the APFS container. For a whole-disk image, open the
APFS partition first, for example with `hadris-part`.

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std`   | Yes     | Standard library support (enables `alloc`) |
| `alloc` | Yes     | Heap allocation; required by the B-tree and file readers |
| `sync`  | Yes     | Synchronous readers in `hadris_apfs::sync` |
| `async` | No      | Unified asynchronous readers in `hadris_apfs::async_` |
| `encryption` | No | Password-based software FileVault unlocking; implies `alloc` |
| `tracing` | No | Operation spans through the `tracing` crate, also without `std` |

## Tracing

The opt-in `tracing` feature emits operation spans through the application’s
subscriber, with or without `std`. It is disabled by default. See the
[tracing guide](../../../docs/tracing.md) for targets, metadata and async behavior.

## Object mappings

Object-map lookups match full object identifiers and select the newest mapping
at or before the requested transaction. A deleted mapping returns no object
without resurrecting an older version. Volume enumeration uses the container
checkpoint transaction to resolve each live volume once; historical and future
mappings remain available through the raw mapping inspection APIs.

## Unified asynchronous API

One filesystem type in `async_` accepts both Send and local devices through
`hadris_storage::async_::BlockDevice`.
It implements `hadris_fs::local::FileSystem` for all compatible devices and the
Send filesystem contract when its device and operation state are Send. The
`async` feature enables both capabilities; no separate local feature is needed.

## Documentation

- [Library API](https://docs.rs/hadris-apfs/3.0.0-rc.2)
- [Unified CLI (`hadris apfs`)](../../tools/hadris-cli/README.md)

## License

Licensed under the [MIT license](../../../LICENSE-MIT).
