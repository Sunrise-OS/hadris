io_transform! {
use super::storage::BlockDevice;
use crate::write::BLOCK;
use crate::write::mkfs::{ApfsOptions, Formatted, Plan};
use crate::write::tree::Content;
use alloc::vec;
use hadris_fs::{ErrorKind, FsResult};
use hadris_storage::BlockIndex;

/// Zeroed blocks written in one request.
const ZERO_RUN: usize = 32;

async fn put<D: BlockDevice>(dev: &mut D, block: u64, data: &[u8]) -> FsResult<(), D::Error> {
    let factor = BLOCK as u64 / u64::from(dev.block_size().get());
    dev.write_blocks(BlockIndex::new(block * factor), data).await
}

/// Fills `buf` from `content` at `offset`, which must hold that many more
/// bytes.
fn read_source<E>(content: &Content, mut offset: u64, buf: &mut [u8]) -> FsResult<(), E> {
    let mut done = 0;
    while done < buf.len() {
        match content.read_at(offset, &mut buf[done..])? {
            0 => return Err(ErrorKind::Corrupt.into()),
            n => {
                done += n;
                offset += n as u64;
            }
        }
    }
    Ok(())
}

async fn zero<D: BlockDevice>(dev: &mut D, zeros: &[u8], first: u64, count: u64) -> FsResult<(), D::Error> {
    let run = (zeros.len() / BLOCK) as u64;
    let end = first + count;
    let mut at = first;
    while at < end {
        let n = run.min(end - at);
        put(dev, at, &zeros[..n as usize * BLOCK]).await?;
        at += n;
    }
    Ok(())
}

/// Formats `dev` as an APFS container holding one empty, unencrypted,
/// case-sensitive volume, and returns what it created.
///
/// The container fills the device, rounded down to whole 4096-byte blocks,
/// unless [`ApfsOptions::with_size`] asks for another size; a growable
/// device is grown to the container's end. Pass a `hadris_storage`
/// `Partition` to format a partition. The volume holds the root directory
/// and the private directory APFS keeps beside it, and nothing else. Mount it
/// with `ApfsFs::mount`, or with `ApfsFs::mount_writable` to add files.
///
/// Block 0 and the checkpoint areas are overwritten first, so no older
/// container on the device survives, and the device is flushed before the new
/// checkpoint is published and again after block 0 is written last. Space
/// beyond the metadata is left as it is. A format that fails or is
/// interrupted leaves a device that does not mount.
///
/// Fails with [`ErrorKind::InvalidInput`] for a label or time that is out of
/// range or a size that is not a multiple of 4096, with
/// [`ErrorKind::NoSpace`] when the device is too small for the container,
/// with [`ErrorKind::LimitExceeded`] when the container is larger than the
/// space manager layout holds (about 3 TiB), with [`ErrorKind::Unsupported`]
/// when the device's blocks are not 512, 1024, 2048 or 4096 bytes or its
/// physical blocks are larger than 4096 bytes, and with
/// [`ErrorKind::ReadOnly`] when it refuses writes. Nothing is written unless
/// the options are valid.
#[cfg_attr(feature = "tracing", tracing::instrument(target = "hadris::apfs", level = "trace", skip_all))]
pub async fn format<D: BlockDevice>(dev: &mut D, options: &ApfsOptions) -> FsResult<Formatted, D::Error> {
    let device_block = u64::from(dev.block_size().get());
    let physical = u64::from(dev.physical_block_size().get());
    if !matches!(device_block, 512 | 1024 | 2048 | 4096)
        || physical > BLOCK as u64
        || BLOCK as u64 % physical != 0
    {
        return Err(ErrorKind::Unsupported.into());
    }
    if !dev.writable() {
        return Err(ErrorKind::ReadOnly.into());
    }
    let device_bytes = dev.block_count().saturating_mul(device_block);
    let size = match options.size {
        None => device_bytes / BLOCK as u64 * BLOCK as u64,
        Some(size) => {
            if size > device_bytes && size > dev.max_block_count().saturating_mul(device_block) {
                return Err(ErrorKind::NoSpace.into());
            }
            size
        }
    };
    let mut plan = Plan::new(options, size)?;
    let blocks = plan.blocks()?;

    let zeros = vec![0_u8; ZERO_RUN * BLOCK];
    let mut scratch = vec![0_u8; ZERO_RUN * BLOCK];
    if device_bytes < size {
        zero(dev, &zeros, plan.last_block(), 1).await?;
    }
    zero(dev, &zeros, 0, 1).await?;
    let areas = plan.areas();
    zero(dev, &zeros, areas.start, areas.end - areas.start).await?;
    for (block, data) in &blocks {
        put(dev, *block, data).await?;
    }
    for (block, content) in plan.data(options) {
        let len = content.len();
        let mut at = block;
        let mut offset = 0;
        while offset < len {
            let want = ((len - offset) as usize).min(scratch.len());
            read_source(content, offset, &mut scratch[..want])?;
            let whole = want / BLOCK * BLOCK;
            if whole > 0 {
                put(dev, at, &scratch[..whole]).await?;
            }
            if whole < want {
                let tail = whole + BLOCK;
                scratch[want..tail].fill(0);
                put(dev, at + (whole / BLOCK) as u64, &scratch[whole..tail]).await?;
            }
            offset += want as u64;
            at += want.div_ceil(BLOCK) as u64;
        }
    }
    let live = plan.used_chunks();
    for chunk in 0..live {
        put(dev, plan.bitmap_start + chunk, &plan.bitmap(chunk)).await?;
    }
    zero(dev, &zeros, plan.bitmap_start + live, plan.chunk_count - live).await?;
    dev.flush().await?;

    let superblock = plan.superblock();
    put(dev, plan.checkpoint_block(), &superblock).await?;
    dev.flush().await?;
    put(dev, 0, &superblock).await?;
    dev.flush().await?;
    Ok(plan.formatted())
}
}
