#![cfg(all(feature = "write", any(feature = "sync", feature = "async")))]

mod common;
#[cfg(feature = "sync")]
#[path = "common/write_fault.rs"]
mod write_fault;
use common::write as fixture;

use common::BLOCK;
use hadris_fs::{ErrorKind, MountOptions, Name, SetAttr};
#[cfg(feature = "sync")]
use hadris_fs::{OpenMode, Permissions, RenameMode};
use hadris_storage::{BlockSize, MemDevice};

fn device(image: Vec<u8>) -> MemDevice<Vec<u8>> {
    MemDevice::new(image, BlockSize::new(BLOCK as u32).unwrap())
}

#[cfg(feature = "sync")]
mod sync {
    use super::*;
    use hadris_apfs::sync::ApfsFs;

    fn reopen(fs: ApfsFs<MemDevice<Vec<u8>>>) -> ApfsFs<MemDevice<Vec<u8>>> {
        ApfsFs::mount_writable(fs.into_container().into_inner(), MountOptions::new()).unwrap()
    }

    #[test]
    fn empty_unicode_file_survives_reopen() {
        let mut fs = ApfsFs::mount_writable(device(fixture::image()), MountOptions::new()).unwrap();
        let root = fs.root();
        let node = fs.create(root, Name::new("δ"), &SetAttr::new()).unwrap();
        let mut fs = reopen(fs);
        assert_eq!(fs.lookup(root, Name::new("δ")).unwrap(), node);
        let stat = fs.stat(node).unwrap();
        assert_eq!(stat.len(), 0);
        assert_eq!(stat.allocated(), 0);
        let mut bytes = [0xff; 8];
        assert_eq!(fs.read(node, 0, &mut bytes).unwrap(), 0);
        assert_eq!(bytes, [0xff; 8]);
    }

    #[test]
    fn mutations_survive_checkpoint_ring_wrap_and_reopen() {
        let mut fs = ApfsFs::mount_writable(device(fixture::image()), MountOptions::new()).unwrap();
        let root = fs.root();
        let original = fs.lookup(root, Name::new("existing")).unwrap();
        let mut bytes = [0; 64];
        let n = fs.read(original, 0, &mut bytes).unwrap();
        assert_eq!(&bytes[..n], fixture::ORIGINAL);
        let dir = fs
            .mkdir(root, Name::new("newdir"), &SetAttr::new())
            .unwrap();
        let file = fs.create(dir, Name::new("file"), &SetAttr::new()).unwrap();
        let payload: Vec<_> = (0..BLOCK * 3 + 17).map(|i| (i % 251) as u8).collect();
        assert_eq!(fs.write(file, 7, &payload).unwrap(), payload.len());
        fs.fsync(file).unwrap();
        fs = reopen(fs);
        let mut actual = vec![0xff; payload.len() + 7];
        assert_eq!(fs.read(file, 0, &mut actual).unwrap(), actual.len());
        assert_eq!(&actual[..7], &[0; 7]);
        assert_eq!(&actual[7..], payload);
        fs.truncate(file, BLOCK as u64 + 3).unwrap();
        fs.truncate(file, BLOCK as u64 * 2).unwrap();
        fs.setattr(
            file,
            &SetAttr::new().with_permissions(Permissions::new(0o600)),
        )
        .unwrap();
        fs.rename(
            dir,
            Name::new("file"),
            root,
            Name::new("renamed"),
            RenameMode::Replace,
        )
        .unwrap();
        fs = reopen(fs);
        assert_eq!(fs.lookup(root, Name::new("renamed")).unwrap(), file);
        assert_eq!(
            fs.lookup(dir, Name::new("file")).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(fs.stat(file).unwrap().permissions().bits(), 0o600);
        let mut actual = vec![0xff; BLOCK * 2];
        assert_eq!(fs.read(file, 0, &mut actual).unwrap(), BLOCK * 2);
        assert_eq!(&actual[..7], &[0; 7]);
        assert_eq!(&actual[7..BLOCK + 3], &payload[..BLOCK - 4]);
        assert!(actual[BLOCK + 3..].iter().all(|&byte| byte == 0));
        fs.open(file, OpenMode::Read).unwrap();
        assert_eq!(
            fs.unlink(root, Name::new("renamed")).unwrap_err().kind(),
            ErrorKind::Busy
        );
        fs.close(file).unwrap();
        fs.forget(file, u64::MAX);
        fs.unlink(root, Name::new("renamed")).unwrap();
        fs.forget(dir, u64::MAX);
        fs.rmdir(root, Name::new("newdir")).unwrap();
        fs.sync().unwrap();
        fs = reopen(fs);
        assert_eq!(
            fs.lookup(root, Name::new("renamed")).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            fs.lookup(root, Name::new("newdir")).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        let n = fs.read(original, 0, &mut bytes).unwrap();
        assert_eq!(&bytes[..n], fixture::ORIGINAL);
    }

    #[test]
    fn ordinary_mount_never_enables_writes() {
        let mut fs = ApfsFs::mount(device(common::build_image()), MountOptions::new()).unwrap();
        assert_eq!(
            fs.create(fs.root(), Name::new("no"), &SetAttr::new())
                .unwrap_err()
                .kind(),
            ErrorKind::ReadOnly
        );
        assert_eq!(
            fs.into_container().into_inner().into_inner(),
            common::build_image()
        );
    }
    #[test]
    fn unsupported_volume_features_are_rejected_without_writes() {
        for (offset, value) in [(56, 1_u64), (216, 1), (264, 0)] {
            let mut image = fixture::image();
            let volume = &mut image[69 * BLOCK..70 * BLOCK];
            volume[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            let checksum = hadris_apfs::types::checksum::fletcher64(volume).unwrap();
            volume[..8].copy_from_slice(&checksum.to_le_bytes());
            let error =
                ApfsFs::mount_writable(device(image.clone()), MountOptions::new()).unwrap_err();
            let (error, device) = error.into_parts();
            assert_eq!(error.kind(), ErrorKind::Unsupported, "offset {offset}");
            assert_eq!(device.into_inner(), image);
        }
    }

    fn seal_block(image: &mut [u8], block: usize) {
        let bytes = &mut image[block * BLOCK..(block + 1) * BLOCK];
        let checksum = hadris_apfs::types::checksum::fletcher64(bytes).unwrap();
        bytes[..8].copy_from_slice(&checksum.to_le_bytes());
    }

    #[test]
    fn live_extent_marked_free_is_rejected_before_writing() {
        let mut image = fixture::image();
        image[63 * BLOCK + 61 / 8] &= !(1 << (61 % 8));
        let free = (fixture::BLOCK_COUNT - 72 + 1) as u64;
        image[62 * BLOCK + 60..62 * BLOCK + 64].copy_from_slice(&(free as u32).to_le_bytes());
        image[9 * BLOCK + 72..9 * BLOCK + 80].copy_from_slice(&free.to_le_bytes());
        seal_block(&mut image, 62);
        seal_block(&mut image, 9);
        let (error, device) = ApfsFs::mount_writable(device(image.clone()), MountOptions::new())
            .unwrap_err()
            .into_parts();
        assert_eq!(error.kind(), ErrorKind::Corrupt);
        assert_eq!(device.into_inner(), image);
    }

    #[test]
    fn exhausted_allocation_leaves_the_current_checkpoint_unchanged() {
        let mut image = fixture::image();
        image[63 * BLOCK..63 * BLOCK + fixture::BLOCK_COUNT / 8].fill(0xff);
        image[62 * BLOCK + 60..62 * BLOCK + 64].fill(0);
        image[9 * BLOCK + 72..9 * BLOCK + 80].fill(0);
        seal_block(&mut image, 62);
        seal_block(&mut image, 9);
        let mut fs = ApfsFs::mount_writable(device(image.clone()), MountOptions::new()).unwrap();
        let node = fs.lookup(fs.root(), Name::new("existing")).unwrap();
        assert_eq!(
            fs.write(node, 0, b"changed").unwrap_err().kind(),
            ErrorKind::NoSpace
        );
        assert_eq!(fs.into_inner().into_inner(), image);
    }

    #[test]
    fn interrupted_checkpoint_reopens_as_one_complete_version() {
        use crate::write_fault::FaultDevice;
        let replacement = vec![0x5a; BLOCK * 2 + 31];
        let mut baseline = ApfsFs::mount_writable(FaultDevice::new(), MountOptions::new()).unwrap();
        let node = baseline
            .lookup(baseline.root(), Name::new("existing"))
            .unwrap();
        baseline.write(node, 0, &replacement).unwrap();
        let events = baseline.into_inner().events;
        for (fail_at, torn) in (0..events).flat_map(|event| [(event, false), (event, true)]) {
            let mut disk = FaultDevice::new();
            disk.fail_at = Some(fail_at);
            disk.torn = torn;
            let mut fs = ApfsFs::mount_writable(disk, MountOptions::new()).unwrap();
            let node = fs.lookup(fs.root(), Name::new("existing")).unwrap();
            assert_eq!(
                fs.write(node, 0, &replacement).unwrap_err().kind(),
                ErrorKind::Io,
                "event {fail_at}"
            );
            assert_eq!(
                fs.write(node, 0, b"retry").unwrap_err().kind(),
                ErrorKind::ReadOnly
            );
            let mut disk = fs.into_inner();
            disk.fail_at = None;
            let mut fs = ApfsFs::mount(device(disk.bytes), MountOptions::new()).unwrap();
            let node = fs.lookup(fs.root(), Name::new("existing")).unwrap();
            let len = fs.stat(node).unwrap().len() as usize;
            let mut bytes = vec![0; len];
            assert_eq!(fs.read(node, 0, &mut bytes).unwrap(), len);
            assert!(
                bytes == fixture::ORIGINAL || bytes == replacement,
                "mixed transaction at event {fail_at}"
            );
        }
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use hadris_apfs::async_::ApfsFs;
    use std::task::{Context, Poll, Waker};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn asynchronous_write_growth_and_reopen() {
        block_on(async {
            let mut fs = ApfsFs::mount_writable(device(fixture::image()), MountOptions::new())
                .await
                .unwrap();
            let root = fs.root();
            let node = fs
                .create(root, Name::new("async"), &SetAttr::new())
                .await
                .unwrap();
            let expected = vec![0x73; BLOCK * 2 + 9];
            fs.write(node, 3, &expected).await.unwrap();
            let disk = fs.unmount().await.unwrap();
            let mut fs = ApfsFs::mount_writable(disk, MountOptions::new())
                .await
                .unwrap();
            assert_eq!(fs.lookup(root, Name::new("async")).await.unwrap(), node);
            let mut actual = vec![0xff; expected.len() + 3];
            assert_eq!(fs.read(node, 0, &mut actual).await.unwrap(), actual.len());
            assert_eq!(&actual[..3], &[0; 3]);
            assert_eq!(&actual[3..], expected);
            fs.truncate(node, 0).await.unwrap();
            fs.forget(node, u64::MAX);
            fs.unlink(root, Name::new("async")).await.unwrap();
            let mut fs = ApfsFs::mount(fs.into_inner(), MountOptions::new())
                .await
                .unwrap();
            assert_eq!(
                fs.lookup(root, Name::new("async"))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::NotFound
            );
        });
    }

    struct PendingDevice(MemDevice<Vec<u8>>);
    impl hadris_io::ErrorType for PendingDevice {
        type Error = core::convert::Infallible;
    }
    impl hadris_storage::async_::BlockDevice for PendingDevice {
        type State = ();
        fn cancel(&mut self, _: &mut ()) {}
        fn block_size(&self) -> BlockSize {
            BlockSize::new(BLOCK as u32).unwrap()
        }
        fn block_count(&self) -> u64 {
            fixture::BLOCK_COUNT as u64
        }
        fn writable(&self) -> bool {
            true
        }
        fn poll_read_blocks(
            &mut self,
            state: &mut (),
            cx: &mut Context<'_>,
            first: hadris_storage::BlockIndex,
            buf: &mut [u8],
        ) -> Poll<Result<(), hadris_io::Error<Self::Error>>> {
            hadris_storage::async_::BlockDevice::poll_read_blocks(
                &mut self.0,
                state,
                cx,
                first,
                buf,
            )
        }
        fn poll_write_blocks(
            &mut self,
            _: &mut (),
            _: &mut Context<'_>,
            _: hadris_storage::BlockIndex,
            _: &[u8],
        ) -> Poll<Result<(), hadris_io::Error<Self::Error>>> {
            Poll::Pending
        }
    }

    #[test]
    fn cancelled_write_requires_reopening_before_another_mutation() {
        block_on(async {
            let mut fs = ApfsFs::mount_writable(
                PendingDevice(device(fixture::image())),
                MountOptions::new(),
            )
            .await
            .unwrap();
            let node = fs.lookup(fs.root(), Name::new("existing")).await.unwrap();
            {
                let mut transaction = std::pin::pin!(fs.write(node, 0, b"changed"));
                let mut context = Context::from_waker(Waker::noop());
                assert!(transaction.as_mut().poll(&mut context).is_pending());
            }
            assert_eq!(
                fs.write(node, 0, b"retry").await.unwrap_err().kind(),
                ErrorKind::ReadOnly
            );
            let mut fs = ApfsFs::mount(fs.into_inner().0, MountOptions::new())
                .await
                .unwrap();
            let mut bytes = [0; 64];
            let n = fs.read(node, 0, &mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], fixture::ORIGINAL);
        });
    }
}
