#![cfg(all(feature = "write", any(feature = "sync", feature = "async")))]

mod common;
#[cfg(feature = "sync")]
#[path = "common/write_fault.rs"]
mod write_fault;

use hadris_apfs::ApfsOptions;
use hadris_storage::{BlockSize, MemDevice};

const SIZE: usize = 16 << 20;

fn device(bytes: Vec<u8>, block: u32) -> MemDevice<Vec<u8>> {
    MemDevice::new(bytes, BlockSize::new(block).unwrap())
}

fn blank(block: u32) -> MemDevice<Vec<u8>> {
    device(vec![0; SIZE], block)
}

#[cfg(feature = "sync")]
mod sync {
    use super::*;
    use crate::common::BLOCK;
    use crate::common::write as fixture;
    use hadris_apfs::sync::{ApfsFs, format};
    use hadris_fs::{DirCursor, ErrorKind, MountOptions, Name, SetAttr};
    use hadris_storage::sync::BlockDevice;

    fn names<D: BlockDevice>(fs: &mut ApfsFs<D>) -> Vec<Vec<u8>> {
        let root = fs.root();
        let mut out = Vec::new();
        let mut cursor = DirCursor::START;
        while let Some(entry) = fs.readdir(root, cursor).unwrap() {
            cursor = entry.next_cursor();
            out.push(entry.name().as_bytes().to_vec());
        }
        out
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 249) as u8).collect()
    }

    #[test]
    fn formats_an_empty_volume_that_mounts_read_only() {
        let mut dev = blank(4096);
        let options = ApfsOptions::new().with_label("Scratch").with_seed(5);
        let formatted = format(&mut dev, &options).unwrap();
        assert_eq!(formatted.block_count, (SIZE / BLOCK) as u64);

        let mut fs = ApfsFs::mount(dev, MountOptions::new()).unwrap();
        assert_eq!(fs.volume_superblock().volume_id, formatted.volume_uuid);
        let mut label = [0; 32];
        assert_eq!(fs.label(&mut label).unwrap(), Some("Scratch"));
        assert!(names(&mut fs).is_empty());
        assert!(fs.stat(fs.root()).unwrap().file_type().is_dir());
        assert_eq!(
            fs.lookup(fs.root(), Name::new("x")).unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn a_formatted_volume_passes_the_writers_validation_and_takes_writes() {
        for insensitive in [true, false] {
            let mut dev = blank(4096);
            let options = ApfsOptions::new().with_normalization_insensitive(insensitive);
            format(&mut dev, &options).unwrap();
            let mut fs = ApfsFs::mount_writable(dev, MountOptions::new()).unwrap();
            let root = fs.root();
            let dir = fs.mkdir(root, Name::new("docs"), &SetAttr::new()).unwrap();
            let file = fs.create(dir, Name::new("note"), &SetAttr::new()).unwrap();
            let payload = pattern(BLOCK * 2 + 123);
            assert_eq!(fs.write(file, 0, &payload).unwrap(), payload.len());
            fs.sync().unwrap();

            let mut fs = ApfsFs::mount(fs.into_inner(), MountOptions::new()).unwrap();
            let dir = fs.lookup(root, Name::new("docs")).unwrap();
            let file = fs.lookup(dir, Name::new("note")).unwrap();
            let mut back = vec![0; payload.len()];
            assert_eq!(fs.read(file, 0, &mut back).unwrap(), payload.len());
            assert!(back == payload, "insensitive={insensitive}");
            assert_eq!(names(&mut fs), vec![b"docs".to_vec()]);
        }
    }

    #[test]
    fn a_container_spanning_several_bitmap_chunks_is_valid_and_writable() {
        let blocks = 40_960;
        let mut dev = device(vec![0; blocks * BLOCK], 4096);
        let formatted = format(&mut dev, &ApfsOptions::new()).unwrap();
        assert_eq!(formatted.block_count, blocks as u64);
        let mut fs = ApfsFs::mount_writable(dev, MountOptions::new()).unwrap();
        let root = fs.root();
        let file = fs.create(root, Name::new("big"), &SetAttr::new()).unwrap();
        let payload = pattern(BLOCK * 5);
        fs.write(file, 0, &payload).unwrap();
        let mut fs = ApfsFs::mount(fs.into_inner(), MountOptions::new()).unwrap();
        let file = fs.lookup(root, Name::new("big")).unwrap();
        let mut back = vec![0; payload.len()];
        assert_eq!(fs.read(file, 0, &mut back).unwrap(), payload.len());
        assert!(back == payload);
    }

    #[test]
    fn the_device_block_size_does_not_change_the_container() {
        let options = ApfsOptions::new();
        let mut large = blank(4096);
        format(&mut large, &options).unwrap();
        let mut small = blank(512);
        format(&mut small, &options).unwrap();
        let (large, small) = (large.into_inner(), small.into_inner());
        assert!(large == small);

        let mut fs = ApfsFs::mount_writable(device(small, 512), MountOptions::new()).unwrap();
        let root = fs.root();
        let file = fs.create(root, Name::new("a"), &SetAttr::new()).unwrap();
        fs.write(file, 0, b"small blocks").unwrap();
        let mut fs = ApfsFs::mount(fs.into_inner(), MountOptions::new()).unwrap();
        let file = fs.lookup(root, Name::new("a")).unwrap();
        let mut back = [0; 32];
        let n = fs.read(file, 0, &mut back).unwrap();
        assert_eq!(&back[..n], b"small blocks");
    }

    #[test]
    fn format_replaces_an_older_container_and_its_checkpoints() {
        let mut fs =
            ApfsFs::mount_writable(device(fixture::image(), 4096), MountOptions::new()).unwrap();
        let root = fs.root();
        for n in 0..5 {
            let name = format!("old{n}");
            fs.create(root, Name::new(&name), &SetAttr::new()).unwrap();
        }
        let mut dev = fs.into_inner();
        format(&mut dev, &ApfsOptions::new()).unwrap();
        let mut fs = ApfsFs::mount(dev, MountOptions::new()).unwrap();
        assert!(names(&mut fs).is_empty());
        assert_eq!(
            fs.lookup(root, Name::new("existing")).unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn invalid_requests_fail_before_writing() {
        let untouched = vec![0xa5; SIZE];
        let cases = [
            (ApfsOptions::new().with_size(4097), ErrorKind::InvalidInput),
            (ApfsOptions::new().with_label(""), ErrorKind::InvalidInput),
            (
                ApfsOptions::new().with_size(SIZE as u64 * 2),
                ErrorKind::NoSpace,
            ),
            (ApfsOptions::new().with_size(4096 * 10), ErrorKind::NoSpace),
        ];
        for (options, kind) in cases {
            let mut dev = device(untouched.clone(), 4096);
            assert_eq!(format(&mut dev, &options).unwrap_err().kind(), kind);
            assert!(dev.into_inner() == untouched);
        }
        let mut read_only = MemDevice::new(&untouched[..], BlockSize::new(4096).unwrap());
        assert_eq!(
            format(&mut read_only, &ApfsOptions::new())
                .unwrap_err()
                .kind(),
            ErrorKind::ReadOnly
        );
        let mut large_blocks = device(vec![0; SIZE], 8192);
        assert_eq!(
            format(&mut large_blocks, &ApfsOptions::new())
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn an_interrupted_format_never_leaves_a_hybrid_container() {
        use crate::write_fault::FaultDevice;
        let old = fixture::image();
        let mut probe = FaultDevice::from_bytes(old.clone());
        format(&mut probe, &ApfsOptions::new()).unwrap();
        let (mut untouched, mut unmountable, mut complete) = (0, 0, 0);
        for (fail_at, torn) in (0..probe.events).flat_map(|event| [(event, false), (event, true)]) {
            let mut disk = FaultDevice::from_bytes(old.clone());
            disk.fail_at = Some(fail_at);
            disk.torn = torn;
            let error = format(&mut disk, &ApfsOptions::new()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Io, "event {fail_at}");
            let bytes = disk.bytes;
            if bytes == old {
                untouched += 1;
                continue;
            }
            match ApfsFs::mount(device(bytes, 4096), MountOptions::new()) {
                Err(_) => unmountable += 1,
                Ok(mut fs) => {
                    assert!(
                        names(&mut fs).is_empty(),
                        "hybrid container at event {fail_at}, torn {torn}"
                    );
                    complete += 1;
                }
            }
        }
        assert!(
            untouched >= 1,
            "no failure left the old container untouched"
        );
        assert!(
            unmountable >= 10,
            "only {unmountable} interruptions left an unmountable device"
        );
        assert!(
            complete >= 1,
            "no failure happened after the checkpoint was complete"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_host_file_grows_to_the_container_size() {
        use hadris_storage::host::FileDevice;
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path =
            std::env::temp_dir().join(format!("hadris-apfs-format-{}.img", std::process::id()));
        let _cleanup = Cleanup(path.clone());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let mut dev = FileDevice::new(file).unwrap();
        let formatted = format(&mut dev, &ApfsOptions::new().with_size(8 << 20)).unwrap();
        drop(dev);
        assert_eq!(formatted.block_count, 2048);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8 << 20);
        let mut fs = ApfsFs::mount(FileDevice::open(&path).unwrap(), MountOptions::new()).unwrap();
        assert!(names(&mut fs).is_empty());
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use hadris_apfs::async_::{ApfsFs, format};
    use hadris_fs::{MountOptions, Name, SetAttr};
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
    fn async_format_then_writable_mount() {
        block_on(async {
            let mut dev = blank(4096);
            format(&mut dev, &ApfsOptions::new()).await.unwrap();
            let mut fs = ApfsFs::mount_writable(dev, MountOptions::new())
                .await
                .unwrap();
            let root = fs.root();
            let file = fs
                .create(root, Name::new("a"), &SetAttr::new())
                .await
                .unwrap();
            fs.write(file, 0, b"async").await.unwrap();
            let mut fs = ApfsFs::mount(fs.into_inner(), MountOptions::new())
                .await
                .unwrap();
            let file = fs.lookup(root, Name::new("a")).await.unwrap();
            let mut back = [0; 8];
            let n = fs.read(file, 0, &mut back).await.unwrap();
            assert_eq!(&back[..n], b"async");
        });
    }

    #[cfg(feature = "sync")]
    #[test]
    fn async_and_sync_formats_are_byte_identical() {
        let options = ApfsOptions::new().with_label("Same").with_seed(3);
        let mut blocking = blank(4096);
        hadris_apfs::sync::format(&mut blocking, &options).unwrap();
        let mut asynchronous = blank(4096);
        block_on(format(&mut asynchronous, &options)).unwrap();
        assert!(blocking.into_inner() == asynchronous.into_inner());
    }
}
