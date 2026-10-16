use crate::common::BLOCK;
use crate::common::write::image;
use hadris_io::{Error, ErrorKind};
use hadris_storage::{BlockIndex, BlockSize};

pub struct FaultDevice {
    pub bytes: Vec<u8>,
    pub events: usize,
    pub fail_at: Option<usize>,
    pub torn: bool,
}

impl FaultDevice {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::from_bytes(image())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            events: 0,
            fail_at: None,
            torn: false,
        }
    }

    fn step(&mut self) -> Result<(), Error<core::convert::Infallible>> {
        let event = self.events;
        self.events += 1;
        if self.fail_at == Some(event) {
            Err(Error::new(
                ErrorKind::Io,
                "injected transaction interruption",
            ))
        } else {
            Ok(())
        }
    }
}

impl hadris_io::ErrorType for FaultDevice {
    type Error = core::convert::Infallible;
}

impl hadris_storage::sync::BlockDevice for FaultDevice {
    fn block_size(&self) -> BlockSize {
        BlockSize::new(BLOCK as u32).unwrap()
    }
    fn block_count(&self) -> u64 {
        (self.bytes.len() / BLOCK) as u64
    }
    fn writable(&self) -> bool {
        true
    }
    fn read_blocks(&mut self, first: BlockIndex, buf: &mut [u8]) -> Result<(), Error<Self::Error>> {
        let start = first.get() as usize * BLOCK;
        buf.copy_from_slice(&self.bytes[start..start + buf.len()]);
        Ok(())
    }
    fn write_blocks(&mut self, first: BlockIndex, buf: &[u8]) -> Result<(), Error<Self::Error>> {
        let result = self.step();
        let start = first.get() as usize * BLOCK;
        if result.is_err() {
            if self.torn {
                let len = buf.len() / 2;
                self.bytes[start..start + len].copy_from_slice(&buf[..len]);
            }
            return result;
        }
        self.bytes[start..start + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error<Self::Error>> {
        self.step()
    }
}
