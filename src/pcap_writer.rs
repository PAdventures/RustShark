use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PcapWriter {
    writer: BufWriter<File>,
}

enum Endianness {
    Little,
    Big,
}

fn native_endianness() -> Endianness {
    if u16::from_ne_bytes([0x01, 0x00]) == 1 {
        Endianness::Little
    } else {
        Endianness::Big
    }
}

fn write_u16_ne(w: &mut BufWriter<File>, v: u16) -> std::io::Result<()> {
    w.write_all(&v.to_ne_bytes())
}

fn write_u32_ne(w: &mut BufWriter<File>, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_ne_bytes())
}

impl PcapWriter {
    pub fn create(path: &str, snaplen: u32, link_type: u32) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        Self::write_global_header(&mut writer, snaplen, link_type)?;

        Ok(Self { writer })
    }

    fn write_global_header(
        w: &mut BufWriter<File>,
        snaplen: u32,
        link_type: u32,
    ) -> std::io::Result<()> {
        let magic = match native_endianness() {
            Endianness::Little => 0xA1B2C3D4u32,
            Endianness::Big => 0xA1B2C3D4u32,
        };

        write_u32_ne(w, magic)?;
        write_u16_ne(w, 2)?;
        write_u16_ne(w, 4)?;
        write_u32_ne(w, 0)?;
        write_u32_ne(w, 0)?;
        write_u32_ne(w, snaplen)?;
        write_u32_ne(w, link_type)?;
        Ok(())
    }

    pub fn write_packet(&mut self, data: &[u8], orig_len: u32) -> std::io::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let ts_sec = now.as_secs() as u32;
        let ts_usec = now.subsec_micros();
        let cap_len = data.len() as u32;

        write_u32_ne(&mut self.writer, ts_sec)?;
        write_u32_ne(&mut self.writer, ts_usec)?;
        write_u32_ne(&mut self.writer, cap_len)?;
        write_u32_ne(&mut self.writer, orig_len)?;
        self.writer.write_all(data)?;

        Ok(())
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

pub mod link_type {
    pub const ETHERNET: u32 = 1;
    pub const RAW_IP: u32 = 101;
    pub const LINUX_SLL: u32 = 113;
    pub const NULL: u32 = 0;
}
