use std::fmt::{Debug, Display};

use crate::ip_protocol::IpProtocol;

pub struct IPv4Packet<'a> {
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub ident: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> IPv4Packet<'a> {
    /// IPv4 header (RFC 791):
    /// ```
    ///  0               1               2               3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Version|  IHL  |   DSCP  | ECN |         Total Length          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Identification        |Flags|     Fragment Offset     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Time to Live |    Protocol   |        Header Checksum        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Source Address                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                      Destination Address                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] >> 4) & 0xF;
        let ihl = (data[0] >> 0) & 0xF; // in 32-bit words

        if version != 4 {
            return None;
        }

        let header_len = (ihl as usize) * 4;
        if data.len() < header_len {
            return None;
        }

        let dscp = (data[1] >> 2) & 0x3F;
        let ecn = (data[1] >> 0) & 0x03;
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let ident = u16::from_be_bytes([data[4], data[5]]);
        let flags = (data[6] >> 5) & 0x07;
        let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
        let ttl = data[8];
        let protocol = IpProtocol::from(data[9]);
        let checksum = u16::from_be_bytes([data[10], data[11]]);
        let src: [u8; 4] = data[12..16].try_into().unwrap();
        let dst: [u8; 4] = data[16..20].try_into().unwrap();

        // Payload starts after the variable-length header (skip options if present)
        let payload = &data[header_len..total_length as usize];

        Some(Self {
            ihl,
            dscp,
            ecn,
            total_length,
            ident,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source_address: src,
            destination_address: dst,
            payload,
        })
    }

    pub fn fmt_ip(ip: &[u8; 4]) -> String {
        ip.iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }

    /// RFC 1071 one's complement checksum verification
    pub fn verify_checksum(data: &[u8]) -> bool {
        let ihl = ((data[0] & 0xF) as usize) * 4;
        let mut sum: u32 = 0;
        for i in (0..ihl).step_by(2) {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum += word as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }
}

impl<'a> Display for IPv4Packet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv4] {} → {}  TTL: {}  Proto: {:?}  Len: {}",
            Self::fmt_ip(&self.source_address),
            Self::fmt_ip(&self.destination_address),
            self.ttl,
            self.protocol,
            self.total_length
        )
    }
}

impl<'a> Debug for IPv4Packet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv4] {} → {}  IHL: {}  DSCP: {}  ECN: {}  Len: {}  ID: {}  Flags: {}  Fragment Offset: {}  TTL: {}  Proto: {:?}  Checksum: {}  Payload: {:?}",
            Self::fmt_ip(&self.source_address),
            Self::fmt_ip(&self.destination_address),
            self.ihl,
            self.dscp,
            self.ecn,
            self.total_length,
            self.ident,
            self.flags,
            self.fragment_offset,
            self.ttl,
            self.protocol,
            self.checksum,
            self.payload
        )
    }
}
