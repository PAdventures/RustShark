use std::fmt::{Debug, Display};

use bytes::Bytes;
use libc::timeval;

use crate::{
    network::ip_protocol::IpProtocol,
    traits::Protocol,
    transport::{
        TransportPacket, icmp::IcmpPacket, igmp::IgmpMessage, tcp::TcpSegment, udp::UdpDatagram,
    },
    utils::{self, timeval_to_string},
};

#[derive(Clone)]
pub struct IPv4Packet {
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
    pub payload: Option<TransportPacket>,
    pub raw_payload: Bytes,
}

impl IPv4Packet {
    /// RFC 1071 one's complement checksum verification
    pub fn verify_checksum(data: Bytes) -> bool {
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

impl Protocol for IPv4Packet {
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
    fn parse(data: Bytes) -> Option<Self> {
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
            payload: None, // To be parsed later by higher layers
            raw_payload: data.slice(header_len..total_length as usize),
        })
    }

    fn format_protocol(count: u64, ts: timeval, protocol: Self) -> String {
        if let Some(payload) = protocol.to_owned().payload {
            match payload {
                TransportPacket::TCP(tcp) => return TcpSegment::format_protocol(count, ts, tcp),
                TransportPacket::UDP(udp) => return UdpDatagram::format_protocol(count, ts, udp),
                TransportPacket::ICMP(icmp) => return IcmpPacket::format_protocol(count, ts, icmp),
                TransportPacket::IGMP(igmp) => {
                    return IgmpMessage::format_protocol(count, ts, igmp);
                }
                _ => (),
            }
        }

        format!("{count} {} {}", timeval_to_string(ts), protocol.to_string())
    }
}

impl Display for IPv4Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv4] {} → {} TTL={} Proto={:?} Len={}",
            utils::format_ipv4(&self.source_address),
            utils::format_ipv4(&self.destination_address),
            self.ttl,
            self.protocol,
            self.total_length
        )
    }
}

impl Debug for IPv4Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv4] {} → {} IHL={} DSCP={} ECN={} Len={} ID={} Flags={} Fragment Offset={} TTL={} Proto={:?} Checksum={} Payload={:?}",
            utils::format_ipv4(&self.source_address),
            utils::format_ipv4(&self.destination_address),
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
            self.raw_payload
        )
    }
}
