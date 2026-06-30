use std::fmt::{Debug, Display};

use bytes::Bytes;

use crate::{
    network::ip_protocol::IpProtocol,
    traits::Protocol,
    transport::{
        TransportPacket, icmp::IcmpPacket, igmp::IgmpMessage, tcp::TcpSegment, udp::UdpDatagram,
    },
    utils,
};

#[derive(Clone, PartialEq)]
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
        if data.len() < 20 {
            return false;
        }
        let ihl = ((data[0] & 0xF) as usize) * 4;
        if ihl < 20 || data.len() < ihl || ihl % 2 != 0 {
            return false;
        }
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

        if version != 4 || ihl < 5 {
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
        let total_len = total_length as usize;

        if total_len < header_len || data.len() < total_len {
            return None;
        }

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
            raw_payload: data.slice(header_len..total_len),
        })
    }

    fn format_protocol(protocol: Self) -> String {
        if let Some(payload) = protocol.to_owned().payload {
            match payload {
                TransportPacket::TCP(tcp) => return TcpSegment::format_protocol(tcp),
                TransportPacket::UDP(udp) => return UdpDatagram::format_protocol(udp),
                TransportPacket::ICMP(icmp) => return IcmpPacket::format_protocol(icmp),
                TransportPacket::IGMP(igmp) => {
                    return IgmpMessage::format_protocol(igmp);
                }
                _ => (),
            }
        }

        protocol.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> Bytes {
        Bytes::from_static(&[
            0x45, 0x00, 0x00, 0x18, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
            192, 168, 1, 2, 0xde, 0xad, 0xbe, 0xef,
        ])
    }

    #[test]
    fn parses_valid_ipv4_packet() {
        let parsed = IPv4Packet::parse(packet()).unwrap();

        assert_eq!(parsed.ihl, 5);
        assert_eq!(parsed.total_length, 24);
        assert_eq!(parsed.protocol, IpProtocol::TCP);
        assert_eq!(parsed.source_address, [192, 168, 1, 1]);
        assert_eq!(parsed.destination_address, [192, 168, 1, 2]);
        assert_eq!(
            parsed.raw_payload,
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn rejects_ipv4_boundary_and_invalid_lengths() {
        assert!(IPv4Packet::parse(Bytes::from_static(&[0; 19])).is_none());

        let mut wrong_version = packet().to_vec();
        wrong_version[0] = 0x65;
        assert!(IPv4Packet::parse(Bytes::from(wrong_version)).is_none());

        let mut ihl_too_small = packet().to_vec();
        ihl_too_small[0] = 0x44;
        assert!(IPv4Packet::parse(Bytes::from(ihl_too_small)).is_none());

        let mut total_too_short = packet().to_vec();
        total_too_short[3] = 19;
        assert!(IPv4Packet::parse(Bytes::from(total_too_short)).is_none());

        let mut total_too_long = packet().to_vec();
        total_too_long[3] = 25;
        assert!(IPv4Packet::parse(Bytes::from(total_too_long)).is_none());
    }

    #[test]
    fn checksum_verification_rejects_short_headers() {
        assert!(!IPv4Packet::verify_checksum(Bytes::from_static(&[
            0x45, 0x00
        ])));
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
