use std::fmt::{Debug, Display};

use bytes::Bytes;

use crate::{
    network::ip_protocol::IpProtocol,
    traits::Protocol,
    transport::{TransportPacket, icmpv6::Icmpv6Packet, tcp::TcpSegment, udp::UdpDatagram},
    utils,
};

#[derive(Clone, PartialEq)]
pub struct IPv6Packet {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub payload: Option<TransportPacket>,
    pub raw_payload: Bytes,
}

impl Protocol for IPv6Packet {
    /// IPv6 fixed header (RFC 8200) is always 40 bytes:
    /// ```
    ///  0               1               2               3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Version| Traffic Class |            Flow Label                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Payload Length        |  Next Header  |   Hop Limit   |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Source Address                        |
    /// |                          (128 bits)                           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                      Destination Address                      |
    /// |                          (128 bits)                           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let version = (data[0] >> 4) & 0xF;

        if version != 6 {
            return None;
        }

        let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
        let flow_label = u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]);
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let mut next_header = IpProtocol::from(data[6]);
        let hop_limit = data[7];
        let src: [u8; 16] = data[8..24].try_into().unwrap();
        let dst: [u8; 16] = data[24..40].try_into().unwrap();

        let mut offset = 40;

        match next_header {
            IpProtocol::IPv6HopByHop => {
                if data.len() < offset + 2 {
                    return None;
                }
                let hbh_next_header = IpProtocol::from(data[offset]);
                let hbh_len = (data[offset + 1] as usize + 1) * 8;
                if data.len() < offset + hbh_len {
                    return None;
                }
                next_header = hbh_next_header;
                offset += hbh_len;
            }
            _ => (),
        }

        if data.len() < 40 + payload_length as usize || offset > data.len() {
            return None;
        }

        Some(Self {
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source_address: src,
            destination_address: dst,
            payload: None, // To be parsed later by higher layers
            raw_payload: data.slice(offset..),
        })
    }

    fn format_protocol(protocol: Self) -> String {
        if let Some(payload) = protocol.to_owned().payload {
            match payload {
                TransportPacket::TCP(tcp) => return TcpSegment::format_protocol(tcp),
                TransportPacket::UDP(udp) => return UdpDatagram::format_protocol(udp),
                TransportPacket::ICMPv6(icmpv6) => {
                    return Icmpv6Packet::format_protocol(icmpv6);
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

    fn packet() -> Vec<u8> {
        let mut data = vec![0x6a, 0xbc, 0xde, 0xf0, 0x00, 0x04, 0x11, 0x40];
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        data.extend_from_slice(&[1, 2, 3, 4]);
        data
    }

    #[test]
    fn parses_valid_ipv6_packet() {
        let parsed = IPv6Packet::parse(Bytes::from(packet())).unwrap();

        assert_eq!(parsed.traffic_class, 0xab);
        assert_eq!(parsed.flow_label, 0x0cdef0);
        assert_eq!(parsed.payload_length, 4);
        assert_eq!(parsed.next_header, IpProtocol::UDP);
        assert_eq!(parsed.raw_payload, Bytes::from_static(&[1, 2, 3, 4]));
    }

    #[test]
    fn rejects_ipv6_boundary_and_invalid_lengths() {
        assert!(IPv6Packet::parse(Bytes::from_static(&[0; 39])).is_none());

        let mut wrong_version = packet();
        wrong_version[0] = 0x40;
        assert!(IPv6Packet::parse(Bytes::from(wrong_version)).is_none());

        let mut payload_too_long = packet();
        payload_too_long[5] = 5;
        assert!(IPv6Packet::parse(Bytes::from(payload_too_long)).is_none());
    }

    #[test]
    fn rejects_truncated_hop_by_hop_extension() {
        let mut data = packet();
        data[6] = 0;
        data[40] = 17;
        data[41] = 1;
        assert!(IPv6Packet::parse(Bytes::from(data)).is_none());
    }
}

impl Display for IPv6Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv6] {} → {} Hop={} Next={:?} Len={}",
            utils::format_ipv6(&self.source_address),
            utils::format_ipv6(&self.destination_address),
            self.hop_limit,
            self.next_header,
            self.payload_length
        )
    }
}

impl Debug for IPv6Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv6] {} → {} Traffic Class={} Flow Label={} Len={} Next={:?} Hop={} Payload={:?}",
            utils::format_ipv6(&self.source_address),
            utils::format_ipv6(&self.destination_address),
            self.traffic_class,
            self.flow_label,
            self.payload_length,
            self.next_header,
            self.hop_limit,
            self.raw_payload
        )
    }
}
