use std::fmt::{Debug, Display};

use bytes::Bytes;

use crate::{
    network::{NetworkPacket, arp::ArpPacket, ipv4::IPv4Packet, ipv6::IPv6Packet},
    traits::Protocol,
    utils,
};

#[derive(Clone, PartialEq)]
pub struct EthernetFrame {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ether_type: EtherType,
    pub payload: Option<NetworkPacket>,
    pub raw_payload: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(v: u16) -> Self {
        match v {
            0x0800 => Self::IPv4,
            0x0806 => Self::ARP,
            0x86DD => Self::IPv6,
            other => Self::Unknown(other),
        }
    }
}

impl Protocol for EthernetFrame {
    /// Ethernet Type II frame:
    ///
    /// 6 dst MAC | 6 src MAC | 2 EtherType
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        let destination_mac: [u8; 6] = data[0..6].try_into().unwrap();
        let source_mac: [u8; 6] = data[6..12].try_into().unwrap();
        let ether_type: EtherType = u16::from_be_bytes([data[12], data[13]]).into();

        Some(Self {
            destination_mac,
            source_mac,
            ether_type,
            payload: None, // To be parsed later by higher layers
            raw_payload: data.slice(14..),
        })
    }

    fn format_protocol(protocol: Self) -> String {
        if let Some(payload) = protocol.payload {
            match payload {
                NetworkPacket::IPv4(ipv4) => IPv4Packet::format_protocol(ipv4),
                NetworkPacket::IPv6(ipv6) => IPv6Packet::format_protocol(ipv6),
                NetworkPacket::ARP(arp) => ArpPacket::format_protocol(arp),
            }
        } else {
            protocol.to_string()
        }
    }
}

impl Display for EthernetFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[Ethernet II] {} -> {} Type={:?}",
            utils::format_mac(&self.source_mac),
            utils::format_mac(&self.destination_mac),
            self.ether_type
        )
    }
}

impl Debug for EthernetFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[Ethernet II] {} -> {} Type={:?} Payload={:?}",
            utils::format_mac(&self.source_mac),
            utils::format_mac(&self.destination_mac),
            self.ether_type,
            self.raw_payload
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ether_type() {
        let ipv4 = 0x0800;
        let ipv6 = 0x86DD;
        let arp = 0x0806;
        let other = 0xFFFF;

        assert_eq!(EtherType::IPv4, EtherType::from(ipv4));
        assert_eq!(EtherType::IPv6, EtherType::from(ipv6));
        assert_eq!(EtherType::ARP, EtherType::from(arp));
        assert_eq!(EtherType::Unknown(other), EtherType::from(other));
    }

    #[test]
    fn parse_ethernet_frame() {
        let expected = EthernetFrame {
            destination_mac: [0, 0, 0, 0, 0, 0],
            source_mac: [0, 0, 0, 0, 0, 1],
            ether_type: EtherType::IPv4,
            payload: None,
            raw_payload: Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]),
        };
        let raw: Bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // destination_mac
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // source mac
            0x08, 0x00, // ether type
            0x01, 0x02, 0x03, 0x04, // payload (dummy data)
        ]);

        let parsed_option = EthernetFrame::parse(raw);

        assert!(parsed_option.is_some());

        let parsed = parsed_option.unwrap();

        assert_eq!(parsed, expected)
    }

    #[test]
    fn parse_short_ethernet_frame() {
        let raw: Bytes = Bytes::from_static(&[]);

        let parsed_option = EthernetFrame::parse(raw);

        assert!(parsed_option.is_none());
    }

    #[test]
    fn parse_long_ethernet_frame() {
        let expected = EthernetFrame {
            destination_mac: [0, 0, 0, 0, 0, 0],
            source_mac: [0, 0, 0, 0, 0, 1],
            ether_type: EtherType::IPv4,
            payload: None,
            raw_payload: Bytes::from_static(&[0x00; 1500]),
        };

        let mut raw_vec = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // destination_mac
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // source mac
            0x08, 0x00, // ether type
        ];
        raw_vec.extend_from_slice(&[0x00; 1500]); // payload (dummy data)
        let raw: Bytes = Bytes::from(raw_vec);

        let parsed_option = EthernetFrame::parse(raw);

        assert!(parsed_option.is_some());

        let parsed = parsed_option.unwrap();

        assert_eq!(parsed, expected)
    }

    #[test]
    fn parse_ethernet_boundary() {
        let expected = EthernetFrame {
            destination_mac: [0, 0, 0, 0, 0, 0],
            source_mac: [0, 0, 0, 0, 0, 1],
            ether_type: EtherType::IPv4,
            payload: None,
            raw_payload: Bytes::new(),
        };

        let raw_good: Bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // destination_mac
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // source mac
            0x08, 0x00, // ether type
        ]);

        let raw_bad = Bytes::from_static(&[0x00; 13]);

        let parsed_good_option = EthernetFrame::parse(raw_good);
        let parsed_bad_option = EthernetFrame::parse(raw_bad);

        assert!(parsed_good_option.is_some());
        assert!(parsed_bad_option.is_none());

        let parsed = parsed_good_option.unwrap();

        assert_eq!(parsed, expected)
    }

    #[test]
    fn display() {
        let expected = String::from(
            "[Ethernet II] 00:00:00:00:00:01 -> 00:00:00:00:00:00 Type=IPv4 Payload=b\"\\x01\\x02\\x03\\x04\"",
        );

        let raw: Bytes = Bytes::from_static(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // destination_mac
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // source mac
            0x08, 0x00, // ether type
            0x01, 0x02, 0x03, 0x04, // payload (dummy data)
        ]);

        let parsed_option = EthernetFrame::parse(raw);

        assert!(parsed_option.is_some());

        let parsed = parsed_option.unwrap();

        let display = format!("{:?}", parsed);

        assert_eq!(expected, display);
    }
}
