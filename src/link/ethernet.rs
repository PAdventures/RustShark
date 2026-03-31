use std::fmt::{Debug, Display};

use bytes::Bytes;

use crate::network::NetworkPacket;

#[derive(Clone)]
pub struct EthernetFrame {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ether_type: EtherType,
    pub payload: Option<NetworkPacket>,
    pub raw_payload: Bytes,
}

#[derive(Debug, Clone)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Unknown(u16),
}

impl EthernetFrame {
    /// Ethernet Type II frame:
    ///
    /// 6 dst MAC | 6 src MAC | 2 EtherType
    pub fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        let destination_mac: [u8; 6] = data[0..6].try_into().unwrap();
        let source_mac: [u8; 6] = data[6..12].try_into().unwrap();
        let ether_type: EtherType = match u16::from_be_bytes([data[12], data[13]]) {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x086DD => EtherType::IPv6,
            other => EtherType::Unknown(other),
        };

        Some(Self {
            destination_mac,
            source_mac,
            ether_type,
            payload: None, // To be parsed later by higher layers
            raw_payload: data.slice(14..),
        })
    }

    pub fn format_mac(mac: &[u8; 6]) -> String {
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Display for EthernetFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[Ethernet II] {} -> {} Type={:?}",
            Self::format_mac(&self.source_mac),
            Self::format_mac(&self.destination_mac),
            self.ether_type
        )
    }
}

impl Debug for EthernetFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[Ethernet II] {} -> {} Type={:?} Payload={:?}",
            Self::format_mac(&self.source_mac),
            Self::format_mac(&self.destination_mac),
            self.ether_type,
            self.raw_payload
        )
    }
}
