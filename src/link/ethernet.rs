use std::fmt::{Debug, Display};

use bytes::Bytes;
use libc::timeval;

use crate::{
    network::{NetworkPacket, arp::ArpPacket, ipv4::IPv4Packet, ipv6::IPv6Packet},
    traits::Protocol,
    utils::{self, timeval_to_string},
};

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

    fn format_protocol(count: u64, ts: timeval, protocol: Self) -> String {
        if let Some(payload) = protocol.payload {
            match payload {
                NetworkPacket::IPv4(ipv4) => IPv4Packet::format_protocol(count, ts, ipv4),
                NetworkPacket::IPv6(ipv6) => IPv6Packet::format_protocol(count, ts, ipv6),
                NetworkPacket::ARP(arp) => ArpPacket::format_protocol(count, ts, arp),
            }
        } else {
            format!("{count} {} {}", timeval_to_string(ts), protocol.to_string())
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
