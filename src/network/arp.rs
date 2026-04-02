use std::fmt::{Debug, Display};

use bytes::Bytes;
use libc::timeval;

use crate::{traits::Protocol, utils::timeval_to_string};

#[derive(Clone)]
pub struct ArpPacket {
    pub hardware_type: HardwareType,
    pub protocol_type: ProtocolType,
    pub hardware_length: u8,
    pub protocol_length: u8,
    pub operation: ArpOperation,
    pub sender_hardware_address: [u8; 6],
    pub sender_protocol_address: [u8; 4],
    pub target_hardware_address: [u8; 6],
    pub target_protocol_address: [u8; 4],
}

#[derive(Debug, Clone)]
pub enum HardwareType {
    Ethernet,
}

#[derive(Debug, Clone)]
pub enum ProtocolType {
    IPv4,
}

#[derive(Debug, Clone)]
pub enum ArpOperation {
    Request,
    Reply,
    Unknown(u16),
}

impl ArpPacket {
    pub fn fmt_mac(mac: &[u8; 6]) -> String {
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn fmt_ip(ip: &[u8; 4]) -> String {
        ip.iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }
}

impl Protocol for ArpPacket {
    /// ARP Packet (RFC 826)
    /// Total: 28 bytes for Ethernet + IPv4
    /// ```
    ///  0               1               2               3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Hardware Type         |         Protocol Type         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  HW Addr Len  | Proto Addr Len|           Operation           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                   Sender Hardware Address                     |
    /// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                               |      Sender Protocol Address  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |      Sender Protocol Address  |   Target Hardware Address     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                   Target Hardware Address                     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                   Target Protocol Address                     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 28 {
            return None;
        };

        let hardware_type = match u16::from_be_bytes([data[0], data[1]]) {
            1 => HardwareType::Ethernet,
            _ => return None,
        };

        let protocol_type = match u16::from_be_bytes([data[2], data[3]]) {
            0x0800 => ProtocolType::IPv4,
            _ => return None,
        };

        let hardware_length = data[4];
        let protocol_length = data[5];

        if hardware_length != 6 || protocol_length != 4 {
            return None; // Unsupported lengths for Ethernet + IPv4
        };

        let operation = match u16::from_be_bytes([data[6], data[7]]) {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            other => ArpOperation::Unknown(other),
        };

        let sender_hardware_address: [u8; 6] = data[8..14].try_into().unwrap();
        let sender_protocol_address: [u8; 4] = data[14..18].try_into().unwrap();
        let target_hardware_address: [u8; 6] = data[18..24].try_into().unwrap();
        let target_protocol_address: [u8; 4] = data[24..28].try_into().unwrap();

        Some(Self {
            hardware_type,
            protocol_type,
            hardware_length,
            protocol_length,
            operation,
            sender_hardware_address,
            sender_protocol_address,
            target_hardware_address,
            target_protocol_address,
        })
    }

    fn format_protocol(count: u64, ts: timeval, protocol: Self) -> String {
        format!("{count} {} {}", timeval_to_string(ts), protocol.to_string())
    }
}

impl Display for ArpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.operation {
            ArpOperation::Request => write!(
                f,
                "[ARP] Request - Who has {}? Tell {} ({})",
                Self::fmt_ip(&self.target_protocol_address),
                Self::fmt_ip(&self.sender_protocol_address),
                Self::fmt_mac(&self.sender_hardware_address)
            ),
            ArpOperation::Reply => write!(
                f,
                "[ARP] Reply - {} is at {} (target: {} {})",
                Self::fmt_ip(&self.sender_protocol_address),
                Self::fmt_mac(&self.sender_hardware_address),
                Self::fmt_ip(&self.target_protocol_address),
                Self::fmt_mac(&self.target_hardware_address)
            ),
            ArpOperation::Unknown(op) => write!(f, "[ARP] Unknown operation {op:#06X}"),
        }
    }
}

impl Debug for ArpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ARP] Hardware Type={:?} Protocol Type={:?} Hardware Len={} Protocol Len={} Operation={:?} Sender MAC={} Sender IP={} Target MAC={} Target IP={}",
            self.hardware_type,
            self.protocol_type,
            self.hardware_length,
            self.protocol_length,
            self.operation,
            Self::fmt_mac(&self.sender_hardware_address),
            Self::fmt_ip(&self.sender_protocol_address),
            Self::fmt_mac(&self.target_hardware_address),
            Self::fmt_ip(&self.target_protocol_address)
        )
    }
}
