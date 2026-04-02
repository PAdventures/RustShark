use std::fmt::Display;

use bytes::Bytes;

use crate::traits::Protocol;

#[derive(Debug, Clone)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestUnreachable,
    TimeExceeded,
    RedirectMessage,
    RouterAdvertisement,
    RouterSolicitation,
    ParameterProblem,
    Timestamp,
    TimestampReply,
    ExtendedEchoRequest,
    ExtendedEchoReply,
    Unknown(u8),
}

impl IcmpType {
    fn from_type_code(t: u8) -> Self {
        match t {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestUnreachable,
            5 => IcmpType::RedirectMessage,
            9 => IcmpType::RouterAdvertisement,
            10 => IcmpType::RouterSolicitation,
            8 => IcmpType::EchoRequest,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 => IcmpType::Timestamp,
            14 => IcmpType::TimestampReply,
            42 => IcmpType::ExtendedEchoRequest,
            43 => IcmpType::ExtendedEchoReply,
            other => IcmpType::Unknown(other),
        }
    }
}

impl Protocol for IcmpPacket {
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let icmp_type = IcmpType::from_type_code(data[0]);
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        Some(Self {
            icmp_type,
            code,
            checksum,
            payload: data.slice(4..),
        })
    }

    fn format_protocol(protocol: IcmpPacket) -> String {
        protocol.to_string()
    }
}

impl Display for IcmpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ICMP] Type={:?} Code={} Checksum={:#06X} Len={}",
            self.icmp_type,
            self.code,
            self.checksum,
            self.payload.len(),
        )
    }
}
