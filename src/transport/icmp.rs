use std::fmt::Display;

use bytes::Bytes;

use crate::{traits::Protocol, utils};

#[derive(Debug, Clone, PartialEq)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub raw_payload: Bytes,
    pub payload: Option<IcmpPayload>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    TimeExceeded,
    RedirectMessage,
    RouterAdvertisement,
    RouterSolicitation,
    ParameterProblem,
    Timestamp,
    TimestampReply,
    ExtendedEchoRequest,
    ExtendedEchoReply,
}

impl IcmpType {
    fn from_u8(t: u8) -> Option<Self> {
        let r = match t {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestinationUnreachable,
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
            _ => return None,
        };
        Some(r)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpPayload {
    RedirectMessage {
        ip: [u8; 4],
    },
    Timestamp {
        id: u16,
        seq: u16,
        origin_ts: u32,
        recv_ts: u32,
        transmit_ts: u32,
        is_reply: bool,
    },
}

impl Protocol for IcmpPacket {
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let icmp_type = IcmpType::from_u8(data[0])?;
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        let payload: Option<IcmpPayload> = match icmp_type {
            IcmpType::RedirectMessage if data.len() >= 8 => {
                let ip = [data[4], data[5], data[6], data[7]];
                Some(IcmpPayload::RedirectMessage { ip })
            }
            IcmpType::Timestamp | IcmpType::TimestampReply if data.len() >= 20 => {
                let id = u16::from_be_bytes([data[4], data[5]]);
                let seq = u16::from_be_bytes([data[6], data[7]]);
                let origin_ts = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                let recv_ts = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
                let transmit_ts = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
                let is_reply = icmp_type == IcmpType::TimestampReply;
                Some(IcmpPayload::Timestamp {
                    id,
                    seq,
                    origin_ts,
                    recv_ts,
                    transmit_ts,
                    is_reply,
                })
            }
            _ => None,
        };

        Some(Self {
            icmp_type,
            code,
            checksum,
            raw_payload: data.slice(4..),
            payload,
        })
    }

    fn format_protocol(protocol: IcmpPacket) -> String {
        protocol.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_echo_and_redirect_messages() {
        let echo = IcmpPacket::parse(Bytes::from_static(&[8, 0, 0x12, 0x34, 1, 2])).unwrap();
        assert_eq!(echo.icmp_type, IcmpType::EchoRequest);
        assert_eq!(echo.checksum, 0x1234);
        assert_eq!(echo.raw_payload, Bytes::from_static(&[1, 2]));

        let redirect =
            IcmpPacket::parse(Bytes::from_static(&[5, 1, 0, 0, 192, 168, 1, 1])).unwrap();
        assert_eq!(
            redirect.payload,
            Some(IcmpPayload::RedirectMessage {
                ip: [192, 168, 1, 1]
            })
        );
    }

    #[test]
    fn rejects_unknown_or_short_icmp_packets_without_panicking() {
        assert!(IcmpPacket::parse(Bytes::from_static(&[8, 0, 0])).is_none());
        assert!(IcmpPacket::parse(Bytes::from_static(&[255, 0, 0, 0])).is_none());

        let redirect = IcmpPacket::parse(Bytes::from_static(&[5, 1, 0, 0])).unwrap();
        assert_eq!(redirect.payload, None);
    }

    #[test]
    fn parses_timestamp_only_when_complete() {
        let timestamp = IcmpPacket::parse(Bytes::from_static(&[
            13, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
        ]))
        .unwrap();

        assert_eq!(
            timestamp.payload,
            Some(IcmpPayload::Timestamp {
                id: 1,
                seq: 2,
                origin_ts: 3,
                recv_ts: 4,
                transmit_ts: 5,
                is_reply: false,
            })
        );

        assert_eq!(
            IcmpPacket::parse(Bytes::from_static(&[13, 0, 0, 0, 0, 1]))
                .unwrap()
                .payload,
            None
        );
    }
}

impl Display for IcmpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.icmp_type {
            IcmpType::EchoReply => write!(f, "[ICMP] Echo Reply"),
            IcmpType::EchoRequest => write!(f, "[ICMP] Echo request"),
            IcmpType::DestinationUnreachable => {
                let code_str = match self.code {
                    0 => "Network unreachable",
                    1 => "Host unreachable",
                    2 => "Protocol unreachable",
                    3 => "Port unreachable",
                    4 => "Fragmentation required",
                    5 => "Source route failed",
                    6 => "Network unknown",
                    7 => "Host unknown",
                    8 => "Source host isolated",
                    9 => "Network administratively prohibited",
                    10 => "Host administratively prohibited",
                    11 => "Network unreachable (ToS)",
                    12 => "Host unreachable (ToS)",
                    13 => "Communication administratively prohibited",
                    14 => "Host Precedence Violaion",
                    15 => "Precedence cutoff",
                    _ => "Unknown",
                };
                write!(f, "[ICMP] Destination unreachable: {code_str}")
            }
            IcmpType::RedirectMessage => {
                if let Some(payload) = self.payload {
                    if let IcmpPayload::RedirectMessage { ip } = payload {
                        let code_str = match self.code {
                            0 => "Redirect for Network",
                            1 => "Redirect for Host",
                            2 => "Redirect for ToS & Network",
                            3 => "Redirect for ToS & Host",
                            _ => "Unknown",
                        };
                        return write!(
                            f,
                            "[ICMP] Redirect to {}: {code_str}",
                            utils::format_ipv4(&ip)
                        );
                    };
                };
                write!(f, "[ICMP] Unknown Redirect")
            }
            IcmpType::RouterAdvertisement => write!(f, "[ICMP] Router Advertisment"),
            IcmpType::RouterSolicitation => write!(f, "[ICMP] Router Solicitation"),
            IcmpType::TimeExceeded => {
                let code_str = match self.code {
                    0 => "TTL expired",
                    1 => "Fragment reassembly time exceeded",
                    _ => "Unknown",
                };
                write!(f, "[ICMP] Time Exceeded: {code_str}")
            }
            IcmpType::ParameterProblem => {
                let code_str = match self.code {
                    0 => "Pointer to error",
                    1 => "Missing required option",
                    2 => "Bad length",
                    _ => "Unknown",
                };
                write!(f, "[ICMP] Parameter Problem: {code_str}")
            }
            IcmpType::Timestamp | IcmpType::TimestampReply => {
                if let Some(payload) = self.payload {
                    if let IcmpPayload::Timestamp {
                        origin_ts,
                        recv_ts,
                        transmit_ts,
                        is_reply,
                        ..
                    } = payload
                    {
                        return if is_reply {
                            write!(
                                f,
                                "[ICMP] Timestamp reply {origin_ts} {recv_ts} {transmit_ts}"
                            )
                        } else {
                            write!(f, "[ICMP] Timestamp {origin_ts} {recv_ts} {transmit_ts}")
                        };
                    }
                }
                write!(f, "[ICMP] Unknown Timestamp Message")
            }
            IcmpType::ExtendedEchoRequest => write!(f, "[ICMP] Extended Echo Request"),
            IcmpType::ExtendedEchoReply => write!(f, "[ICMP] Extended Echo Reply"),
        }
    }
}
