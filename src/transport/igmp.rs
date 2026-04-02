use std::fmt::Display;

use bytes::Bytes;

use crate::{traits::Protocol, utils};

#[derive(Clone)]
pub enum IgmpMessage {
    GeneralQuery {
        version: IgmpVersion,
        max_resp_time: f32,
        checksum: u16,
    },
    GroupQuery {
        version: IgmpVersion,
        max_resp_time: f32,
        checksum: u16,
        group: [u8; 4],
    },
    Report {
        version: IgmpVersion,
        checksum: u16,
        group: [u8; 4],
    },
    Leave {
        checksum: u16,
        group: [u8; 4],
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IgmpVersion {
    V1,
    V2,
}

impl Display for IgmpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
        }
    }
}

impl Protocol for IgmpMessage {
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 8 {
            return None;
        };

        let igmp_type = data[0];
        let max_resp_byte = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let group: [u8; 4] = data[4..8].try_into().unwrap();

        match igmp_type {
            0x11 if data.len() == 8 => {
                let version = if max_resp_byte == 0 {
                    IgmpVersion::V1
                } else {
                    IgmpVersion::V2
                };

                let max_resp_time = max_resp_byte as f32 / 10.0;
                let is_general = group == [0, 0, 0, 0];

                if is_general {
                    Some(IgmpMessage::GeneralQuery {
                        version,
                        max_resp_time,
                        checksum,
                    })
                } else {
                    Some(IgmpMessage::GroupQuery {
                        version,
                        max_resp_time,
                        checksum,
                        group,
                    })
                }
            }
            0x12 => Some(IgmpMessage::Report {
                version: IgmpVersion::V1,
                checksum,
                group,
            }),
            0x16 => Some(IgmpMessage::Report {
                version: IgmpVersion::V2,
                checksum,
                group,
            }),
            0x17 => Some(IgmpMessage::Leave { checksum, group }),
            _ => None,
        }
    }

    fn format_protocol(protocol: Self) -> String {
        protocol.to_string()
    }
}

impl Display for IgmpMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Report { version, group, .. } => write!(
                f,
                "[IGMP{}] Membership Report group {}",
                version,
                utils::format_ipv4(group)
            ),
            Self::GeneralQuery { version, .. } => {
                write!(f, "[IGMP{}] Membership Query, general", version)
            }

            Self::GroupQuery { version, group, .. } => write!(
                f,
                "[IGMP{}] Membership Query, specific for group {}",
                version,
                utils::format_ipv4(group)
            ),
            Self::Leave { group, .. } => write!(
                f,
                "[IGMPv2] Leave Group {}, specific for group {}",
                utils::format_ipv4(group),
                utils::format_ipv4(group)
            ),
        }
    }
}
