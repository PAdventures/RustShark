use std::fmt::Display;

use bytes::Bytes;

use crate::{traits::Protocol, utils};

#[derive(Clone, PartialEq)]
pub enum IgmpMessage {
    GeneralQuery {
        version: IgmpVersion,
        max_resp_time: f32,
        checksum: u16,
    },
    V3GeneralQuery {
        max_resp_code: u8,
        checksum: u16,
        s: bool,
        qrv: u8,
        qqic: u8,
        addresses: Vec<[u8; 4]>,
    },
    GroupQuery {
        version: IgmpVersion,
        max_resp_time: f32,
        checksum: u16,
        group: [u8; 4],
    },
    V3GroupQuery {
        max_resp_code: u8,
        checksum: u16,
        s: bool,
        qrv: u8,
        qqic: u8,
        addresses: Vec<[u8; 4]>,
        group: [u8; 4],
    },
    Report {
        version: IgmpVersion,
        checksum: u16,
        group: [u8; 4],
    },
    V3Report {
        checksum: u16,
        num_records: u16,
        records: Vec<V3GroupRecord>,
    },
    Leave {
        checksum: u16,
        group: [u8; 4],
    },
}

#[derive(Clone, PartialEq)]
pub struct V3GroupRecord {
    pub record_type: V3GroupRecordType,
    pub num_src: u16,
    pub address: [u8; 4],
}

impl Display for V3GroupRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            self.record_type,
            utils::format_ipv4(&self.address)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum V3GroupRecordType {
    ModeIsInclude,
    ModeIsExclude,
    ChangeToIncludeMode,
    ChangeToExcludeMode,
    AllowNewSources,
    BlockOldSources,
    Unknown(u8),
}

impl V3GroupRecordType {
    pub fn from_u8(t: u8) -> Self {
        match t {
            1 => Self::ModeIsInclude,
            2 => Self::ModeIsExclude,
            3 => Self::ChangeToIncludeMode,
            4 => Self::ChangeToExcludeMode,
            5 => Self::AllowNewSources,
            6 => Self::BlockOldSources,
            other => Self::Unknown(other),
        }
    }
}

impl Display for V3GroupRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModeIsInclude => write!(f, "Mode Is Include"),
            Self::ModeIsExclude => write!(f, "Mode Is Exclude"),
            Self::ChangeToIncludeMode => write!(f, "Change To Include Mode"),
            Self::ChangeToExcludeMode => write!(f, "Change to Exlcude Mode"),
            Self::AllowNewSources => write!(f, "Allow New Sources"),
            Self::BlockOldSources => write!(f, "Block Old Sources"),
            Self::Unknown(other) => write!(f, "Unknown ({other})"),
        }
    }
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
            0x11 if data.len() > 8 => {
                if data.len() < 12 {
                    return None;
                }
                let s = (data[8] & 0x08) != 0;
                let qrv = data[8] & 0x07;
                let qqic = data[9];
                let num_src = u16::from_be_bytes([data[10], data[11]]);
                let sources_len = num_src as usize * 4;

                if data.len() < 12 + sources_len {
                    return None;
                }

                let mut addresses = Vec::new();

                for i in (12..12 + sources_len).step_by(4) {
                    addresses.push([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                }

                if group == [0, 0, 0, 0] {
                    Some(IgmpMessage::V3GeneralQuery {
                        max_resp_code: max_resp_byte,
                        checksum,
                        s,
                        qrv,
                        qqic,
                        addresses,
                    })
                } else {
                    Some(IgmpMessage::V3GroupQuery {
                        max_resp_code: max_resp_byte,
                        checksum,
                        s,
                        qrv,
                        qqic,
                        addresses,
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
            0x22 if max_resp_byte == 0 => {
                let num_records = u16::from_be_bytes([data[6], data[7]]);

                let mut records = Vec::with_capacity(num_records as usize);
                let mut cursor = 8;

                for _ in 0..num_records {
                    if data.len() < cursor + 8 {
                        return None;
                    }
                    let record_type = V3GroupRecordType::from_u8(data[cursor]);
                    let aux_data_len = data[cursor + 1] as usize;
                    let num_src = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]);
                    let address = [
                        data[cursor + 4],
                        data[cursor + 5],
                        data[cursor + 6],
                        data[cursor + 7],
                    ];
                    let record_len = 8 + num_src as usize * 4 + aux_data_len * 4;
                    if data.len() < cursor + record_len {
                        return None;
                    }
                    records.push(V3GroupRecord {
                        record_type,
                        num_src,
                        address,
                    });
                    cursor += record_len;
                }

                Some(IgmpMessage::V3Report {
                    checksum,
                    num_records,
                    records,
                })
            }
            _ => None,
        }
    }

    fn format_protocol(protocol: Self) -> String {
        protocol.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_query_report_and_leave() {
        assert!(matches!(
            IgmpMessage::parse(Bytes::from_static(&[0x11, 10, 0, 1, 0, 0, 0, 0])).unwrap(),
            IgmpMessage::GeneralQuery {
                version: IgmpVersion::V2,
                max_resp_time: 1.0,
                checksum: 1
            }
        ));

        assert!(matches!(
            IgmpMessage::parse(Bytes::from_static(&[0x16, 0, 0, 2, 224, 0, 0, 1])).unwrap(),
            IgmpMessage::Report {
                version: IgmpVersion::V2,
                checksum: 2,
                group: [224, 0, 0, 1]
            }
        ));

        assert!(matches!(
            IgmpMessage::parse(Bytes::from_static(&[0x17, 0, 0, 3, 224, 0, 0, 2])).unwrap(),
            IgmpMessage::Leave {
                checksum: 3,
                group: [224, 0, 0, 2]
            }
        ));
    }

    #[test]
    fn parses_v3_query_and_rejects_truncated_sources() {
        let parsed = IgmpMessage::parse(Bytes::from_static(&[
            0x11, 100, 0, 1, 0, 0, 0, 0, 0x0b, 125, 0, 2, 10, 0, 0, 1, 10, 0, 0, 2,
        ]))
        .unwrap();

        assert!(matches!(
            parsed,
            IgmpMessage::V3GeneralQuery {
                s: true,
                qrv: 3,
                qqic: 125,
                addresses,
                ..
            } if addresses == vec![[10, 0, 0, 1], [10, 0, 0, 2]]
        ));

        assert!(
            IgmpMessage::parse(Bytes::from_static(&[
                0x11, 100, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 10,
            ]))
            .is_none()
        );
    }

    #[test]
    fn parses_v3_report_and_rejects_truncated_records() {
        let parsed = IgmpMessage::parse(Bytes::from_static(&[
            0x22, 0, 0x12, 0x34, 0, 0, 0, 1, 1, 0, 0, 0, 224, 0, 0, 1,
        ]))
        .unwrap();

        assert!(matches!(
            parsed,
            IgmpMessage::V3Report {
                checksum: 0x1234,
                num_records: 1,
                records,
            } if records.len() == 1
                && records[0].record_type == V3GroupRecordType::ModeIsInclude
                && records[0].address == [224, 0, 0, 1]
        ));

        assert!(
            IgmpMessage::parse(Bytes::from_static(&[0x22, 0, 0x12, 0x34, 0, 0, 0, 1, 1,]))
                .is_none()
        );
        assert!(IgmpMessage::parse(Bytes::from_static(&[0; 7])).is_none());
        assert!(IgmpMessage::parse(Bytes::from_static(&[0xff, 0, 0, 0, 0, 0, 0, 0])).is_none());
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
            Self::V3Report { records, .. } => write!(
                f,
                "[IGMPv3] Membership Report group(s) {}",
                records
                    .iter()
                    .map(|r| format!("{r}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            Self::GeneralQuery { version, .. } => {
                write!(f, "[IGMP{}] Membership Query, general", version)
            }
            Self::V3GeneralQuery { addresses, .. } => {
                write!(
                    f,
                    "[IGMPv3] Membership Query, general {}",
                    addresses
                        .iter()
                        .map(|a| utils::format_ipv4(a))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            Self::GroupQuery { version, group, .. } => write!(
                f,
                "[IGMP{}] Membership Query, specific for group {}",
                version,
                utils::format_ipv4(group)
            ),
            Self::V3GroupQuery {
                group, addresses, ..
            } => {
                write!(
                    f,
                    "[IGMPv3] Membership Query, specific for group {} ({})",
                    utils::format_ipv4(group),
                    addresses
                        .iter()
                        .map(|a| utils::format_ipv4(a))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            Self::Leave { group, .. } => write!(
                f,
                "[IGMPv2] Leave Group {}, specific for group {}",
                utils::format_ipv4(group),
                utils::format_ipv4(group)
            ),
        }
    }
}
