use std::fmt::Display;

use bytes::Bytes;

use crate::{traits::Protocol, utils};

const QUIC_V1: u32 = 0x00000001;
const QUIC_V2: u32 = 0x6B3343CF;
const QUIC_VERSION_NEGOTIATION: u32 = 0x00000000;

#[derive(Clone)]
pub enum QuicPacket {
    Initial(QuicInitial),
    ZeroRtt(QuicZeroRtt),
    Handshake(QuicHandshake),
    Retry(QuicRetry),
    VersionNegotiation(QuicVersionNegotiation),
}

#[derive(Clone)]
pub struct QuicInitial {
    pub version: u32,
    pub dcid: Bytes,
    pub scid: Bytes,
    pub token: Bytes,
}

#[derive(Clone)]
pub struct QuicZeroRtt {
    pub version: u32,
    pub dcid: Bytes,
    pub scid: Bytes,
}

#[derive(Clone)]
pub struct QuicHandshake {
    pub version: u32,
    pub dcid: Bytes,
    pub scid: Bytes,
}

#[derive(Clone)]
pub struct QuicRetry {
    pub version: u32,
    pub dcid: Bytes,
    pub scid: Bytes,
    pub token: Bytes,
    pub integrity_tag: [u8; 16],
}

#[derive(Clone)]
pub struct QuicVersionNegotiation {
    pub dcid: Bytes,
    pub scid: Bytes,
    pub supported_versions: Vec<u32>,
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let prefix = first >> 6;
    match prefix {
        0 => Some(((first & 0x3F) as u64, 1)),
        1 => {
            if data.len() < 2 {
                return None;
            }
            let val = (((first & 0x3F) as u64) << 8) | data[1] as u64;
            Some((val, 2))
        }
        2 => {
            if data.len() < 4 {
                return None;
            }
            let val = (((first & 0x3F) as u64) << 24)
                | ((data[1] as u64) << 16)
                | ((data[2] as u64) << 8)
                | data[3] as u64;
            Some((val, 4))
        }
        3 => {
            if data.len() < 8 {
                return None;
            }
            let val = (((first & 0x3F) as u64) << 56)
                | ((data[1] as u64) << 48)
                | ((data[2] as u64) << 40)
                | ((data[3] as u64) << 32)
                | ((data[4] as u64) << 24)
                | ((data[5] as u64) << 16)
                | ((data[6] as u64) << 8)
                | data[7] as u64;
            Some((val, 8))
        }
        _ => None,
    }
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(b.try_into().ok()?))
}

impl Protocol for QuicPacket {
    fn parse(data: Bytes) -> Option<Self> {
        fn parse_version_negotiation(data: Bytes) -> Option<QuicVersionNegotiation> {
            let mut cursor = 5;

            let dcid_len = *data.get(cursor)? as usize;
            cursor += 1;
            let dcid = data.slice(cursor..cursor + dcid_len);
            cursor += dcid_len;

            let scid_len = *data.get(cursor)? as usize;
            cursor += 1;
            let scid = data.slice(cursor..cursor + scid_len);
            cursor += scid_len;

            let mut supported_versions = Vec::new();
            while cursor + 4 <= data.len() {
                supported_versions.push(read_u32(&data, cursor)?);
                cursor += 4;
            }

            Some(QuicVersionNegotiation {
                dcid,
                scid,
                supported_versions,
            })
        }

        let first = *data.first()?;
        let fixed_bit = (first >> 6) & 1;

        if fixed_bit != 1 {
            return None;
        }

        let long_header = (first >> 7) == 1;

        if !long_header {
            return None;
        }

        if data.len() < 6 {
            return None;
        }

        let version = read_u32(&data, 1)?;

        if version == QUIC_VERSION_NEGOTIATION {
            return parse_version_negotiation(data).map(QuicPacket::VersionNegotiation);
        }

        if version != QUIC_V1 && version != QUIC_V2 {
            return None;
        }

        let mut cursor = 5;

        let dcid_len = *data.get(cursor)? as usize;
        cursor += 1;
        if dcid_len > 20 {
            return None;
        }
        let dcid = data.slice(cursor..cursor + dcid_len);
        cursor += dcid_len;

        let scid_len = *data.get(cursor)? as usize;
        cursor += 1;
        if scid_len > 20 {
            return None;
        }
        let scid = data.slice(cursor..cursor + scid_len);
        cursor += scid_len;

        let packet_type = (first >> 4) & 0x3;

        match packet_type {
            0x0 => {
                let (token_len, consumed) = read_varint(data.get(cursor..)?)?;
                cursor += consumed;
                let token = data.slice(cursor..cursor + token_len as usize);
                Some(QuicPacket::Initial(QuicInitial {
                    version,
                    dcid,
                    scid,
                    token,
                }))
            }
            0x1 => Some(QuicPacket::ZeroRtt(QuicZeroRtt {
                version,
                dcid,
                scid,
            })),
            0x2 => Some(QuicPacket::Handshake(QuicHandshake {
                version,
                dcid,
                scid,
            })),
            0x3 => {
                if data.len() < cursor + 16 {
                    return None;
                }
                let token_end = data.len() - 16;
                let token = data.slice(cursor..token_end);
                let tag: [u8; 16] = data[token_end..].try_into().ok()?;
                Some(QuicPacket::Retry(QuicRetry {
                    version,
                    dcid,
                    scid,
                    token,
                    integrity_tag: tag,
                }))
            }
            _ => None,
        }
    }

    fn format_protocol(protocol: QuicPacket) -> String {
        protocol.to_string()
    }
}

impl Display for QuicPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicPacket::Initial(p) => write!(
                f,
                "[QUIC] Initial {} dcid={} scid={}",
                fmt_version(p.version),
                utils::format_bytes(&p.dcid.to_vec()),
                utils::format_bytes(&p.scid.to_vec())
            ),
            QuicPacket::ZeroRtt(p) => write!(
                f,
                "[QUIC] 0-RTT {} dcid={} scid={}",
                fmt_version(p.version),
                utils::format_bytes(&p.dcid.to_vec()),
                utils::format_bytes(&p.scid.to_vec())
            ),
            QuicPacket::Handshake(p) => write!(
                f,
                "[QUIC] Handshake {} dcid={} scid={}",
                fmt_version(p.version),
                utils::format_bytes(&p.dcid.to_vec()),
                utils::format_bytes(&p.scid.to_vec())
            ),
            QuicPacket::Retry(p) => write!(
                f,
                "[QUIC] Retry {} dcid={} scid={}",
                fmt_version(p.version),
                utils::format_bytes(&p.dcid.to_vec()),
                utils::format_bytes(&p.scid.to_vec())
            ),
            QuicPacket::VersionNegotiation(p) => {
                let versions: Vec<String> = p
                    .supported_versions
                    .iter()
                    .map(|v| fmt_version(*v))
                    .collect();
                write!(
                    f,
                    "[QUIC] VersionNegotiation dcid={} scid={} supported=[{}]",
                    utils::format_bytes(&p.dcid.to_vec()),
                    utils::format_bytes(&p.scid.to_vec()),
                    versions.join(", ")
                )
            }
        }
    }
}

fn fmt_version(v: u32) -> String {
    match v {
        QUIC_V1 => "v1".to_string(),
        QUIC_V2 => "v2".to_string(),
        QUIC_VERSION_NEGOTIATION => "version-negotiation".to_string(),
        v if v >> 8 == 0xFF0000 => format!("draft-{}", v & 0xFF),
        v => format!("0x{v:08X}"),
    }
}
