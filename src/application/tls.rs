use std::fmt::Display;

use bytes::Bytes;

use crate::traits::Protocol;

#[derive(Clone, PartialEq)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    pub version: TlsVersion,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsHandshakeType {
    ClientHello,
    ServerHello,
    Certificate,
    ServerHelloDone,
    Finished,
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TlsVersion {
    pub major: u8,
    pub minor: u8,
}

impl Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.major, self.minor) {
            (3, 1) => write!(f, "1.0"),
            (3, 2) => write!(f, "1.1"),
            (3, 3) => write!(f, "1.2"),
            (3, 4) => write!(f, "1.3"),
            _ => write!(f, "{} {}", self.major, self.minor),
        }
    }
}

impl Protocol for TlsRecord {
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 5 {
            return None;
        }

        let content_type = match data[0] {
            20 => TlsContentType::ChangeCipherSpec,
            21 => TlsContentType::Alert,
            22 => TlsContentType::Handshake,
            23 => TlsContentType::ApplicationData,
            v => TlsContentType::Unknown(v),
        };

        let version = TlsVersion {
            major: data[1],
            minor: data[2],
        };

        match version {
            TlsVersion {
                major: 3,
                minor: 1..=4,
            } => {}
            _ => return None, // Unsupported TLS version
        }

        let length = u16::from_be_bytes([data[3], data[4]]) as usize;

        if data.len() < 5 + length {
            return None;
        }

        Some(Self {
            content_type,
            version,
            payload: data.slice(5..5 + length),
        })
    }

    fn format_protocol(protocol: TlsRecord) -> String {
        protocol.to_string()
    }
}

impl Display for TlsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.content_type {
            TlsContentType::Handshake => {
                if self.payload.is_empty() {
                    return write!(f, "[TLSv{}] Handshake=Unknown(empty)", self.version);
                }
                let hs_type = match self.payload[0] {
                    1 => TlsHandshakeType::ClientHello,
                    2 => TlsHandshakeType::ServerHello,
                    11 => TlsHandshakeType::Certificate,
                    14 => TlsHandshakeType::ServerHelloDone,
                    20 => TlsHandshakeType::Finished,
                    v => TlsHandshakeType::Unknown(v),
                };

                return write!(f, "[TLSv{}] Handshake={:?}", self.version, hs_type);
            }
            TlsContentType::ApplicationData => {
                return write!(
                    f,
                    "[TLSv{}] ApplicationData ({} bytes, encrypted)",
                    self.version,
                    self.payload.len()
                );
            }
            TlsContentType::Alert => {
                if self.payload.len() < 2 {
                    return write!(f, "[TLSv{}] Alert malformed", self.version);
                }
                let level = match self.payload[0] {
                    1 => "warning",
                    2 => "fatal",
                    _ => "unknown",
                };
                return write!(
                    f,
                    "[TLSv{}] Alert level={} code={}",
                    self.version, level, self.payload[1]
                );
            }
            other => {
                return write!(
                    f,
                    "[TLSv{}] {:?} ({} bytes)",
                    self.version,
                    other,
                    self.payload.len()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tls_record_and_known_versions() {
        let parsed = TlsRecord::parse(Bytes::from_static(&[22, 3, 3, 0, 4, 1, 0, 0, 0])).unwrap();

        assert_eq!(parsed.content_type, TlsContentType::Handshake);
        assert_eq!(parsed.version, TlsVersion { major: 3, minor: 3 });
        assert_eq!(parsed.payload, Bytes::from_static(&[1, 0, 0, 0]));
        assert_eq!(format!("{}", parsed), "[TLSv1.2] Handshake=ClientHello");
    }

    #[test]
    fn rejects_short_unsupported_or_truncated_tls_records() {
        assert!(TlsRecord::parse(Bytes::from_static(&[22, 3, 3, 0])).is_none());
        assert!(TlsRecord::parse(Bytes::from_static(&[22, 2, 0, 0, 0])).is_none());
        assert!(TlsRecord::parse(Bytes::from_static(&[22, 3, 3, 0, 2, 1])).is_none());
    }

    #[test]
    fn displays_empty_handshake_and_short_alert_without_panicking() {
        let handshake = TlsRecord::parse(Bytes::from_static(&[22, 3, 3, 0, 0])).unwrap();
        assert_eq!(
            format!("{}", handshake),
            "[TLSv1.2] Handshake=Unknown(empty)"
        );

        let alert = TlsRecord::parse(Bytes::from_static(&[21, 3, 3, 0, 1, 1])).unwrap();
        assert_eq!(format!("{}", alert), "[TLSv1.2] Alert malformed");
    }
}
