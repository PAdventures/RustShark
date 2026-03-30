use std::fmt::Display;

pub struct TlsRecord<'a> {
    pub content_type: TlsContentType,
    pub version: TlsVersion,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum TlsContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

#[derive(Debug)]
pub enum TlsHandshakeType {
    ClientHello,
    ServerHello,
    Certificate,
    ServerHelloDone,
    Finished,
    Unknown(u8),
}

#[derive(Debug)]
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

impl<'a> TlsRecord<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
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
            payload: &data[5..5 + length],
        })
    }
}

impl Display for TlsRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.content_type {
            TlsContentType::Handshake => {
                let hs_type = match self.payload[0] {
                    1 => TlsHandshakeType::ClientHello,
                    2 => TlsHandshakeType::ServerHello,
                    11 => TlsHandshakeType::Certificate,
                    14 => TlsHandshakeType::ServerHelloDone,
                    20 => TlsHandshakeType::Finished,
                    v => TlsHandshakeType::Unknown(v),
                };

                return write!(f, "[TLSv{}] Handshake: {:?}", self.version, hs_type);
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
                let level = match self.payload[0] {
                    1 => "warning",
                    2 => "fatal",
                    _ => "unknown",
                };
                return write!(
                    f,
                    "[TLSv{}] Alert — level: {}  code: {}",
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
