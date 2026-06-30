use std::fmt::Display;

use bytes::Bytes;

use crate::{
    application::{
        ApplicationMessage, dns::DnsMessage, http::HttpMessage, quic::QuicPacket, tls::TlsRecord,
    },
    traits::Protocol,
};

#[derive(Clone, PartialEq)]
pub struct UdpDatagram {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Option<ApplicationMessage>,
    pub raw_payload: Bytes,
}

impl Protocol for UdpDatagram {
    /// UDP header (RFC 768) — fixed 8 bytes:
    ///  0               1               2               3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |          Source Port          |       Destination Port        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |             Length            |           Checksum            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let destination_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);
        let length_usize = length as usize;

        if length_usize < 8 || data.len() < length_usize {
            return None;
        }

        Some(Self {
            source_port,
            destination_port,
            length,
            checksum,
            payload: None, // To be parsed later by higher layers
            raw_payload: data.slice(8..length_usize),
        })
    }

    fn format_protocol(protocol: UdpDatagram) -> String {
        if let Some(payload) = protocol.payload {
            match payload {
                ApplicationMessage::HTTP(http) => HttpMessage::format_protocol(http),
                ApplicationMessage::DNS(dns) => DnsMessage::format_protocol(dns),
                ApplicationMessage::TLS(tls) => TlsRecord::format_protocol(tls),
                ApplicationMessage::QUIC(quic) => QuicPacket::format_protocol(quic),
            }
        } else {
            protocol.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram() -> Bytes {
        Bytes::from_static(&[
            0x00, 0x35, 0x12, 0x34, 0x00, 0x0b, 0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef,
        ])
    }

    #[test]
    fn parses_valid_udp_datagram() {
        let parsed = UdpDatagram::parse(datagram()).unwrap();

        assert_eq!(parsed.source_port, 53);
        assert_eq!(parsed.destination_port, 0x1234);
        assert_eq!(parsed.length, 11);
        assert_eq!(parsed.checksum, 0xabcd);
        assert_eq!(parsed.raw_payload, Bytes::from_static(&[0xde, 0xad, 0xbe]));
    }

    #[test]
    fn rejects_invalid_udp_lengths() {
        assert!(UdpDatagram::parse(Bytes::from_static(&[0; 7])).is_none());

        let mut shorter_than_header = datagram().to_vec();
        shorter_than_header[5] = 7;
        assert!(UdpDatagram::parse(Bytes::from(shorter_than_header)).is_none());

        let mut longer_than_buffer = datagram().to_vec();
        longer_than_buffer[5] = 13;
        assert!(UdpDatagram::parse(Bytes::from(longer_than_buffer)).is_none());
    }
}

impl Display for UdpDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[UDP] Port {} → {} Len={} Checksum={:#06X}",
            self.source_port,
            self.destination_port,
            self.raw_payload.len(),
            self.checksum,
        )
    }
}
