use std::fmt::Display;

use bytes::Bytes;
use libc::timeval;

use crate::{
    application::{ApplicationMessage, dns::DnsMessage, http::HttpMessage, tls::TlsRecord},
    utils::timeval_to_string,
};

#[derive(Clone)]
pub struct UdpDatagram {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Option<ApplicationMessage>,
    pub raw_payload: Bytes,
}

impl UdpDatagram {
    /// UDP header (RFC 768) — fixed 8 bytes:
    ///  0               1               2               3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |          Source Port          |       Destination Port        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |             Length            |           Checksum            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    pub fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let destination_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        Some(Self {
            source_port,
            destination_port,
            length,
            checksum,
            payload: None, // To be parsed later by higher layers
            raw_payload: data.slice(8..),
        })
    }

    pub fn format_packet(count: u64, ts: timeval, datagram: UdpDatagram) -> String {
        if let Some(payload) = datagram.payload {
            match payload {
                ApplicationMessage::HTTP(http) => HttpMessage::format_packet(count, ts, http),
                ApplicationMessage::DNS(dns) => DnsMessage::format_packet(count, ts, dns),
                ApplicationMessage::TLS(tls) => TlsRecord::format_packet(count, ts, tls),
            }
        } else {
            format!("{count} {} {}", timeval_to_string(ts), datagram.to_string())
        }
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
