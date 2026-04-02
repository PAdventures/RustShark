use std::fmt::Display;

use bytes::Bytes;
use libc::timeval;

use crate::{
    application::{ApplicationMessage, dns::DnsMessage, http::HttpMessage, tls::TlsRecord},
    traits::Protocol,
    utils::timeval_to_string,
};

#[derive(Clone)]
pub struct TcpSegment {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub payload: Option<ApplicationMessage>,
    pub raw_payload: Bytes,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    fn from_byte(byte: u8) -> Self {
        Self {
            cwr: byte & 0x80 != 0,
            ece: byte & 0x40 != 0,
            urg: byte & 0x20 != 0,
            ack: byte & 0x10 != 0,
            psh: byte & 0x08 != 0,
            rst: byte & 0x04 != 0,
            syn: byte & 0x02 != 0,
            fin: byte & 0x01 != 0,
        }
    }
}

impl Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        if self.cwr {
            flags.push("CWR");
        }
        if self.ece {
            flags.push("ECE");
        }
        if self.urg {
            flags.push("URG");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.syn {
            flags.push("SYN");
        }
        if self.fin {
            flags.push("FIN");
        }
        write!(f, "{}", flags.join(", "))
    }
}

impl Protocol for TcpSegment {
    /// TCP header (RFC 9293):
    /// ```
    ///  0               1               2               3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |          Source Port          |       Destination Port        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Sequence Number                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                    Acknowledgment Number                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Data  |       |C|E|U|A|P|R|S|F|                              |
    /// |Offset | Rsrvd |W|C|R|C|S|S|Y|I|           Window             |
    /// |       |       |R|E|G|K|H|T|N|N|                              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |           Checksum            |         Urgent Pointer        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 20 {
            return None;
        };

        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let destination_port = u16::from_be_bytes([data[2], data[3]]);
        let sequence_number = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let acknowledgment_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] >> 4) & 0x0F;
        let flags = TcpFlags::from_byte(data[13]);
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        let header_length = (data_offset as usize) * 4;
        if data.len() < header_length {
            return None;
        }

        Some(Self {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            payload: None, // To be parsed later by higher layers
            raw_payload: data.slice(header_length..),
        })
    }

    fn format_protocol(count: u64, ts: timeval, protocol: TcpSegment) -> String {
        if let Some(payload) = protocol.payload {
            match payload {
                ApplicationMessage::HTTP(http) => HttpMessage::format_protocol(count, ts, http),
                ApplicationMessage::DNS(dns) => DnsMessage::format_protocol(count, ts, dns),
                ApplicationMessage::TLS(tls) => TlsRecord::format_protocol(count, ts, tls),
            }
        } else {
            format!("{count} {} {}", timeval_to_string(ts), protocol.to_string())
        }
    }
}

impl Display for TcpSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[TCP] Port {} → {} Seq={} Ack={} Win={} Flags=[{}] Len={}",
            self.source_port,
            self.destination_port,
            self.sequence_number,
            self.acknowledgment_number,
            self.window_size,
            self.flags,
            self.raw_payload.len()
        )
    }
}
