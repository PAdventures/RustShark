pub mod dns;
pub mod http;
pub mod tls;

use crate::transport::{tcp::TcpSegment, udp::UdpDatagram};

#[derive(Clone)]
pub enum ApplicationMessage {
    HTTP(http::HttpMessage),
    TLS(tls::TlsRecord),
    DNS(dns::DnsMessage),
}

pub fn parse_tcp_application(tcp: TcpSegment) -> Option<ApplicationMessage> {
    if tcp.raw_payload.is_empty() {
        return None;
    }

    match (tcp.source_port, tcp.destination_port) {
        (80, _) | (_, 80) => {
            if let Some(http) = http::HttpMessage::parse(tcp.raw_payload) {
                return Some(ApplicationMessage::HTTP(http));
            }
            return None;
        }
        (443, _) | (_, 443) => {
            if let Some(tls) = tls::TlsRecord::parse(tcp.raw_payload) {
                return Some(ApplicationMessage::TLS(tls));
            }
            return None;
        }
        _ => {
            return None;
        }
    }
}

pub fn parse_udp_application(udp: UdpDatagram) -> Option<ApplicationMessage> {
    match (udp.source_port, udp.destination_port) {
        (53, _) | (_, 53) => {
            if let Some(dns) = dns::DnsMessage::parse(udp.raw_payload) {
                return Some(ApplicationMessage::DNS(dns));
            }
            return None;
        }
        _ => {
            return None;
        }
    }
}
