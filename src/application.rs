pub mod dns;
pub mod http;
pub mod tls;

use libc::timeval;

use crate::{
    transport::{tcp::TcpSegment, udp::UdpDatagram},
    utils::timeval_to_string,
};

pub fn dispatch_tcp_application(ts: timeval, tcp: &TcpSegment) -> Option<()> {
    if tcp.payload.is_empty() {
        return None;
    }

    match (tcp.source_port, tcp.destination_port) {
        (80, _) | (_, 80) => {
            if let Some(http) = http::HttpMessage::parse(tcp.payload) {
                println!("{} {http}", timeval_to_string(ts));
                return Some(());
            }
            return None;
        }
        (443, _) | (_, 443) => {
            if let Some(tls) = tls::TlsRecord::parse(tcp.payload) {
                println!("{} {tls}", timeval_to_string(ts));
                return Some(());
            }
            return None;
        }
        _ => {
            return None;
        }
    }
}

pub fn dispatch_udp_application(ts: timeval, udp: &UdpDatagram) -> Option<()> {
    match (udp.source_port, udp.destination_port) {
        (53, _) | (_, 53) => {
            if let Some(dns) = dns::DnsMessage::parse(udp.payload) {
                println!("{} {dns}", timeval_to_string(ts));
                return Some(());
            }
            return None;
        }
        _ => {
            return None;
        }
    }
}
