pub mod http;

use libc::timeval;

use crate::{transport::tcp::TcpSegment, utils::timeval_to_string};

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
        _ => {
            return None;
        }
    }
}
