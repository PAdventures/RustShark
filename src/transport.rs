use libc::timeval;

use crate::{network::ip_protocol::IpProtocol, utils::timeval_to_string};

pub mod icmp;
pub mod icmpv6;
pub mod tcp;
pub mod udp;

pub fn dispatch_transport(ts: timeval, protocol: IpProtocol, payload: &[u8]) {
    match protocol {
        IpProtocol::TCP => {
            if let Some(tcp) = tcp::TcpSegment::parse(payload) {
                println!("{} {tcp}", timeval_to_string(ts))
            }
        }
        IpProtocol::UDP => {
            if let Some(udp) = udp::UdpDatagram::parse(payload) {
                println!("{} {udp}", timeval_to_string(ts))
            }
        }
        IpProtocol::ICMP => {
            if let Some(icmp) = icmp::IcmpPacket::parse(payload) {
                println!("{} {icmp}", timeval_to_string(ts))
            }
        }
        IpProtocol::ICMPv6 => {
            if let Some(icmpv6) = icmpv6::Icmpv6Packet::parse(payload) {
                println!("{} {icmpv6}", timeval_to_string(ts))
            }
        }
        _ => {
            println!("[Transport] Unknown protocol")
        }
    }
}
