use libc::timeval;

use crate::{
    application::{dispatch_tcp_application, dispatch_udp_application},
    network::ip_protocol::IpProtocol,
    utils::timeval_to_string,
};

pub mod icmp;
pub mod icmpv6;
pub mod tcp;
pub mod udp;

pub fn dispatch_transport(ts: timeval, protocol: IpProtocol, payload: &[u8]) {
    match protocol {
        IpProtocol::TCP => {
            if let Some(tcp) = tcp::TcpSegment::parse(payload) {
                let result = dispatch_tcp_application(ts, &tcp);
                if result.is_none() {
                    println!("{} {tcp}", timeval_to_string(ts))
                }
            }
        }
        IpProtocol::UDP => {
            if let Some(udp) = udp::UdpDatagram::parse(payload) {
                let result = dispatch_udp_application(ts, &udp);
                if result.is_none() {
                    println!("{} {udp}", timeval_to_string(ts))
                }
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
