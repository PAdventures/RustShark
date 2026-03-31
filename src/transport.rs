use bytes::Bytes;
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

#[derive(Clone)]
pub enum TransportPacket {
    TCP(tcp::TcpSegment),
    UDP(udp::UdpDatagram),
    ICMP(icmp::IcmpPacket),
    ICMPv6(icmpv6::Icmpv6Packet),
}

pub fn dispatch_transport(
    ts: timeval,
    protocol: IpProtocol,
    payload: Bytes,
) -> Option<TransportPacket> {
    match protocol {
        IpProtocol::TCP => {
            if let Some(mut tcp) = tcp::TcpSegment::parse(payload) {
                let result = dispatch_tcp_application(ts, tcp.clone());
                if result.is_none() {
                    println!("{} {tcp}", timeval_to_string(ts));
                    tcp.payload = result;
                    return Some(TransportPacket::TCP(tcp));
                }
            }
        }
        IpProtocol::UDP => {
            if let Some(mut udp) = udp::UdpDatagram::parse(payload) {
                let result = dispatch_udp_application(ts, udp.clone());
                if result.is_none() {
                    println!("{} {udp}", timeval_to_string(ts));
                    udp.payload = result;
                    return Some(TransportPacket::UDP(udp));
                }
            }
        }
        IpProtocol::ICMP => {
            if let Some(icmp) = icmp::IcmpPacket::parse(payload) {
                println!("{} {icmp}", timeval_to_string(ts));
                return Some(TransportPacket::ICMP(icmp));
            }
        }
        IpProtocol::ICMPv6 => {
            if let Some(icmpv6) = icmpv6::Icmpv6Packet::parse(payload) {
                println!("{} {icmpv6}", timeval_to_string(ts));
                return Some(TransportPacket::ICMPv6(icmpv6));
            }
        }
        _ => {
            return None;
        }
    }
    return None;
}
