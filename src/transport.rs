use std::sync::{Arc, RwLock};

use bytes::Bytes;

use crate::{
    application::{parse_tcp_application, parse_udp_application},
    dns_cache::DnsCache,
    network::ip_protocol::IpProtocol,
    traits::Protocol,
};

pub mod icmp;
pub mod icmpv6;
pub mod igmp;
pub mod tcp;
pub mod udp;

#[derive(Clone)]
pub enum TransportPacket {
    TCP(tcp::TcpSegment),
    UDP(udp::UdpDatagram),
    ICMP(icmp::IcmpPacket),
    ICMPv6(icmpv6::Icmpv6Packet),
    IGMP(igmp::IgmpMessage),
}

pub fn parse_transport(
    protocol: IpProtocol,
    payload: Bytes,
    dns_cache: Option<&Arc<RwLock<DnsCache>>>,
) -> Option<TransportPacket> {
    match protocol {
        IpProtocol::TCP => {
            if let Some(mut tcp) = tcp::TcpSegment::parse(payload) {
                tcp.payload = parse_tcp_application(tcp.clone());
                return Some(TransportPacket::TCP(tcp));
            }
        }
        IpProtocol::UDP => {
            if let Some(mut udp) = udp::UdpDatagram::parse(payload) {
                udp.payload = parse_udp_application(dns_cache, udp.clone());
                return Some(TransportPacket::UDP(udp));
            }
        }
        IpProtocol::ICMP => {
            if let Some(icmp) = icmp::IcmpPacket::parse(payload) {
                return Some(TransportPacket::ICMP(icmp));
            }
        }
        IpProtocol::ICMPv6 => {
            if let Some(icmpv6) = icmpv6::Icmpv6Packet::parse(payload) {
                return Some(TransportPacket::ICMPv6(icmpv6));
            }
        }
        IpProtocol::IGMP => {
            if let Some(igmp) = igmp::IgmpMessage::parse(payload) {
                return Some(TransportPacket::IGMP(igmp));
            }
        }
        _ => {
            return None;
        }
    }
    return None;
}
