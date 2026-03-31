pub mod arp;
pub mod ip_protocol;
pub mod ipv4;
pub mod ipv6;

#[derive(Debug, Clone)]
pub enum NetworkPacket {
    IPv4(ipv4::IPv4Packet),
    IPv6(ipv6::IPv6Packet),
    ARP(arp::ArpPacket),
}
