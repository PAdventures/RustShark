use std::fmt::Display;

use bytes::Bytes;

use crate::traits::Protocol;

#[derive(Debug, Clone)]
pub struct Icmpv6Packet {
    pub icmp_type: Icmpv6Type,
    pub code: u8,
    pub checksum: u16,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy)]
pub enum Icmpv6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    MulticastListenerQuery,
    MulticastListenerReport,
    MulticastListenerDone,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    RedirectMessage,
    RouterRenumbering,
    NodeInformationQuery,
    NodeInformationResponse,
    InverseNeighborDiscoverySolicitationMessage,
    InverseNeighborDiscoveryAdvertisementMessage,
    MulticastListenerDiscoveryReport,
    HomeAgentAddressDiscoveryRequestMessage,
    HomeAgentAddressDiscoveryReplyMessage,
    MobilePrefixSolicitation,
    MobilePrefixAdvertisement,
    CertificationPathSolicitation,
    CertificationPathAdvertisement,
    MulticastRouterAdvertisement,
    MulticastRouterSolicitation,
    MulticastRouterTermination,
    RPLControlMessage,
    ExtendedEchoRequest,
    ExtendedEchoReply,
}

impl Icmpv6Type {
    fn from_u8(t: u8) -> Option<Self> {
        let r = match t {
            1 => Icmpv6Type::DestinationUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            130 => Icmpv6Type::MulticastListenerQuery,
            131 => Icmpv6Type::MulticastListenerReport,
            132 => Icmpv6Type::MulticastListenerDone,
            133 => Icmpv6Type::RouterSolicitation,
            134 => Icmpv6Type::RouterAdvertisement,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            137 => Icmpv6Type::RedirectMessage,
            138 => Icmpv6Type::RouterRenumbering,
            139 => Icmpv6Type::NodeInformationQuery,
            140 => Icmpv6Type::NodeInformationResponse,
            141 => Icmpv6Type::InverseNeighborDiscoverySolicitationMessage,
            142 => Icmpv6Type::InverseNeighborDiscoveryAdvertisementMessage,
            143 => Icmpv6Type::MulticastListenerDiscoveryReport,
            144 => Icmpv6Type::HomeAgentAddressDiscoveryRequestMessage,
            145 => Icmpv6Type::HomeAgentAddressDiscoveryReplyMessage,
            146 => Icmpv6Type::MobilePrefixSolicitation,
            147 => Icmpv6Type::MobilePrefixAdvertisement,
            148 => Icmpv6Type::CertificationPathSolicitation,
            149 => Icmpv6Type::CertificationPathAdvertisement,
            151 => Icmpv6Type::MulticastRouterAdvertisement,
            152 => Icmpv6Type::MulticastRouterSolicitation,
            153 => Icmpv6Type::MulticastRouterTermination,
            155 => Icmpv6Type::RPLControlMessage,
            160 => Icmpv6Type::ExtendedEchoRequest,
            161 => Icmpv6Type::ExtendedEchoReply,
            _ => return None,
        };
        Some(r)
    }
}

impl Protocol for Icmpv6Packet {
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let icmp_type = Icmpv6Type::from_u8(data[0])?;
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        Some(Self {
            icmp_type,
            code,
            checksum,
            payload: data.slice(4..),
        })
    }

    fn format_protocol(protocol: Icmpv6Packet) -> String {
        protocol.to_string()
    }
}

impl Display for Icmpv6Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ICMPv6] Type={:?} Code={} Checksum={:#06X} Len={}",
            self.icmp_type,
            self.code,
            self.checksum,
            self.payload.len(),
        )
    }
}
