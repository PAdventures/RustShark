use std::fmt::Display;

use bytes::Bytes;

use crate::{traits::Protocol, utils};

#[derive(Debug, Clone)]
pub struct Icmpv6Packet {
    pub icmp_type: Icmpv6Type,
    pub code: u8,
    pub checksum: u16,
    pub payload: Option<Icmpv6Payload>,
    pub raw_payload: Bytes,
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
    MulticastListenerDiscoveryReport,
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
            143 => Icmpv6Type::MulticastListenerDiscoveryReport,
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

#[derive(Debug, Clone, Copy)]
pub enum Icmpv6Payload {
    RouterAdvertisement {
        cur_hop_lim: u8,
        managed_addr_conf: bool,
        other_conf: bool,
        home_agent: bool,
        prf: i8,
        proxy: bool,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
    },
    NeighborSolicitation {
        target_addr: [u8; 16],
    },
    NeighborAdvertisement {
        router: bool,
        solicited: bool,
        _override: bool,
        target_addr: [u8; 16],
    },
    RedirectMessage {
        target_addr: [u8; 16],
        destination_addr: [u8; 16],
    },
}

impl Protocol for Icmpv6Packet {
    fn parse(data: Bytes) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let icmp_type = Icmpv6Type::from_u8(data[0])?;
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let payload = match icmp_type {
            Icmpv6Type::RouterAdvertisement if data.len() >= 16 => {
                let cur_hop_lim = data[4];
                let managed_addr_conf = (data[5] & 0x80) != 0;
                let other_conf = (data[5] & 0x40) != 0;
                let home_agent = (data[5] & 0x20) != 0;

                let raw_bits = (data[5] & 0x18) >> 3;
                let prf: i8 = if (raw_bits & 0x02) != 0 {
                    (raw_bits as i8) | -4
                } else {
                    raw_bits as i8
                };

                let proxy = (data[5] & 0x04) != 0;
                let router_lifetime = u16::from_be_bytes([data[6], data[7]]);
                let reachable_time = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                let retrans_timer = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
                Some(Icmpv6Payload::RouterAdvertisement {
                    cur_hop_lim,
                    managed_addr_conf,
                    other_conf,
                    home_agent,
                    prf,
                    proxy,
                    router_lifetime,
                    reachable_time,
                    retrans_timer,
                })
            }
            Icmpv6Type::NeighborSolicitation if data.len() >= 24 => {
                let target_addr = data[8..24].try_into().unwrap();

                Some(Icmpv6Payload::NeighborSolicitation { target_addr })
            }
            Icmpv6Type::NeighborAdvertisement if data.len() >= 24 => {
                let router = (data[4] & 0x80) != 0;
                let solicited = (data[4] & 0x40) != 0;
                let _override = (data[4] & 0x20) != 0;
                let target_addr = data[8..24].try_into().unwrap();
                Some(Icmpv6Payload::NeighborAdvertisement {
                    router,
                    solicited,
                    _override,
                    target_addr,
                })
            }
            Icmpv6Type::RedirectMessage if data.len() >= 40 => {
                let target_addr = data[8..24].try_into().unwrap();
                let destination_addr = data[24..40].try_into().unwrap();
                Some(Icmpv6Payload::RedirectMessage {
                    target_addr,
                    destination_addr,
                })
            }
            _ => None,
        };

        Some(Self {
            icmp_type,
            code,
            checksum,
            raw_payload: data.slice(4..),
            payload,
        })
    }

    fn format_protocol(protocol: Icmpv6Packet) -> String {
        protocol.to_string()
    }
}

impl Display for Icmpv6Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.icmp_type {
            Icmpv6Type::EchoRequest => write!(f, "[ICMPv6] Echo Request"),
            Icmpv6Type::EchoReply => write!(f, "[ICMPv6] Echo Reply"),
            Icmpv6Type::MulticastListenerDiscoveryReport => write!(f, "[ICMPv6] MLDv2 Report"),
            Icmpv6Type::MulticastListenerQuery => write!(f, "[ICMPv6] Multicast Listener Query"),
            Icmpv6Type::MulticastListenerDone => write!(f, "[ICMPv6] Multicast Listener Done"),
            Icmpv6Type::MulticastListenerReport => write!(f, "[ICMPv6] Multicast Listener Report"),
            Icmpv6Type::MulticastRouterAdvertisement => {
                write!(f, "[ICMPv6] Multicast Router Advertisement")
            }
            Icmpv6Type::MulticastRouterSolicitation => {
                write!(f, "[ICMPv6] Multicast Router Solicitation")
            }
            Icmpv6Type::MulticastRouterTermination => {
                write!(f, "[ICMPv6] Multicast Router Termination")
            }
            Icmpv6Type::PacketTooBig => write!(f, "[ICMPv6] Packet Too Big"),
            Icmpv6Type::RPLControlMessage => write!(f, "[ICMPv6] RPL Control Message"),
            Icmpv6Type::ExtendedEchoRequest => write!(f, "[ICMPv6] Extended Echo Request"),
            Icmpv6Type::RouterSolicitation => write!(f, "[ICMPv6] Router Solicitation"),
            Icmpv6Type::DestinationUnreachable => {
                let code_str = match self.code {
                    0 => "No route to destination",
                    1 => "Communication with destination administratively prohibited",
                    2 => "Beyond scope of source address",
                    3 => "Address unreachable",
                    4 => "Port unreachable",
                    5 => "Source address failed ingress/egress policy",
                    6 => "Reject route to destination",
                    7 => "Error in Source Routing Header",
                    _ => "Unknown",
                };
                write!(f, "[ICMPv6] Destination Unreachable: {code_str}")
            }
            Icmpv6Type::TimeExceeded => {
                let code_str = match self.code {
                    0 => "Hop limit exceeded",
                    1 => "Fragment reassembly time exceeded",
                    _ => "Unknown",
                };
                write!(f, "[ICMPv6] Time Exceeded: {code_str}")
            }
            Icmpv6Type::ParameterProblem => {
                let code_str = match self.code {
                    0 => "Erroneous header field",
                    1 => "Unrecongized Next Header",
                    2 => "Unrecongized IPv6 option",
                    _ => "Unknown",
                };
                write!(f, "[ICMPv6] Parameter Problem: {code_str}")
            }
            Icmpv6Type::ExtendedEchoReply => {
                let code_str = match self.code {
                    0 => "No error",
                    1 => "Malformed query",
                    2 => "No such interface",
                    3 => "No such table entry",
                    4 => "Multiple interfaces satisfy query",
                    _ => "Unknown",
                };
                write!(f, "[ICMPv6] Extended Echo Reply: {code_str}")
            }
            Icmpv6Type::RouterAdvertisement => {
                if let Some(payload) = self.payload {
                    if let Icmpv6Payload::RouterAdvertisement {
                        managed_addr_conf,
                        other_conf,
                        home_agent,
                        proxy,
                        ..
                    } = payload
                    {
                        let mut flags = Vec::new();
                        if managed_addr_conf {
                            flags.push("mngd");
                        }
                        if other_conf {
                            flags.push("oth");
                        }
                        if home_agent {
                            flags.push("ho");
                        }
                        if proxy {
                            flags.push("prx");
                        }
                        return if flags.len() > 0 {
                            write!(f, "[ICMPv6] Router Advertisement ({})", flags.join(", "))
                        } else {
                            write!(f, "[ICMPv6] Router Advertisement")
                        };
                    }
                }
                write!(f, "[ICMPv6] Unknown Router Advertisement")
            }
            Icmpv6Type::NeighborSolicitation => {
                if let Some(payload) = self.payload {
                    if let Icmpv6Payload::NeighborSolicitation { target_addr } = payload {
                        return write!(
                            f,
                            "[ICMPv6] Neighbour Solicitation for {}",
                            utils::format_ipv6(&target_addr)
                        );
                    }
                }
                write!(f, "[ICMPv6] Unknown Neighbour Solicitation")
            }
            Icmpv6Type::NeighborAdvertisement => {
                if let Some(payload) = self.payload {
                    if let Icmpv6Payload::NeighborAdvertisement {
                        router,
                        solicited,
                        _override,
                        target_addr,
                    } = payload
                    {
                        let mut flags = Vec::new();
                        if router {
                            flags.push("rtr");
                        }
                        if solicited {
                            flags.push("sol");
                        }
                        if _override {
                            flags.push("ovr");
                        }

                        return if flags.len() > 0 {
                            write!(
                                f,
                                "[ICMPv6] Neighbour Advertisement for {} ({})",
                                utils::format_ipv6(&target_addr),
                                flags.join(", ")
                            )
                        } else {
                            write!(
                                f,
                                "[ICMPv6] Neighbour Advertisement for {}",
                                utils::format_ipv6(&target_addr)
                            )
                        };
                    }
                }
                write!(f, "[ICMPv6] Unknown Neighbour Advertisement")
            }
            Icmpv6Type::RedirectMessage => {
                if let Some(payload) = self.payload {
                    if let Icmpv6Payload::RedirectMessage {
                        target_addr,
                        destination_addr,
                    } = payload
                    {
                        return write!(
                            f,
                            "[ICMPv6] Redirect Message from {} to {}",
                            utils::format_ipv6(&target_addr),
                            utils::format_ipv6(&destination_addr)
                        );
                    }
                }
                write!(f, "[ICMPv6] Unknown Redirect Message")
            }
        }
    }
}
