#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpProtocol {
    IPv6HopByHop,
    ICMP,
    IGMP,
    TCP,
    UDP,
    ICMPv6,
    Unknown(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_and_unknown_ip_protocol_numbers() {
        assert_eq!(IpProtocol::from(0), IpProtocol::IPv6HopByHop);
        assert_eq!(IpProtocol::from(1), IpProtocol::ICMP);
        assert_eq!(IpProtocol::from(2), IpProtocol::IGMP);
        assert_eq!(IpProtocol::from(6), IpProtocol::TCP);
        assert_eq!(IpProtocol::from(17), IpProtocol::UDP);
        assert_eq!(IpProtocol::from(58), IpProtocol::ICMPv6);
        assert_eq!(IpProtocol::from(255), IpProtocol::Unknown(255));
    }
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::IPv6HopByHop,
            1 => Self::ICMP,
            2 => Self::IGMP,
            6 => Self::TCP,
            17 => Self::UDP,
            58 => Self::ICMPv6,
            other => Self::Unknown(other),
        }
    }
}
