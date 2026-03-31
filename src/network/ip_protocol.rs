#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpProtocol {
    IPv6HopByHop,
    ICMP,
    TCP,
    UDP,
    ICMPv6,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::IPv6HopByHop,
            1 => Self::ICMP,
            6 => Self::TCP,
            17 => Self::UDP,
            58 => Self::ICMPv6,
            other => Self::Unknown(other),
        }
    }
}
