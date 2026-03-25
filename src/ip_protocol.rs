#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpProtocol {
    ICMP,
    TCP,
    UDP,
    ICMPv6,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::ICMP,
            6 => Self::TCP,
            17 => Self::UDP,
            58 => Self::ICMPv6,
            other => Self::Unknown(other),
        }
    }
}
