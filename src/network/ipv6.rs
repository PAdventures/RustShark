use std::fmt::{Debug, Display};

use crate::network::ip_protocol::IpProtocol;

pub struct IPv6Packet<'a> {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub payload: &'a [u8],
}

impl<'a> IPv6Packet<'a> {
    /// IPv6 fixed header (RFC 8200) is always 40 bytes:
    /// ```
    ///  0               1               2               3
    ///  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Version| Traffic Class |            Flow Label                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Payload Length        |  Next Header  |   Hop Limit   |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Source Address                        |
    /// |                          (128 bits)                           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                      Destination Address                      |
    /// |                          (128 bits)                           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }

        let version = (data[0] >> 4) & 0xF;

        if version != 6 {
            return None;
        }

        let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
        let flow_label = u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]);
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = IpProtocol::from(data[6]);
        let hop_limit = data[7];
        let src: [u8; 16] = data[8..24].try_into().unwrap();
        let dst: [u8; 16] = data[24..40].try_into().unwrap();
        let payload = &data[40..];

        Some(Self {
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source_address: src,
            destination_address: dst,
            payload,
        })
    }

    pub fn fmt_ip(ip: &[u8; 16]) -> String {
        // Condense to standard colon-hex notation
        let groups: Vec<String> = ip
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect();
        groups.join(":")
    }
}

impl Display for IPv6Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv6] {} → {}  Hop Limit: {}  Next: {:?}  PayloadLen: {}",
            Self::fmt_ip(&self.source_address),
            Self::fmt_ip(&self.destination_address),
            self.hop_limit,
            self.next_header,
            self.payload_length
        )
    }
}

impl Debug for IPv6Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[IPv6] {} → {}  Traffic Class: {}  Flow Label: {}  PayloadLen: {}  Next: {:?}  Hop Limit: {}  Payload: {:?}",
            Self::fmt_ip(&self.source_address),
            Self::fmt_ip(&self.destination_address),
            self.traffic_class,
            self.flow_label,
            self.payload_length,
            self.next_header,
            self.hop_limit,
            self.payload
        )
    }
}
