use std::fmt::Display;

#[derive(Debug)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub authcount: u16,
    pub addcount: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    pub authorities: Vec<DnsAnswer>,
    pub additionals: Vec<DnsAnswer>,
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsType,
}

#[derive(Debug)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: DnsType,
    pub ttl: u32,
    pub rdata: DnsRData,
}

#[derive(Debug)]
pub enum DnsType {
    A,
    NS,
    CNAME,
    SOA,
    WKS,
    PTR,
    HINFO,
    MX,
    TXT,
    AAAA,
    HTTPS,
    Unknown(u16),
}

impl DnsType {
    fn from_u16(v: u16) -> Self {
        match v {
            1 => DnsType::A,
            2 => DnsType::NS,
            5 => DnsType::CNAME,
            6 => DnsType::SOA,
            28 => DnsType::AAAA,
            65 => DnsType::HTTPS,
            v => DnsType::Unknown(v),
        }
    }
}

#[derive(Debug)]
pub enum DnsRData {
    A([u8; 4]),
    NS(String),
    CName(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    WKS {
        address: [u8; 4],
        protocol: u8,
        bitmap: Vec<u8>,
    },
    PTR(String),
    HINFO {
        cpu: String,
        os: String,
    },
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(String),
    AAAA([u8; 16]),
    Raw(Vec<u8>),
}

fn parse_name(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut jumped = false;
    let mut end_pos = pos;

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos];

        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        } else if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let offset = ((len as usize & 0x3F) << 8) | data[pos + 1] as usize;
            if !jumped {
                end_pos = pos + 2;
            }
            jumped = true;
            pos = offset;
        } else {
            pos += 1;
            if pos + len as usize > data.len() {
                return None;
            }
            let label = std::str::from_utf8(&data[pos..pos + len as usize]).ok()?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(label);
            pos += len as usize;
        }
    }

    Some((name, end_pos))
}

impl DnsMessage {
    pub fn parse(data: &[u8]) -> Option<Self> {
        fn parse_responses(data: &[u8], mut pos: usize) -> Option<DnsAnswer> {
            let Some((name, next_pos)) = parse_name(data, pos) else {
                return None;
            };
            pos = next_pos;
            if pos + 10 > data.len() {
                return None;
            }

            let rtype = DnsType::from_u16(u16::from_be_bytes([data[pos], data[pos + 1]]));
            let ttl =
                u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlen > data.len() {
                return None;
            }
            let rdata_bytes = &data[pos..pos + rdlen];

            let rdata = match rtype {
                DnsType::A if rdlen == 4 => DnsRData::A(rdata_bytes.try_into().unwrap()),
                DnsType::AAAA if rdlen == 16 => DnsRData::AAAA(rdata_bytes.try_into().unwrap()),
                DnsType::CNAME => parse_name(data, pos)
                    .map(|(n, _)| DnsRData::CName(n))
                    .unwrap_or(DnsRData::Raw(rdata_bytes.to_vec())),
                DnsType::NS => parse_name(data, pos)
                    .map(|(n, _)| DnsRData::NS(n))
                    .unwrap_or(DnsRData::Raw(rdata_bytes.to_vec())),
                DnsType::PTR => parse_name(data, pos)
                    .map(|(n, _)| DnsRData::PTR(n))
                    .unwrap_or(DnsRData::Raw(rdata_bytes.to_vec())),
                DnsType::SOA => {
                    let mname = parse_name(data, pos)?.0;
                    pos += mname.len() + 2; // name + null byte
                    let rname = parse_name(data, pos)?.0;
                    pos += rname.len() + 2;
                    if pos + 20 > data.len() {
                        return None;
                    }
                    let serial = u32::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]);
                    let refresh = u32::from_be_bytes([
                        data[pos + 4],
                        data[pos + 5],
                        data[pos + 6],
                        data[pos + 7],
                    ]);
                    let retry = u32::from_be_bytes([
                        data[pos + 8],
                        data[pos + 9],
                        data[pos + 10],
                        data[pos + 11],
                    ]);
                    let expire = u32::from_be_bytes([
                        data[pos + 12],
                        data[pos + 13],
                        data[pos + 14],
                        data[pos + 15],
                    ]);
                    let minimum = u32::from_be_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                    ]);

                    DnsRData::SOA {
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    }
                }
                DnsType::WKS if rdlen >= 5 => {
                    let address = rdata_bytes[0..4].try_into().unwrap();
                    let protocol = rdata_bytes[4];
                    let bitmap = rdata_bytes[5..].to_vec();
                    DnsRData::WKS {
                        address,
                        protocol,
                        bitmap,
                    }
                }
                DnsType::HINFO => {
                    let cpu_len = rdata_bytes[0] as usize;
                    pos += 1;
                    if pos + cpu_len > data.len() {
                        return None;
                    }
                    let cpu = std::str::from_utf8(&data[pos..pos + cpu_len])
                        .ok()?
                        .to_string();
                    pos += cpu_len;

                    if pos >= data.len() {
                        return None;
                    }
                    let os_len = rdata_bytes[cpu_len + 1] as usize;
                    pos += 1;
                    if pos + os_len > data.len() {
                        return None;
                    }
                    let os = std::str::from_utf8(&data[pos..pos + os_len])
                        .ok()?
                        .to_string();

                    DnsRData::HINFO { cpu, os }
                }
                DnsType::MX if rdlen >= 3 => {
                    let preference = u16::from_be_bytes([rdata_bytes[0], rdata_bytes[1]]);
                    let exchange = parse_name(data, pos + 2)?.0;
                    DnsRData::MX {
                        preference,
                        exchange,
                    }
                }
                DnsType::TXT => {
                    let txt_len = rdata_bytes[0] as usize;
                    if txt_len + 1 > rdata_bytes.len() {
                        return None;
                    }
                    let txt = std::str::from_utf8(&rdata_bytes[1..1 + txt_len])
                        .ok()?
                        .to_string();
                    DnsRData::TXT(txt)
                }
                _ => DnsRData::Raw(rdata_bytes.to_vec()),
            };

            pos += rdlen;

            Some(DnsAnswer {
                name,
                rtype,
                ttl,
                rdata,
            })
        }

        if data.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);

        let is_response = flags & 0x8000 != 0;
        let opcode = ((flags >> 11) & 0xF) as u8;
        let truncated = flags & 0x0200 != 0;
        let recursion_desired = flags & 0x0100 != 0;
        let recursion_available = flags & 0x0080 != 0;
        let rcode = (flags & 0x000F) as u8;

        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let authcount = u16::from_be_bytes([data[8], data[9]]);
        let addcount = u16::from_be_bytes([data[10], data[11]]);

        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additionals = Vec::new();

        let mut pos = 12;

        for _ in 0..qdcount {
            let Some((name, next_pos)) = parse_name(data, pos) else {
                return None;
            };
            pos = next_pos;
            if pos + 4 > data.len() {
                return None;
            }
            let qtype = DnsType::from_u16(u16::from_be_bytes([data[pos], data[pos + 1]]));
            pos += 4;

            questions.push(DnsQuestion { name, qtype });
        }

        for _ in 0..ancount {
            let answer = parse_responses(data, pos)?;
            answers.push(answer);
        }

        for _ in 0..authcount {
            let answer = parse_responses(data, pos)?;
            authorities.push(answer);
        }

        for _ in 0..addcount {
            let answer = parse_responses(data, pos)?;
            additionals.push(answer);
        }

        Some(Self {
            transaction_id: id,
            is_response,
            opcode,
            truncated,
            recursion_desired,
            recursion_available,
            rcode,
            qdcount,
            ancount,
            authcount,
            addcount,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl Display for DnsMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[DNS] {} {}  {}  {}  {}  {}",
            if self.is_response {
                "Response"
            } else {
                "Query"
            },
            self.transaction_id,
            self.questions
                .iter()
                .map(|q| q.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            self.answers
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            self.authorities
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            self.additionals
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

impl Display for DnsRData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRData::A(ip) => write!(
                f,
                "{}",
                ip.iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            ),
            DnsRData::AAAA(ip) => write!(
                f,
                "{}",
                ip.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .chunks(2)
                    .map(|c| c.join(""))
                    .collect::<Vec<_>>()
                    .join(":")
            ),
            DnsRData::CName(name) => write!(f, "{}", name),
            DnsRData::Raw(bytes) => write!(
                f,
                "0x{}",
                bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join("")
            ),
            DnsRData::SOA { mname, .. } => write!(f, "{}", mname),
            DnsRData::NS(ns) => write!(f, "{}", ns),
            DnsRData::PTR(ptr) => write!(f, "{}", ptr),
            DnsRData::HINFO { cpu, os } => write!(f, "{} {}", cpu, os),
            DnsRData::MX { exchange, .. } => write!(f, "{}", exchange),
            DnsRData::WKS { address, .. } => write!(
                f,
                "{}",
                address
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join("."),
            ),
            DnsRData::TXT(txt) => write!(f, "{}", txt),
        }
    }
}

impl Display for DnsQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {}", self.qtype, self.name)
    }
}

impl Display for DnsAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {}", self.rtype, self.rdata)
    }
}
