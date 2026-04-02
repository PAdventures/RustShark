use chrono::{TimeZone, Utc};
use libc::timeval;

pub fn timeval_to_string(tv: timeval) -> String {
    let datetime = Utc.timestamp_opt(tv.tv_sec as i64, tv.tv_usec as u32 * 1000);
    datetime.unwrap().to_string()
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn format_ipv4(ip: &[u8; 4]) -> String {
    ip.iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

pub fn format_ipv6(ip: &[u8; 16]) -> String {
    let groups: Vec<String> = ip
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    groups.join(":")
}
