use chrono::{TimeZone, Utc};
use libc::timeval;

use crate::dns_cache::SharedDnsCache;

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

pub fn format_bytes(bytes: &Vec<u8>) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

pub fn resolve_or_raw_v4(ip: &[u8; 4], cache: &SharedDnsCache) -> String {
    if let Ok(cache) = cache.read() {
        if let Some(hostname) = cache.resolve_v4(ip) {
            return hostname;
        }
    }

    format_ipv4(ip)
}

pub fn resolve_or_raw_v6(ip: &[u8; 16], cache: &SharedDnsCache) -> String {
    if let Ok(cache) = cache.read() {
        if let Some(hostname) = cache.resolve_v6(ip) {
            return hostname;
        }
    }

    format_ipv6(ip)
}
