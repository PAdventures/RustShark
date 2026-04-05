use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    hostname: String,
    inserted_at: DateTime<Utc>,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Utc::now() > self.inserted_at + self.ttl
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Addr([u8; 4]);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6Addr([u8; 16]);

impl Serialize for Ipv4Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ip_str = format!("{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3]);
        serializer.serialize_str(&ip_str)
    }
}

impl<'de> Deserialize<'de> for Ipv4Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ip_str = String::deserialize(deserializer)?;
        let parts: Vec<&str> = ip_str.split('.').collect();
        if parts.len() != 4 {
            return Err(serde::de::Error::custom("Invalid IPv4 address format"));
        }
        let mut octets = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            octets[i] = part.parse::<u8>().map_err(|_| {
                serde::de::Error::custom(format!("Invalid octet '{}' in IPv4 address", part))
            })?;
        }
        Ok(Ipv4Addr(octets))
    }
}

impl Serialize for Ipv6Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ip_str = format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7],
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15]
        );
        serializer.serialize_str(&ip_str)
    }
}

impl<'de> Deserialize<'de> for Ipv6Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ip_str = String::deserialize(deserializer)?;
        let parts: Vec<&str> = ip_str.split(':').collect();
        if parts.len() != 8 {
            return Err(serde::de::Error::custom("Invalid IPv6 address format"));
        }
        let mut octets = [0u8; 16];
        for (i, part) in parts.iter().enumerate() {
            let segment = u16::from_str_radix(part, 16).map_err(|_| {
                serde::de::Error::custom(format!("Invalid segment '{}' in IPv6 address", part))
            })?;
            octets[i * 2] = (segment >> 8) as u8;
            octets[i * 2 + 1] = (segment & 0xFF) as u8;
        }
        Ok(Ipv6Addr(octets))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DnsCache {
    ipv4: HashMap<Ipv4Addr, CacheEntry>,
    ipv6: HashMap<Ipv6Addr, CacheEntry>,
}

pub type SharedDnsCache = Arc<RwLock<DnsCache>>;

impl DnsCache {
    pub fn new_shared() -> SharedDnsCache {
        Arc::new(RwLock::new(DnsCache::default()))
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer(file, self)?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> std::io::Result<SharedDnsCache> {
        let file = File::open(path)?;
        let mut cache: Self = serde_json::from_reader(file)?;
        cache.evict_expired();
        eprintln!("[DNS Cache] Loaded {} entries from DNS cache", cache.len());
        Ok(Arc::new(RwLock::new(cache)))
    }

    pub fn insert_a(&mut self, ip: [u8; 4], hostname: String, ttl_secs: u32) {
        self.ipv4.insert(
            Ipv4Addr(ip),
            CacheEntry {
                hostname,
                inserted_at: Utc::now(),
                ttl: Duration::from_secs(ttl_secs as u64),
            },
        );
    }

    pub fn insert_aaaa(&mut self, ip: [u8; 16], hostname: String, ttl_secs: u32) {
        self.ipv6.insert(
            Ipv6Addr(ip),
            CacheEntry {
                hostname,
                inserted_at: Utc::now(),
                ttl: Duration::from_secs(ttl_secs as u64),
            },
        );
    }

    pub fn resolve_v4(&self, ip: &[u8; 4]) -> Option<String> {
        self.ipv4
            .get(&Ipv4Addr(*ip))
            .filter(|e| !e.is_expired())
            .map(|e| e.hostname.clone())
    }

    pub fn resolve_v6(&self, ip: &[u8; 16]) -> Option<String> {
        self.ipv6
            .get(&Ipv6Addr(*ip))
            .filter(|e| !e.is_expired())
            .map(|e| e.hostname.clone())
    }

    pub fn evict_expired(&mut self) -> usize {
        let current_len = self.len();
        self.ipv4.retain(|_, e| !e.is_expired());
        self.ipv6.retain(|_, e| !e.is_expired());
        current_len - self.len()
    }

    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }
}
