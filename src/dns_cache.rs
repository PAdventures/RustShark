use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
struct CacheEntry {
    hostname: String,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

#[derive(Debug, Default)]
pub struct DnsCache {
    ipv4: HashMap<[u8; 4], CacheEntry>,
    ipv6: HashMap<[u8; 16], CacheEntry>,
}

pub type SharedDnsCache = Arc<RwLock<DnsCache>>;

impl DnsCache {
    pub fn new_shared() -> SharedDnsCache {
        Arc::new(RwLock::new(DnsCache::default()))
    }

    pub fn insert_a(&mut self, ip: [u8; 4], hostname: String, ttl_secs: u32) {
        self.ipv4.insert(
            ip,
            CacheEntry {
                hostname,
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(ttl_secs as u64),
            },
        );
    }

    pub fn insert_aaaa(&mut self, ip: [u8; 16], hostname: String, ttl_secs: u32) {
        self.ipv6.insert(
            ip,
            CacheEntry {
                hostname,
                inserted_at: Instant::now(),
                ttl: Duration::from_secs(ttl_secs as u64),
            },
        );
    }

    pub fn resolve_v4(&self, ip: &[u8; 4]) -> Option<String> {
        self.ipv4
            .get(ip)
            .filter(|e| !e.is_expired())
            .map(|e| e.hostname.clone())
    }

    pub fn resolve_v6(&self, ip: &[u8; 16]) -> Option<String> {
        self.ipv6
            .get(ip)
            .filter(|e| !e.is_expired())
            .map(|e| e.hostname.clone())
    }

    pub fn evict_expired(&mut self) {
        self.ipv4.retain(|_, e| !e.is_expired());
        self.ipv6.retain(|_, e| !e.is_expired());
    }

    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }
}
