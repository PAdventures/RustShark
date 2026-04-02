mod application;
mod cli;
mod dns_cache;
mod link;
mod network;
mod pcap_writer;
mod traits;
mod transport;
mod utils;

use bytes::Bytes;
use pcap::Capture;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::dns_cache::DnsCache;
use crate::network::NetworkPacket;
use crate::traits::Protocol;
use crate::{
    link::ethernet::{EtherType, EthernetFrame},
    network::arp::ArpPacket,
    network::ipv4::IPv4Packet,
    network::ipv6::IPv6Packet,
    pcap_writer::{PcapWriter, link_type},
    transport::parse_transport,
    utils::timeval_to_string,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let dns_cache = DnsCache::new_shared();

    ctrlc::set_handler(move || {
        eprintln!("\nCaught Ctrl+C, flushing and closing...");
        r.store(false, Ordering::SeqCst);
    })?;

    let matches = cli::cmd().get_matches();

    let debug_mode = matches.get_flag("debug");
    let immediate_mode = matches.get_flag("immediate");
    let no_resolve = matches.get_flag("no-resolve");
    let address = matches.get_flag("address");
    let interface = matches.get_one::<String>("interface").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();
    let filter = matches.get_one::<String>("filter").unwrap();
    let packet_limit = matches
        .get_one::<String>("packet-count")
        .unwrap()
        .parse::<u64>()
        .unwrap_or(100);

    if debug_mode {
        println!("Debug mode is enabled")
    }

    if immediate_mode {
        println!("Immediate mode is enabled")
    }

    let mut capture = Capture::from_device(interface.as_str())?
        .promisc(true)
        .immediate_mode(immediate_mode)
        .open()?;

    capture.filter(filter, true)?;

    let dlt = capture.get_datalink();
    let link = match dlt {
        pcap::Linktype::ETHERNET => link_type::ETHERNET,
        pcap::Linktype::RAW => link_type::RAW_IP,
        pcap::Linktype::LINUX_SLL => link_type::LINUX_SLL,
        pcap::Linktype::NULL => link_type::NULL,
        other => {
            eprintln!("Unsupported datalink: {:?}", other);
            std::process::exit(1);
        }
    };

    let mut pcap_out = PcapWriter::create(&output_file, 65535, link)?;

    println!("Sniffing on {interface}, writing to {output_file}");

    if !no_resolve {
        let cache_for_eviction = dns_cache.clone();

        thread::spawn(move || {
            println!("[DNS Cache] Eviction thread started");
            loop {
                thread::sleep(Duration::from_secs(60));
                if let Ok(mut cache) = cache_for_eviction.write() {
                    cache.evict_expired();
                    eprintln!(
                        "[DNS Cache] Evicted expired entries, {} remaining",
                        cache.len()
                    );
                }
            }
        });
    }

    let mut packet_count = 0u64;

    let cache_for_processing = if no_resolve {
        None
    } else {
        Some(&dns_cache.clone())
    };

    while running.load(Ordering::SeqCst) {
        let packet = match capture.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Capture error: {e}");
                break;
            }
        };

        let orig_len = packet.header.len;

        pcap_out.write_packet(packet.header.ts, packet.data, orig_len)?;

        packet_count += 1;
        if packet_count % packet_limit == 0 {
            pcap_out.flush()?;
            eprintln!("Captured {packet_count} packets...");
        }

        let mut ethernet = match EthernetFrame::parse(Bytes::copy_from_slice(packet.data)) {
            Some(eth) => eth,
            None => continue,
        };

        match ethernet.ether_type {
            EtherType::IPv4 => {
                if let Some(mut ip) = IPv4Packet::parse(ethernet.raw_payload.to_owned()) {
                    let _ = IPv4Packet::verify_checksum(ethernet.raw_payload.to_owned());
                    let result = parse_transport(
                        ip.protocol,
                        ip.raw_payload.to_owned(),
                        cache_for_processing,
                    );
                    ip.payload = result;
                    ethernet.payload = Some(NetworkPacket::IPv4(ip));
                }
            }
            EtherType::IPv6 => {
                if let Some(mut ip) = IPv6Packet::parse(ethernet.raw_payload.to_owned()) {
                    let result = parse_transport(
                        ip.next_header,
                        ip.raw_payload.to_owned(),
                        cache_for_processing,
                    );
                    ip.payload = result;
                    ethernet.payload = Some(NetworkPacket::IPv6(ip));
                }
            }
            EtherType::ARP => {
                if let Some(arp) = ArpPacket::parse(ethernet.raw_payload.to_owned()) {
                    ethernet.payload = Some(NetworkPacket::ARP(arp));
                };
            }
            EtherType::Unknown(t) => {
                println!(
                    "{packet_count} {} [Unknown EtherType: {t:#06X}]",
                    timeval_to_string(packet.header.ts)
                );
            }
        }

        if !address {
            println!(
                "{packet_count} {} {}",
                timeval_to_string(packet.header.ts),
                EthernetFrame::format_protocol(ethernet)
            );
            continue;
        }

        if let Some(network) = ethernet.payload.to_owned() {
            match network {
                NetworkPacket::IPv4(ipv4) => {
                    println!(
                        "{packet_count} {} {} → {} {}",
                        timeval_to_string(packet.header.ts),
                        utils::resolve_or_raw_v4(&ipv4.source_address, &dns_cache),
                        utils::resolve_or_raw_v4(&ipv4.destination_address, &dns_cache),
                        EthernetFrame::format_protocol(ethernet)
                    );
                    continue;
                }
                NetworkPacket::IPv6(ipv6) => {
                    println!(
                        "{packet_count} {} {} → {} {}",
                        timeval_to_string(packet.header.ts),
                        utils::resolve_or_raw_v6(&ipv6.source_address, &dns_cache),
                        utils::resolve_or_raw_v6(&ipv6.destination_address, &dns_cache),
                        EthernetFrame::format_protocol(ethernet)
                    );
                    continue;
                }
                NetworkPacket::ARP(_) => (),
            }
        }

        println!(
            "{packet_count} {} {} {} {}",
            timeval_to_string(packet.header.ts),
            utils::format_mac(&ethernet.source_mac),
            utils::format_mac(&ethernet.destination_mac),
            EthernetFrame::format_protocol(ethernet)
        );
    }

    pcap_out.flush()?;
    eprintln!("Wrote {packet_count} packets to {output_file}");
    Ok(())
}
