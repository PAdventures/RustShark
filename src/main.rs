mod application;
mod cli;
mod link;
mod network;
mod pcap_writer;
mod transport;
mod utils;

use pcap::Capture;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    link::ethernet::{EtherType, EthernetFrame},
    network::arp::ArpPacket,
    network::ipv4::IPv4Packet,
    network::ipv6::IPv6Packet,
    pcap_writer::{PcapWriter, link_type},
    transport::dispatch_transport,
    utils::timeval_to_string,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        eprintln!("\nCaught Ctrl+C, flushing and closing...");
        r.store(false, Ordering::SeqCst);
    })?;

    let matches = cli::cmd().get_matches();

    let debug_mode = matches.get_flag("debug");
    let immediate_mode = matches.get_flag("immediate");
    let interface = matches.get_one::<String>("interface").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();
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

    let mut packet_count = 0u64;

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

        pcap_out.write_packet(packet.data, orig_len)?;

        packet_count += 1;
        if packet_count % packet_limit == 0 {
            pcap_out.flush()?;
            eprintln!("Captured {packet_count} packets...");
        }

        let ethernet = match EthernetFrame::parse(packet.data) {
            Some(eth) => eth,
            None => continue,
        };

        match ethernet.ether_type {
            EtherType::IPv4 => {
                if let Some(ip) = IPv4Packet::parse(ethernet.payload) {
                    let _ = IPv4Packet::verify_checksum(ethernet.payload);
                    dispatch_transport(packet.header.ts, ip.protocol, ip.payload);
                }
            }
            EtherType::IPv6 => {
                if let Some(ip) = IPv6Packet::parse(ethernet.payload) {
                    dispatch_transport(packet.header.ts, ip.next_header, ip.payload);
                }
            }
            EtherType::ARP => {
                if let Some(arp) = ArpPacket::parse(ethernet.payload) {
                    if debug_mode {
                        println!("{} {:?}", timeval_to_string(packet.header.ts), arp)
                    } else {
                        println!("{} {arp}", timeval_to_string(packet.header.ts))
                    }
                };
            }
            EtherType::Unknown(t) => {
                println!(
                    "{} [Unknown EtherType: {t:#06X}]",
                    timeval_to_string(packet.header.ts)
                );
            }
        }
    }

    pcap_out.flush()?;
    eprintln!("Wrote {packet_count} packets to {output_file}");
    Ok(())
}
