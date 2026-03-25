mod cli;
mod ethernet;
mod ip_protcol;
mod ipv4;
mod ipv6;

use chrono::{TimeZone, Utc};
use libc::timeval;
use pcap::Capture;

use crate::{
    ethernet::{EtherType, EthernetFrame},
    ipv4::IPv4Packet,
    ipv6::IPv6Packet,
};

fn timeval_to_string(tv: timeval) -> String {
    let datetime = Utc.timestamp_opt(tv.tv_sec as i64, tv.tv_usec as u32 * 1000);
    datetime.unwrap().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli::cmd().get_matches();

    let debug_mode = matches.get_flag("debug");
    let interface = matches.get_one::<String>("interface").unwrap();

    if debug_mode {
        println!("Debug mode is enabled")
    }

    let mut capture = Capture::from_device(interface.as_str())?
        .promisc(true)
        .open()?;

    println!("Sniffing on interface: {interface}");

    while let Ok(packet) = capture.next_packet() {
        let ethernet = match EthernetFrame::parse(packet.data) {
            Some(eth) => eth,
            None => continue,
        };

        match ethernet.ether_type {
            EtherType::IPv4 => {
                if let Some(ip) = IPv4Packet::parse(ethernet.payload) {
                    let valid = IPv4Packet::verify_checksum(ethernet.payload);
                    if debug_mode {
                        println!("{} {:?}", timeval_to_string(packet.header.ts), ip)
                    } else {
                        println!("{} {ip}", timeval_to_string(packet.header.ts))
                    }
                    println!("Checksum valid: {valid}")
                }
            }
            EtherType::IPv6 => {
                if let Some(ip) = IPv6Packet::parse(ethernet.payload) {
                    if debug_mode {
                        println!("{} {:?}", timeval_to_string(packet.header.ts), ip)
                    } else {
                        println!("{} {ip}", timeval_to_string(packet.header.ts))
                    }
                }
            }
            EtherType::ARP => {
                println!(
                    "{} [ARP] ({} bytes)",
                    timeval_to_string(packet.header.ts),
                    ethernet.payload.len()
                );
            }
            EtherType::Unknown(t) => {
                println!(
                    "{} [Unknown EtherType: {t:#06X}]",
                    timeval_to_string(packet.header.ts)
                );
            }
        }
    }

    Ok(())
}
