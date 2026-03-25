mod arp;
mod cli;
mod ethernet;
mod ip_protcol;
mod ipv4;
mod ipv6;

use chrono::{TimeZone, Utc};
use libc::timeval;
use pcap::Capture;
use std::fs::OpenOptions;
use std::io::Write;

use crate::{
    arp::ArpPacket,
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
    let output_file = matches.get_one::<String>("output").unwrap();

    if debug_mode {
        println!("Debug mode is enabled")
    }

    let mut file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_file)
    {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Failed to open output file: {output_file}");
            return Ok(());
        }
    };

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
                        print!("{} {:?}", timeval_to_string(packet.header.ts), ip)
                    } else {
                        print!("{} {ip}", timeval_to_string(packet.header.ts))
                    }
                    println!("  Checksum valid: {valid}");

                    writeln!(
                        file,
                        "{} {ip}  Checksum valid: {valid}",
                        timeval_to_string(packet.header.ts)
                    )?;
                }
            }
            EtherType::IPv6 => {
                if let Some(ip) = IPv6Packet::parse(ethernet.payload) {
                    if debug_mode {
                        println!("{} {:?}", timeval_to_string(packet.header.ts), ip)
                    } else {
                        println!("{} {ip}", timeval_to_string(packet.header.ts))
                    }

                    writeln!(file, "{} {ip}", timeval_to_string(packet.header.ts))?;
                }
            }
            EtherType::ARP => {
                if let Some(arp) = ArpPacket::parse(ethernet.payload) {
                    if debug_mode {
                        println!("{} {:?}", timeval_to_string(packet.header.ts), arp)
                    } else {
                        println!("{} {arp}", timeval_to_string(packet.header.ts))
                    }

                    writeln!(file, "{} {arp}", timeval_to_string(packet.header.ts))?;
                };
            }
            EtherType::Unknown(t) => {
                println!(
                    "{} [Unknown EtherType: {t:#06X}]",
                    timeval_to_string(packet.header.ts)
                );

                writeln!(
                    file,
                    "{} [Unknown EtherType: {t:#06X}]",
                    timeval_to_string(packet.header.ts)
                )?;
            }
        }
    }

    Ok(())
}
