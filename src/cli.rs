use clap::{Command, arg};

pub fn cmd() -> Command {
    Command::new("rustshark")
        .about("A packet sniffer")
        .arg(arg!(-d --debug ... "Enable debugging").action(clap::ArgAction::SetTrue))
        .arg(arg!(-i --interface [INTERFACE] ... "The interface to monitor").default_value("en0"))
        .arg(
            arg!(-o --output [FILE] ... "Output file to write packets to")
                .default_value("output.pcap"),
        )
}
