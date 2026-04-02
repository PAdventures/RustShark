use clap::{Command, arg};

pub fn cmd() -> Command {
    Command::new("rustshark")
        .about("A packet sniffer")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(arg!(-d --debug ... "Enable debugging").action(clap::ArgAction::SetTrue))
        .arg(arg!(-I --immediate ... "Enable immediate mode").action(clap::ArgAction::SetTrue))
        .arg(arg!(--"no-resolve" ... "Disable DNS resolution").action(clap::ArgAction::SetTrue))
        .arg(arg!(-a --address ... "Display MAC or IP addresses before packet details").action(clap::ArgAction::SetTrue))
        .arg(arg!(-i --interface <INTERFACE> ... "The interface to monitor").default_value("en0"))
        .arg(
            arg!(-o --output <FILE> ... "Output file to write packets to")
                .default_value("capture.pcap"),
        )
        .arg(arg!(-p --"packet-count" <COUNT> ... "The number of packets to store before flushing to disk").default_value("100"))
        .arg(arg!(-f --filter <FILTER> ... "The BPF filter to apply to the capture").default_value(""))
    .    arg(arg!(-e --"eviction-interval" <SECONDS> ... "Interval in seconds to evict expired DNS cache entries. Low values may impact performance and are not recommended").default_value("60"))
}
