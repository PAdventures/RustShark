use clap::{Command, arg};

pub fn cmd() -> Command {
    Command::new("rustshark")
        .about("A packet sniffer")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(arg!(-d --debug ... "Enable debugging").action(clap::ArgAction::SetTrue))
        .arg(arg!(-I --immediate ... "Enable immediate mode").action(clap::ArgAction::SetTrue))
        .arg(arg!(--"no-resolve" ... "Disable DNS resolution").action(clap::ArgAction::SetTrue))
        .arg(arg!(-a --address ... "Display MAC or IP addresses before packet details").action(clap::ArgAction::SetTrue))
        .arg(arg!(-s --"save-cache" ... "Save DNS resolution cache to file on exit").action(clap::ArgAction::SetTrue))
        .arg(arg!(-l --"load-cache" ... "Load DNS resolution from cache on start").action(clap::ArgAction::SetTrue))
        .arg(arg!(-i --interface <INTERFACE> ... "The interface to monitor").default_value("en0"))
        .arg(
            arg!(-o --output <FILE> ... "Output file to write packets to")
                .default_value("capture.pcap"),
        )
        .arg(arg!(-p --"packet-count" <COUNT> ... "The number of packets to store before flushing to disk").default_value("100"))
        .arg(arg!(-f --filter <FILTER> ... "The BPF filter to apply to the capture").default_value(""))
        .arg(arg!(-e --"eviction-interval" <SECONDS> ... "Interval in seconds to evict expired DNS cache entries. Low values may impact performance and are not recommended").default_value("60"))
        .arg(arg!(--"save-dns" <FILE> ... "File to save DNS resolution cache to").default_value("dns_cache.json"))
       	.arg(arg!(--"load-dns" <FILE> ... "File to load DNS resolution cache from").default_value("dns_cache.json"))
}
