# RustShark

RustShark is a Rust implementation of a packet sniffer, inspired by Wireshark.
It allows you to capture and analyse network traffic in real-time, providing insights into the data being transmitted over the network.

## Notes

The project is in early stages of development, and currently supports only a limited set of protocols. Future updates will include support for more protocols and additional features such as filtering and advanced analysis tools.

Furthermore, all developement is being done on MacOS, so there may be compatibility issues on other operating systems. Contributions and feedback are welcome to help improve the project and expand its capabilities.

## Platform Support

| Platform | Status                                               |
| -------- | ---------------------------------------------------- |
| macOS    | ✅ Fully supported — primary development platform    |
| Linux    | ⚠️ Best-effort — core functionality expected to work |
| Windows  | ❌ Not supported                                     |

## Usage

To use RustShark, you must first clone the repository and build the project using Cargo:

```zsh
git clone https://github.com/PAdventures/RustShark.git rustshark &&
cd rustshark &&
cargo build -r
```

Once the project is built, you can now run the packet sniffer using the following command:

```zsh
cargo run --release
```

When you run this command, by default, RustShark will attempt to capture packets on the "en0" network interface (which is the default network interface on MacOS) and will print out the decoded information of each packet in real-time.

For all options, run the following:

```zsh
cargo run --release -- --help
```

### Quick Examples

To capture packets on a specific network interface, use the `-i` or `--interface` option followed by the name of the interface. For example, to capture packets on the `en0` interface:

```zsh
cargo run --release -- --interface en0
```

To capture packets with a specific filter (see [BPF filter](https://biot.com/capstats/bpf.html)), use the `-f` or `--filter` option followed by the filter expression. For example, to capture only TCP packets:

```zsh
cargo run --release -- --filter "tcp"
```

To capture packets as soon as they arrive (instead of being buffered by the kernel), use the `-I` or `--immediate` option:

```zsh
cargo run --release -- --immediate
```

## Features

RustShark currently supports the following protocols:

- Ethernet II
- IPv4
- IPv6
- ARP
- ICMP(v6)
- IGMP
- TCP
- UDP
- HTTP
- DNS
- TLS
- QUIC (not 1-RRT/protected payloads)

RustShark will try to decode as many layers of the packet as possible, and will print out the decoded information in a human-readable format.
There is also the option for a debug mode which will print out all info and hexadecimal data of the payload, for the last layer of the packet.

RustShark will also store resolved DNS queries in a cache allowing for IPv4 or IPv6 addresses to be resolved to their corresponding domain names when possible, making it easier to understand the captured traffic.
DNS resolution caching is optionally persistant on program exit and will save the state of the cache to a `.json` file which can be loaded at the start of the program.
On loading the saved cache, all stale DNS enties will automatically be evicted.
_This feature is only supported for resolving IP addresses when the "--address" option is enabled which will print the IP address (or domain name) of the source and destination of each packet_

> Note: DNS resolution is an opt-out feature and address displaying is opt-in

As packets are captured, RustShark will also insert each packet into a `.pcap` file with the appropriate format (again, only tested for MacOS) and timestamp, allowing for later analysis using other tools such as Wireshark or tcpdump.
_This is a very useful feature for debugging and testing, as it allows you to capture packets in real-time and then analyse them later using a more powerful tool._
