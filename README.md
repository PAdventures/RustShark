# RustShark

RustShark is a Rust implementation of a packet sniffer, inspired by Wireshark.
It allows you to capture and analyse network traffic in real-time, providing insights into the data being transmitted over the network.

## Usage

Default use

```bash
cargo run
```

Custom interface

```bash
cargo run -- --interface <interface_name>
```

Debug mode (very verbose)

```bash
cargo run -- --debug
```
