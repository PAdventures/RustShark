# Contributing

## Platform Support

| Platform | Status                                               |
| -------- | ---------------------------------------------------- |
| macOS    | ✅ Fully supported — primary development platform    |
| Linux    | ⚠️ Best-effort — core functionality expected to work |
| Windows  | ❌ Not supported                                     |

### Prerequisites

RustShark requires `libpcap` to be installed:

- **macOS:** included with Xcode Command Line Tools (`xcode-select --install`)
- **Linux (Debian/Ubuntu):** `sudo apt install libpcap-dev`
- **Linux (Fedora/RHEL):** `sudo dnf install libpcap-devel`

Packet capture requires elevated privileges. Run with `sudo`, or on Linux grant `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw+ep ./rustshark
```
