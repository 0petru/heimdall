# Heimdall NIDS

![Heimdall Logo](https://norse-mythology.org/wp-content/uploads/2012/11/Heimdall_an_der_Himmelsbr%C3%BCcke.jpg)

A lightweight **Network Intrusion Detection System (NIDS)** and network traffic analyzer built with Python and Scapy.

![Heimdall](https://img.shields.io/badge/version-0.1-blue)
![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Overview

Heimdall provides four core modes for network security monitoring and packet analysis:

- **Sniffer** — Real-time packet capture with multiple output formats
- **Detector** — IDS-style rule-based threat detection
- **Logger** — Flexible packet logging with multiple storage type
- **NIDS** — Full network intrusion detection system mode

## Features

**Live and offline capture** — Support for live interfaces and PCAP files  
 **Flexible output formats** — Brief, verbose, hexdump, JSON, PCAP  
 **JSON/YAML rules** — Extensible rule format for threat detection  
 **Organized logging** — Organize captured packets by date, protocol, or IP

## Installation

### Requirements

- Python 3.10+
- Scapy (network packet library)
- PyYAML (optional, for YAML rule support)

### Setup

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/heimdall.git
cd heimdall
```

2. **Install in editable mode (recommended for development)**

```bash
pip install -e .
```

3. **Platform-specific setup**

**Windows:**

- Install [Npcap](https://nmap.org/npcap/) (Windows packet capture driver)
- Run cmd/PowerShell as Administrator for live packet capture

**Linux/macOS:**

- Install libpcap: `sudo apt-get install libpcap-dev` (Ubuntu/Debian)
- Run with `sudo` for live packet capture

## Quick Start

### 1. Sniffer Mode

Capture packets from a network interface:

```bash
# List available interfaces
python -m heimdall sniffer -li

# Capture packets with brief output
python -m heimdall sniffer -i eth0 -n 100 -d brief

# Capture to PCAP file
python -m heimdall sniffer -i eth0 -d pcap -O capture.pcap

# Apply BPF filter
python -m heimdall sniffer -i eth0 -f "tcp port 80 or tcp port 443" -d json
```

**Output formats:**

- `brief` — One-liner packet summary (default)
- `verbose` — Detailed packet information
- `hexdump` — Hexadecimal packet dump
- `json` — JSON-formatted layers
- `pcap` — PCAP binary format

### 2. Detector Mode

Run IDS detection on live traffic or PCAP files:

```bash
# Detect threats on live interface
python -m heimdall detector --rules rules/rules.json -i eth0 --alert-format fast

# Offline detection on PCAP file
python -m heimdall detector --rules rules/rules.json --pcap capture.pcap --alert-out alerts.txt

# JSON alert format
python -m heimdall detector --rules rules/rules.json -i eth0 --alert-format json
```

**Alert formats:**

- `fast` — Single-line Suricata-style alerts
- `json` — Detailed JSON alert objects

### 3. Logger Mode

Log all captured packets to disk:

```bash
# Log to disk organized by date
python -m heimdall logger -i eth0 --out logs/ --format pcap --organize-by date

# Organize by protocol
python -m heimdall logger -i eth0 --out logs/ --organize-by protocol

# Organize by source IP
python -m heimdall logger -i eth0 --out logs/ --organize-by src_ip

# Log from PCAP file
python -m heimdall logger --pcap capture.pcap --out logs/ --format json
```

**Organization strategies:**

- `date` — logs/2026-03-12/packets.pcap
- `protocol` — logs/tcp/packets.pcap
- `src_ip` — logs/192.168.1.100/packets.pcap
- `none` — All packets in single file

### 4. NIDS Mode

Full network intrusion detection system:

```bash
python -m heimdall nids --rules rules/rules.json --alert
```

## Rules Format

Heimdall uses JSON or YAML rules. Rules are simple pattern-matching detections based on:

- Protocol (TCP, UDP, ICMP, IP)
- Source/destination IP
- Source/destination port
- Payload content (substring matching)

### JSON Rule Example

```json
[
  {
    "id": 100001,
    "rev": 1,
    "enabled": true,
    "action": "alert",
    "msg": "Suspicious cmd.exe in HTTP traffic",
    "proto": "tcp",
    "src": "any",
    "src_port": "any",
    "dst": "any",
    "dst_port": 80,
    "content": "cmd.exe",
    "priority": 2,
    "classtype": "web-application-attack"
  }
]
```

### YAML Rule Example

```yaml
- id: 100001
  rev: 1
  enabled: true
  action: alert
  msg: "Suspicious HTTP pattern"
  proto: tcp
  src: any
  src_port: any
  dst: any
  dst_port: 80
  content: "admin.php"
  priority: 2
  classtype: "web-application-attack"
```

## Project Structure

```
heimdall/
├── setup.py                # Package installation configuration
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── INSTALL.md             # Detailed installation guide
├── RULES.md               # Rule format documentation
├── DEVELOPMENT.md         # Development guide
├── LICENSE                # MIT License
├── heimdall/
│   ├── __init__.py        # Package initialization
│   ├── __main__.py        # Entry point for python -m heimdall
│   ├── cli.py             # Command-line interface
│   ├── _imports.py        # Lazy imports for optional dependencies
│   ├── sniffer.py         # Packet sniffing and output formatting
│   ├── detector.py        # Rule matching and alert generation
│   ├── logger.py          # Alert logging
│   ├── packet_logger.py   # Packet logging and organization
│   ├── rules.py           # Rule loading and validation
│   ├── utils.py           # Utility functions
│   └── __pycache__/
└── rules/
    └── rules.json         # Default IDS rules
```

## Architecture

### Packet Flow

**Sniffer Mode:**

```
Live Interface / PCAP → Packet Queue → Worker Thread → Format & Output
```

**Detector Mode:**

```
Live Interface / PCAP → Normalization → Rule Matching → Alert Logging
```

### Key Components

- **Detector** — Normalizes packets to an Event and matches against rules
- **Alert** — Represents a matched rule with metadata
- **Rule** — Data structure for detection rules with validation
- **PacketLogger** — Organizes packets on disk by configurable strategy

## Performance Notes

- **Packet Queue:** 20,000 packet bounded queue prevents memory overload
- **Worker Threads:** Async packet processing for low latency
- **Rule Matching:** O(n) per packet; optimize by disabling unused rules

## Troubleshooting

### Permission Denied (Live Capture)

**Windows:** Run terminal as Administrator  
**Linux/macOS:** Use `sudo` or add user to `pcap` group

### Npcap Not Found (Windows)

Download and install [Npcap](https://nmap.org/npcap/)

### Scapy Import Error

```bash
pip install scapy
```

### YAML Rule Support

```bash
pip install pyyaml
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Roadmap

- [ ] Regex pattern support in rules
- [ ] Stateful TCP stream reassembly
- [ ] Connection tracking and rate limiting
- [ ] Multi-threaded detection pipeline (worker pool)
- [ ] Alert deduplication
- [ ] GeoIP enrichment
- [ ] Web dashboard

## License

MIT License — See LICENSE file for details

## Author

Developed by Ungureanu Calin Petru | timnik.com

---

**Questions?** Open an issue or check [INSTALL.md](INSTALL.md) and [RULES.md](RULES.md) for detailed guides.
