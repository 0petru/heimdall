# Installation Guide

Detailed instructions for setting up Heimdall on different platforms.

## Table of Contents

- [System Requirements](#system-requirements)
- [Windows Installation](#windows-installation)
- [Linux Installation](#linux-installation)
- [macOS Installation](#macos-installation)
- [Verify Installation](#verify-installation)
- [Troubleshooting](#troubleshooting)

## System Requirements

- **Python:** 3.10 or higher
- **RAM:** 512MB minimum (1GB+ recommended for high packet rates)
- **Network:** Access to a network interface (Ethernet, WiFi)
- **Permissions:** Administrator/root access for live packet capture

## Windows Installation

### Step 1: Install Python

1. Download Python 3.10+ from [python.org](https://www.python.org/downloads/)
2. Run installer and check "Add Python to PATH"
3. Verify installation:

```powershell
python --version
```

### Step 2: Install Npcap

Npcap is required for packet capture on Windows:

1. Download from [nmap.org/npcap](https://nmap.org/npcap/)
2. Run installer
3. Choose "Install Npcap in WinPcap API-compatible Mode" during setup

### Step 3: Clone & Install Heimdall

```powershell
# Navigate to your dev directory
cd C:\Users\YourUsername\dev

# Clone the repo
git clone https://github.com/yourusername/heimdall.git
cd heimdall

# Install in editable mode (recommended)
pip install -e .
```

### Step 4: Run as Administrator

For live packet capture, run PowerShell/CMD as Administrator:

```powershell
# List interfaces
python -m heimdall sniffer -li

# Start sniffing
python -m heimdall sniffer -i Ethernet -n 100

# Or use the installed console script (if installed globally)
heimdall sniffer -i Ethernet -n 100
```

## Linux Installation

### Ubuntu/Debian

```bash
# Update package manager
sudo apt update

# Install Python and dependencies
sudo apt install python3.10 python3-pip libpcap-dev

# Navigate to your dev directory
cd ~/dev

# Clone the repo
git clone https://github.com/yourusername/heimdall.git
cd heimdall

# Install in editable mode (recommended)
pip install -e .

# OR install normally
pip install .
```

### Grant Permissions (Optional)

To run without `sudo`, add your user to the `pcap` group:

```bash
# Create pcap group if it doesn't exist
sudo groupadd pcap

# Add your user
sudo usermod -a -G pcap $USER

# Change ownership
sudo chown root:pcap /usr/sbin/dumpcap
sudo chmod 750 /usr/sbin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/dumpcap

# Log out and log back in for changes to take effect
```

### Test Installation

```bash
# List interfaces
python -m heimdall sniffer -li

# Sniff (with sudo if permissions not granted)
sudo python -m heimdall sniffer -i eth0 -n 10
```

## macOS Installation

### Using Homebrew

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and libpcap
brew install python@3.10 libpcap

# Navigate to dev directory
cd ~/dev

# Clone the repo
git clone https://github.com/yourusername/heimdall.git
cd heimdall

# Install in editable mode (recommended)
pip install -e .

# OR install normally
pip install .
```

### ChmodBPF (Optional)

For unprivileged packet capture:

```bash
# Install ChmodBPF
brew install chmodbpf

# Restart required
```

## Verify Installation

### Test 1: Import Check

```bash
python -c "import scapy; print('Scapy OK')"
```

### Test 2: List Interfaces

```bash
# Windows
python -m heimdall sniffer -li

# Linux/macOS (may need sudo)
sudo python -m heimdall sniffer -li
```

### Test 3: Sniff Live Traffic

```bash
python -m heimdall sniffer -i eth0 -n 5
```

### Test 4: Run Detector on PCAP

If you have a PCAP file:

```bash
python -m heimdall detector --rules rules/rules.json --pcap myfile.pcap
```

## Optional Dependencies

### PyYAML (YAML Rule Support)

```bash
pip install pyyaml
```

Then you can use YAML rules:

```bash
python -m heimdall detector --rules rules/rules.yaml -i eth0
```

## Troubleshooting

### Issue: "Module 'scapy' not found"

**Solution:**

```bash
pip install --upgrade scapy
```

### Issue: "Permission denied" on Linux/macOS

**Solution (Option 1 - Using sudo):**

```bash
sudo python -m heimdall sniffer -i eth0
```

**Solution (Option 2 - Grant permissions):**
See "Grant Permissions" section above.

### Issue: "No interfaces found" on Windows

**Solution:**

1. Verify Npcap is installed
2. Restart your computer
3. Run as Administrator

### Issue: Npcap silent install option missing

**Solution:**
Download the latest Npcap installer from https://nmap.org/npcap/

### Issue: "tcpdump not found" on macOS

**Solution:**

```bash
brew install tcpdump
```

### Issue: Low packet capture rate

**Possible causes:**

- OS filtering/buffering — Increase buffer size if available
- CPU bottleneck — Reduce output verbosity or use PCAP output
- Network load — Consider using BPF filters

**Solutions:**

```bash
# Use BPF filter to reduce packets
python -m heimdall sniffer -i eth0 -f "tcp port 80"

# Use efficient output format
python -m heimdall sniffer -i eth0 -d brief

# Process in batches with offline PCAP
python -m heimdall sniffer -i eth0 -d pcap -O capture.pcap
```

## Next Steps

After successful installation:

1. Read [README.md](README.md) for usage examples
2. Review [RULES.md](RULES.md) to create custom rules
3. Capture live traffic: `python -m heimdall sniffer -i eth0 -n 10`
4. For development, see [DEVELOPMENT.md](DEVELOPMENT.md)

## Support

If you encounter issues:

1. Check this guide for your OS
2. Review [Troubleshooting](#troubleshooting) section
3. Open an issue on GitHub with:
   - OS and Python version (`python --version`)
   - Error message (full traceback)
   - Command you ran
