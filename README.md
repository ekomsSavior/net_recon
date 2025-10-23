# NET_RECON - Network Reconnaissance Tool

<div align="center">

**❤ ❤ ❤ NET-RECON ❤ ❤ ❤**  
*by ek0ms & savi0r*

![NET_RECON](https://img.shields.io/badge/NET_RECON-v2.0-red)
![Python](https://img.shields.io/badge/Python-3.6+-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple)

</div>

NET_RECON is a comprehensive network reconnaissance tool designed for authorized security testing and network analysis. It provides automated network discovery, vulnerability assessment, and lateral movement analysis in a single, powerful package.

**❤ FOR AUTHORIZED TESTING ONLY ❤**

### Features

- **Network Discovery**: Automatically scan and map your network
- **Port Scanning**: Identify open ports and running services  
- **Vulnerability Assessment**: Detect common security weaknesses
- **WiFi Analysis**: Discover access points and their security configurations
- **Topology Mapping**: Visualize network connections and relationships
- **Lateral Movement Analysis**: Identify potential attack paths
- **Professional Reporting**: Generate detailed JSON reports

##  Installation 

### Step 1: Clone the Repository

```bash
git clone https://github.com/ekomsSavior/net_recon.git
cd net_recon
```

### Step 2: Install Dependencies 

```bash
sudo apt update

sudo apt install -y python3 python3-pip

sudo apt install -y nmap

sudo apt install -y python3-nmap python3-scapy python3-requests

```
# Alternative: Install via pip if system packages fail

```bash
pip3 install --user python-nmap scapy requests
```

### Step 3: Verify Installation

```bash
# Check if nmap is installed
nmap --version

# Make the script executable
chmod +x net_recon.py

# Test run (without sudo first to check dependencies)
python3 net_recon.py
```

![image1(2)](https://github.com/user-attachments/assets/f50d8e37-9dab-4d0e-ad45-a3c3357d7a72)

## Usage

```bash

sudo python3 net_recon.py
```

### Step-by-Step Walkthrough

1. **Authorization Check**: 
   - The tool will ask "Hack the Planet? (yes/no)"
   - Type `yes` to continue

2. **Target Configuration**:
   - Enter a target name (for report identification)
   - Specify IP range (default: 192.168.1.0/24)

3. **Scan Execution**:
   - The tool automatically performs:
     - WiFi network discovery
     - Active host detection
     - Port scanning on found hosts
     - Vulnerability assessment
     - Network topology mapping
     - Lateral movement analysis

4. **Results**:
   - Comprehensive summary displayed in terminal
   - Detailed JSON report saved in `scan_reports/` directory
   - 
![image0(5)](https://github.com/user-attachments/assets/0d7454d4-7fc6-4e7c-bf93-f19e73885785)

## What NET_RECON Discovers

### Network Information
- Active hosts and their IP addresses
- MAC addresses and hostnames
- Open ports and running services
- Operating system detection

### Security Assessment
- Common service vulnerabilities
- Risky open ports (FTP, Telnet, SMB, RDP)
- Cleartext protocol usage
- Web service security headers
- Default credential service warnings

### Network Topology
- Device interconnections
- Lateral movement paths
- Potential attack vectors
- Exploitation suggestions


### Report Contents
Each JSON report includes:
- Scan metadata and timestamps
- Access point information
- Network node details with vulnerabilities
- Topology maps and connection paths
- Risk breakdown and critical findings
- Lateral movement analysis


###  PROPER USAGE

Only use NET_RECON on:
- Your own networks and systems
- Networks you have explicit written permission to test
- Isolated lab environments for educational purposes

---

*NET_RECON - Because knowing your network is the first step in securing it.* 

