# ScanCannon v1.5

![scancannon](https://i.imgur.com/jebggX7.png)

**A Bash script for efficient credentials-based attack surface enumeration and general reconnaissance of massive external network ranges.**

ScanCannon handles the enumeration of extremely large networks (such as The Internet) at high of speeds as the infrastructure can handle, specifically looking for credentials-based attack surfaces and APIs. It uses `masscan` to quickly identify open ports, then calls `nmap` to gain detailed information on the systems and services listening on those ports, thus compensating for the lack of acureacy in `masscan.` Final artifact is an array of flat text files full of IPs, hostnames, and interesting services that you can easily load up into the next tool in your killchain. 

## Table of Contents

- [What is ScanCannon?](#what-is-scancannon)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Progress Tracking](#progress-tracking)
- [Understanding Output](#understanding-output)
- [Safety & Legal Considerations](#safety--legal-considerations)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Known Issues](#known-issues)
- [License](#license)

## What is ScanCannon?

### Features

- **High-speed network enumeration** using masscan for initial discovery
- **Detailed service detection** using nmap for discovered hosts
- **API endpoint detection** using nmap NSE scripts and targeted curl probing (with `-a` flag)
- **Full ASN-based network discovery** — resolves all A records, queries `whois` for CIDR + ASN, then discovers ALL prefixes announced by the ASN via RADB. Works for both `-d` (domain) and `-c` (CIDR) inputs with interactive range selection.
- **Comprehensive output formats** including flat files for easy import into other tools
- **Automatic domain/subdomain discovery** from scan results
- **Service categorization** for common credential attack vectors (SSH, FTP, HTTP, SMB, etc.)
- **Advanced progress tracking** with real-time visual feedback, ETA calculations, and phase monitoring
- **Automatic cleanup** and file organization
- **Cross-platform support** (Linux, MacOS, WSL2)

### Target Services

ScanCannon focuses on these high-value services for security assessment:

**TCP Services:**

- **21** - FTP (File Transfer Protocol)
- **22** - SSH (Secure Shell)
- **23** - Telnet
- **53** - DNS (Domain Name System)
- **80** - HTTP (Web servers)
- **135** - MSRPC (Microsoft RPC)
- **139** - NetBIOS Session Service
- **443** - HTTPS (Secure web servers)
- **445** - Microsoft-DS (SMB/CIFS)
- **990** - SFTP (Secure FTP)
- **1701** - L2F (Layer 2 Forwarding)
- **1723** - PPTP (Point-to-Point Tunneling Protocol)

**UDP Services (with -u flag):**

- **53** - DNS (Domain Name System)
- **161** - SNMP (Simple Network Management Protocol)
- **500** - ISAKMP (Internet Security Association and Key Management Protocol)

*This focused approach dramatically reduces scan time while ensuring all high-value attack surface services are discovered.*

## Prerequisites


- **Root/Administrator privileges** (required for raw packet manipulation)
- **[Masscan v1.0.3+](https://github.com/robertdavidgraham/masscan)** - High-speed port scanner
- **[Nmap v7.0.1+](https://github.com/nmap/nmap)** - Network discovery and security auditing
- **Standard Unix tools**: `dig`, `whois`, `wget`, `awk`, `sed`
- **curl** *(optional, required for API endpoint detection with `-a` flag)*


## Quick Start

### Command Syntax

```bash
sudo ./scancannon.sh [-u] [-a] <-d domain | -c CIDR> [...]
```

At least one `-d` or `-c` flag is **required**. Both flags are repeatable and can be combined.

**Options:**
- `-d domain` : Discover all networks for a domain (resolves all A records → whois → ASN → RADB prefix lookup; repeatable; accepts URLs too)
- `-c CIDR` : Discover all networks related to a CIDR (whois → ASN → RADB prefix lookup; repeatable)
- `-u` : Perform UDP scan on common ports (53, 161, 500) using nmap (significantly slower)
- `-a` : Perform API endpoint detection on HTTP/HTTPS services (requires `curl`)

Both `-d` and `-c` run full ASN-based network discovery and present an interactive selection menu where you choose which discovered ranges to scan.

### Examples

```bash
# Scan a network by CIDR (includes ASN discovery of related networks)
sudo ./scancannon.sh -c 203.0.113.0/24

# Discover all networks for a domain (resolves all IPs → ASN → all announced prefixes)
sudo ./scancannon.sh -d example.com

# Combine domain + CIDR (both are scanned)
sudo ./scancannon.sh -d example.com -c 10.0.0.0/24

# Include UDP scanning (slower but more comprehensive)
sudo ./scancannon.sh -u -d example.com

# Include API endpoint detection
sudo ./scancannon.sh -a -c 203.0.113.0/24

# Combine all flags
sudo ./scancannon.sh -ua -d example.com -c 10.0.0.0/24
```

## Configuration

### Basic Configuration

The main configuration is handled through [`scancannon.conf`](scancannon.conf):

```bash
# Key settings you may want to adjust:
rate = 5000.00           # Packets per second (start low!)
excludefile = exclude.txt # Networks to exclude from scanning
# Only scan ports that ScanCannon actually uses - much more efficient!
ports = 21,22,23,53,80,135,139,443,445,990,1701,1723
```

### Exclusion List

Edit [`exclude.txt`](exclude.txt) to add networks you want to skip:

```bash
# Add networks to exclude (one per line)
192.168.0.0/16    # Private networks
10.0.0.0/8        # Private networks
172.16.0.0/12     # Private networks
127.0.0.0/8       # Loopback
```

### Automatic Network Configuration

ScanCannon automatically prompts for network adapter configuration every time you run it. This ensures optimal performance by helping masscan achieve maximum scanning speed. The script will:

1. **Detect network interfaces** and let you choose which one to use
2. **Automatically configure** adapter-ip and adapter-mac settings
3. **Find your default gateway** and configure router-mac settings
4. **Update scancannon.conf** with the detected settings

```bash
# Every time you run ScanCannon:
sudo ./scancannon.sh -c 192.168.1.0/24

# You'll always see:
=== Network Adapter Configuration ===
For optimal performance, ScanCannon can automatically configure your network adapter settings.
This helps masscan achieve maximum scanning speed by bypassing the kernel network stack.

Would you like to automatically configure network adapter settings? [y/N]: y

# If multiple interfaces exist:
Multiple network interfaces found:
  [1] eth0 - IP: 192.168.1.100, MAC: aa:bb:cc:dd:ee:ff
  [2] wlan0 - IP: 10.0.0.50, MAC: 11:22:33:44:55:66
Select interface [1-2]: 1

# Configuration is automatically applied to scancannon.conf
# Answer 'N' if you want to keep existing settings or configure manually
```

### Manual Network Configuration (Advanced)

If you prefer manual configuration or need to customize settings, you can edit [`scancannon.conf`](scancannon.conf) directly:

```bash
# Network adapter settings for maximum performance:
adapter-ip = 192.168.1.100    # Your machine's IP address
adapter-mac = aa:bb:cc:dd:ee:ff  # Your network card's MAC address
router-mac = 11:22:33:44:55:66   # Your router's MAC address
```

**Why These Settings Matter:**

- **`adapter-ip`**: Your machine's IP address on the scanning interface
  - Masscan uses this to craft packets with the correct source IP
  - Must match the IP of the interface you're scanning from
  
- **`adapter-mac`**: Your network card's MAC address
  - Used for raw packet transmission to bypass kernel networking
  - Improves performance by avoiding OS network stack overhead
  
- **`router-mac`**: Your default gateway's MAC address
  - Required for masscan to send packets directly to the router
  - Enables maximum scanning speed by bypassing ARP lookups

**When These Settings Help:**
- **High-speed scans** (>10,000 pps) - significantly improves performance
- **Large network ranges** - reduces packet loss and improves accuracy
- **Dedicated scanning systems** - maximizes hardware utilization
- **Virtual machines** - may be required for proper packet transmission

**Manual Detection Commands:**
```bash
# Linux - Get IP, MAC, and gateway:
ip addr show                    # Your IP and MAC
ip route show                   # Default gateway IP
arp -a | grep $(ip route | grep default | awk '{print $3}')  # Gateway MAC

# macOS - Get IP, MAC, and gateway:
ifconfig                        # Your IP and MAC
netstat -rn                     # Default gateway IP
arp -a | grep $(netstat -rn | grep default | awk '{print $2}')  # Gateway MAC
```

**Important**: Masscan requires MAC addresses in dash format (aa-bb-cc-dd-ee-ff), not colon format (aa:bb:cc:dd:ee:ff). The automatic configuration handles this conversion, but if configuring manually, ensure you use dashes.

## Understanding Output

ScanCannon creates organized output in the `results/` directory:

```
results/
├── 203_0_113_0_24/                    # Per-network results
│   ├── masscan_output.bin             # Binary masscan results
│   ├── masscan_output.txt             # Text masscan results
│   ├── hosts_and_ports.txt            # Discovered hosts:ports
│   ├── nmap_files/                    # Individual nmap scans
│   ├── gnmap_files/                   # Greppable nmap output
│   ├── nmap_xml_files/                # XML nmap output
│   ├── interesting_servers/           # Categorized services
│   │   ├── ssh_servers.txt            # SSH servers found
│   │   ├── http_servers.txt           # Web servers found
│   │   ├── ftp_servers.txt            # FTP servers found
│   │   ├── api_servers.txt            # API endpoints found (with -a)
│   │   ├── api_details.txt            # API detection details (with -a)
│   │   └── ...                        # Other services
│   ├── resolved_subdomains.txt        # Discovered domains
│   └── resolved_root_domains.csv      # Domain details with WHOIS
├── all_interesting_servers/           # Combined results
│   ├── all_ssh_servers.txt            # All SSH servers
│   ├── all_http_servers.txt           # All web servers
│   ├── all_api_servers.txt            # All API endpoints (with -a)
│   └── ...                            # Other combined lists
├── all_subdomains.txt                 # All discovered domains
├── all_root_domains.csv               # All domain details
└── dead_networks.txt                  # Unresponsive networks
```

## Safety & Legal Considerations

### ⚠️ **CRITICAL WARNING** ⚠️

**ScanCannon can easily cause Denial of Service conditions, even from a single source.**

### Rate Limiting Guidelines

| Network Type | Recommended Rate | Notes |
|--------------|------------------|-------|
| Home/SOHO | 1,000-5,000 pps | May crash consumer routers |
| Small Business | 5,000-10,000 pps | Monitor for connectivity issues |
| Enterprise | 10,000-20,000 pps | Test incrementally |
| ISP/Large Scale | 20,000+ pps | Can damage infrastructure |

### Best Practices

1. **Start Low**: Begin with `rate = 1000` and increase gradually
2. **Test First**: Scan a small subnet before large networks
3. **Monitor Impact**: Watch for network degradation
4. **Legal Compliance**: Only scan networks you own or have permission to test
5. **Backup Configs**: Save working configurations before changes

## Troubleshooting

### Common Issues

**"ERROR: masscan is not installed"**
```bash
# Install masscan using your package manager
sudo apt install masscan  # Ubuntu/Debian
```

**"ERROR: This script must be run as root"**
```bash
# Run with sudo
sudo ./scancannon.sh -c 192.168.1.0/24
```

**"No IPs are up; skipping nmap"**
- Check if the target network is actually reachable
- Verify your network configuration in `scancannon.conf`
- Try a lower scan rate
- Check firewall rules

**Scan seems to hang or is very slow**
- Reduce the `rate` setting in `scancannon.conf`
- Check network connectivity
- Verify target networks are responsive

**"bad MAC address" error from masscan**
- Masscan requires MAC addresses in dash format (aa-bb-cc-dd-ee-ff), not colon format (aa:bb:cc:dd:ee:ff)
- The automatic configuration now handles this conversion automatically
- If configuring manually, convert colons to dashes: `aa:bb:cc:dd:ee:ff` → `aa-bb-cc-dd-ee-ff`

## FAQ

### Don't `nmap` and `masscan` do the same thing? Why use both?

Masscan sacrifices accuracy for speed and may miss responses due to its aggressive scanning approach. ScanCannon uses masscan to quickly identify which IP addresses have listening services, then uses nmap's more reliable scanning against only those responsive hosts. This gives you both speed and accuracy.

### Doesn't Tool X do all of this and more? Why use this one?

Most enumeration tools try to be comprehensive "one-stop shops" but end up being mediocre at everything. ScanCannon focuses on doing network enumeration exceptionally well and outputs to standard, widely-compatible file formats that work with other specialized tools.

### How does API endpoint detection work?

When the `-a` flag is used, ScanCannon employs a two-tier detection approach:

1. **Tier 1 (Passive):** During nmap TCP enumeration, lightweight NSE scripts (`http-headers`, `http-title`, `http-robots.txt`, `http-server-header`) are added for HTTP ports. The resulting XML output is then parsed for API framework fingerprints (Express, Django, Flask, FastAPI, Spring, etc.), API-related response headers (CORS, `X-API-Version`, JSON content types), and documentation page titles (Swagger UI, GraphQL Playground, etc.).

2. **Tier 2 (Active):** For each discovered HTTP/HTTPS host, `curl` probes 14 well-known API paths including `/api`, `/api/v1`, `/swagger.json`, `/openapi.json`, `/graphql`, and others. Responses are classified as API endpoints based on JSON content types, known API path patterns, and authentication-required responses (401/403).

Results are written to `api_servers.txt` (clean endpoint list) and `api_details.txt` (full detection log with tier indicators).

### Why do I need root privileges?

Both masscan and nmap require raw socket access for SYN scanning and OS detection, which requires root privileges on Unix systems.

### Can I pause and resume scans?

Currently, ScanCannon doesn't support pause/resume functionality. For large scans, consider breaking them into smaller CIDR ranges.

### How do I scan IPv6 networks?

ScanCannon currently focuses on IPv4 networks. For IPv6 scanning, use nmap directly or consider other specialized tools.

## Known Issues

- **International TLD Detection**: Domain detection for international TLDs (like .co.uk, .io, etc.) may not work reliably due to varying WHOIS output standards (TODO?)

## License

This project is released under the Creative Commons Attribution-NonCommercial 3.0 Unported License.

![CC BY-NC](https://upload.wikimedia.org/wikipedia/commons/9/99/Cc-by-nc_icon.svg)

**You are free to:**
- **Share** — copy and redistribute the material in any medium or format
- **Adapt** — remix, transform, and build upon the material

**Under the following terms:**
- **Attribution** — You must give appropriate credit to all contributors, provide a link to the license, and indicate if changes were made
- **NonCommercial** — You may not use the material for commercial purposes

For the full license text, see [LICENSE](LICENSE).

---

**ScanCannon v1.5 by J0hnnyXm4s**

*"Efficient credential attack surface enumeration and general reconnaissance of massive network ranges"*
