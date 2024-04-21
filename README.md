# ScanCannon v1.1

![scancannon](https://i.imgur.com/FUvPADq.png)

**A Bash script for efficient enumeration of massive Internet network ranges.**

Handles the enumeration of large, internet-based networks at high speed. Uses masscan to quickly identify open ports, then calls nmap to gain details on the systems/services listening on those ports. 

- Provides tons of handy flat files for importing into other tools: 
  - `masscan` & `nmap` standard output files 
  - Discovered domains and subdomains
  - Highly-attackable services such as RDP, ssh, ftp
- Provides sacreenshots of discovered web pages

## FAQ

### Don't `nmap` and `masscan` do the same thing? Why use both?

Masscan, by nature of what makes it so fast, has a potential for losing packets and thus reporting false negatives during many scans. Thus, Masscan is used to identify which IP addresses have a listening host, then hands this full list off to Nmap. Nmap, on the other hand, is insanely slow when scanning massive networks which is why Masscan was created, so we use Masscan first to shrink the actual number of hosts to attempt to scan deeper. 

### Doesn't $Tool[x] do all of this and more? Why use this one?

While there is an ocean of tools for performing enumeration in this manner, everything wants to be the one-stop shop for attack surface and OSINT cataloging. This inevitably results in an AOL-level tool and interface that is good at a small number of things, but not great at the rest, and its output still requires a lot of annoying custom parsers to import into the better tools you want to use. This tool does a sparse few things, and outputs to universally-acceptaed flat files.

## Usage

`$ scancannon.sh [CIDR range | Targets file] -u 

`-u` Perform UDP scan on common ports (53, 161, 500) using nmap (very slow)

`Targets file` contains a line-separated list of CIDR networks

Masscan arguments can be modified within scancannon.conf. DO NOT add arguments that are already present in the script itself; these are hard-coded for a reason and changing them will break stuff. Be aware that Masscan first reads from its default conf file (usually /etc/masscan/masscan.conf) and overrides it with anything provided in scancannon.conf.

## Software Requirements

- [Masscan v1.0.3+](https://github.com/robertdavidgraham/masscan)
- [nmap v7.0.1+](https://github.com/nmap/nmap)

## WARNING

It is VERY FEASIBLE to execute a Denial of Service against the target networks, even when launching from a single source. You should start with a very low masscan max-rate (5,000-10,000 kpps) and increase slowly to test. Even 10,000 kpps can take down some SOHO routers (Is it the new deauth attack?). On bare metal, pushing beyond 20,000 seems to increase the chances of missing responses from the target. 40,000 kpps has been known to DoS ESXi virtual switches (even on the source). ~200,000 is often enough to take out ISP equipment (but will probably literally melt your NIC first).

## Known Issues

- Domain detection for International TLDs (Such as .co.uk) doesn't work too well due to InterNIC, etc. not complying with ARIN standards.

## LICENSE

This project is released under the Creative Commons Attribution-NonCommercial 3.0 Unported License.

![](https://upload.wikimedia.org/wikipedia/commons/9/99/Cc-by-nc_icon.svg)

You are free to:

- Share — copy and redistribute the material in any medium or format
- Adapt — remix, transform, and build upon the material
- The licensor cannot revoke these freedoms as long as you follow the license terms.

Under the following terms:

- [!]Attribution — You must give appropriate credit to all contributors to this project, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

- [!]NonCommercial — You may not use the material for commercial purposes.
No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

Notices:

You do not have to comply with the license for elements of the material in the public domain or where your use is permitted by an applicable exception or limitation.

No warranties are given.

For the full text of this license, see [LICENSE](https://github.com/johnnyxmas/ScanCannon/blob/master/LICENSE).
