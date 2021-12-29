![scancannon](https://i.kym-cdn.com/photos/images/original/000/175/719/1155844718213mp8.jpg)


ScanCannon v1.0-beta
=========
A POSIX-compliant BASH script for efficient reconnaissance and attack prep against massive edge networks!

Handles the enumeration of large edge networks at high speed. Uses masscan to quickly identify open ports, then calls nmap to gain details on the systems / services listening on those ports. Data is stored in both masscan & nmap standard outputs, as well as a few other grepable intermediary files that include identified domains & subdomains, all nicely organized into per-network directories to make your boss think you know what you're doing. Most importantly (IMHO), quite a number of flat files are produced in IP:PORT format for highly-attackable services such as RDP, ssh, ftp and lots more!


CHANGES IN THIS VERSION:
=========
HOLY CRAP I MADE A v1.0!! This is a near-complete re-write, with lots of effort put into reducing duplicate scans and processing, and adding POSIX compliance (Native MacOS support!!). Many more flat files are produced for your consumption, and it's very easy to have the script look for anything else you specifically need (see comments). 


TO-DO:
=========

* Root domain detection for International TLDs (Such as .co.uk) doesn't work too well due to InterNIC, etc not complying with ARIN standards. Need to fix this.
* Tarpit detection
* Perform OS detection on systems which were discovered by UDP scan but NOT masscan (to avoide double-scanning)
* Add more customizability to scancannon.conf, such as ability to enable/disable certain scans


Software Requirements:
=========
* [Masscan v1.0.3+](https://github.com/robertdavidgraham/masscan)
* [nmap v7.0.1+](https://github.com/nmap/nmap)
* Root \ sudo privs (for various low-level network stack stuff)


Usage:
=========
$ scancannon.sh [file . . .]

File contains a line-separated list of CIDR networks, i.e.:

	192.168.1.128/28
	172.110.80.250/30
	12.16.8.45/32
	172.0.0.0/8

Masscan arguments can be modified within scancannon.conf. DO NOT add arguments which are already present in the script itself; these are hard-coded for a reason and changing them will break stuff. Be aware that Masscan first reads from /etc/masscan/masscan.conf and overides it with anything provided in scancannon.conf, so make sure you don't have anything inappropriate in there. 


WARNING:
=========
It is VERY FEASIBLE to execute a Denial of Service against the target networks, even when launching from a single source. You should start with a very low masscan max-rate (5,000-10,000 kpps) and increase slowly to test. Even 10,000 kpps can take down some SOHO routers (Is it the new deauth attack?). On bare metal, pushing beyond 20,000 seems to increase the chances of missing responses from the target. 40,000 kpps has been known to DoS ESXi virtual switches (even on the source). ~200,000 is often enough to take out ISP equipment (but will probably literally melt your NIC first). 



LICENSE
=========
This project is released under the Creative Commons Attribution-NonCommercial 3.0 Unported License.

![](https://upload.wikimedia.org/wikipedia/commons/9/99/Cc-by-nc_icon.svg)

You are free to:

* Share — copy and redistribute the material in any medium or format
* Adapt — remix, transform, and build upon the material
* The licensor cannot revoke these freedoms as long as you follow the license terms.

Under the following terms:

* [!]Attribution — You must give appropriate credit to all contributors to this project, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

* [!]NonCommercial — You may not use the material for commercial purposes.
No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

Notices:

You do not have to comply with the license for elements of the material in the public domain or where your use is permitted by an applicable exception or limitation.

No warranties are given.

For the full text of this license, see [LICENSE](https://github.com/johnnyxmas/ScanCannon/blob/master/LICENSE).
