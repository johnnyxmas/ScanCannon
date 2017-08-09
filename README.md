![scancannon](http://oi43.tinypic.com/2vwwdpw.jpg)


ScanCannon v0.95
=========
The speed of masscan with the reliability and detailed enumeration of nmap!

Handles the enumeration of large networks, including banner grabbing & OS / service version guessing at high speed. Uses masscan to quickly identify open ports, then calls nmap to gain details on the systems / services listening on those ports. Data is stored in both masscan & nmap standard outputs, as well as a few other grepable intermediary files that include identified domains & subdomains, all nicely organized into per-network directories to make your boss think you know what you're doing.


CHANGELOG FOR v0.95:

* Fixed issue with some final catalogue files being generated
* Now moves nma *.xml files to their own directory to more easily suck them into other tools


TO-DO:

* Root domain detection for International TLDs (Such as .co.uk) doesn't work too well due to InterNIC, etc not complying with ARIN standards. Need to fix this.
* Add arguments for Masscan & nmap speeds
* Tarpit detection


Software Requirements:
=========
* GNU Utilities
* [Masscan v1.0.3+](https://github.com/robertdavidgraham/masscan)
* [nmap v7.0.1+](https://github.com/nmap/nmap)
* Root \ sudo privs (for TCP fingerprinting)

Usage:
=========
$ scancannon.sh [file . . .]

File contains a line-separated list of CIDR networks, i.e.:

	192.168.1.128/28
	172.110.80.250/30
	12.16.8.45/32
	172.0.0.0/8


Masscan & nmap arguments can be modified within the script.


WARNING:
=========
It is VERY FEASIBLE to execute a Denial of Service against the target networks, even when launching from a single source. You should start with a very low masscan max-rate (5,000-10,000 kpps) and increase slowly to test. On bare metal, pushing beyond 20,000 seems to increase the chances of missing responses from the target. 40,000 kpps has been known to DoS ESXi virtual switches (even on the source). ~200,000 is often enough to take out ISP equipment. 

Similar warnings exist for nmap, though it is much less dangerous. Some older or over-utilized LANs may hiccup with a Timing of T4 or T5, but this is rare. 


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
