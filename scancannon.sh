#!/bin/bash
set -euo pipefail

#Logging
LOG_FILE="scancannon.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "███████╗ ██████╗ █████╗ ███╗   ██╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗ ██████╗ ███╗   ██╗";
echo "██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔═══██╗████╗  ██║";
echo "███████╗██║     ███████║██╔██╗ ██║██║     ███████║██╔██╗ ██║██╔██╗ ██║██║   ██║██╔██╗ ██║";
echo "╚════██║██║     ██╔══██║██║╚██╗██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██║   ██║██║╚██╗██║";
echo "███████║╚██████╗██║  ██║██║ ╚████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║╚██████╔╝██║ ╚████║";
echo "╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝";

echo -e "••¤(×[¤ ScanCannon v1.0 by J0hnnyXm4s ¤]×)¤••\n"

#Help Text:
function helptext() {
echo -e "\nScanCannon: a program to enumerate and parse a large range of public networks, primarily for determining potential attack vectors"
echo "usage: scancannon.sh [-u] [CIDR range | file containing line-separated CIDR ranges]"
echo "  -u  Perform UDP scan on common ports (53, 161, 500) using nmap (very slow)"
}

#Check if required tools are installed
for tool in masscan nmap dig whois; do
if ! command -v "$tool" >/dev/null 2>&1; then
echo "ERROR: $tool is not installed. Please install it and try again."
exit 1
fi
done

#Parse command line options
UDP_SCAN=0
while getopts ":u" opt; do
case ${opt} in
u )
UDP_SCAN=1
;;
? )
echo "Invalid option: $OPTARG" 1>&2
helptext
exit 1
;;
esac
done
shift $((OPTIND -1))

#Make sure an argument is supplied:
if [ "$#" -ne 1 ]; then
echo "ERROR: Invalid argument(s)."
helptext >&2
exit 1
fi

#Check if the argument is a valid CIDR range or a file
if echo "$1" | grep -qE '^([0-9]{1,3}.){3}[0-9]{1,3}(/(3[0-2]|[12]?[0-9]))?$'; then
CIDR_RANGES=("$1")
elif [ -s "$1" ]; then
readarray -t CIDR_RANGES < "$1"
else
echo "ERROR: Invalid CIDR range or file."
helptext >&2
exit 1
fi

#Check for root:
if [ "$(id -u)" != "0" ]; then
echo "ERROR: This script must be run as root"
helptext >&2
exit 1
fi

#Check if MacOS
if [ "$(uname)" = "Darwin" ]; then
MACOS=1
else
MACOS=0
fi

#Alert for existing Results files
if [ -s "./results" ]; then
read -p "Results folder exists. New results will be combined with existing. Re-scanning previous subnets will overwrite some files. Proceed?" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
exit 1
fi
else
mkdir "results"
fi

#Download and prep the lastest list of TLDs from IANA
if [ -s "./all_tlds.txt" ]; then
rm "./all_tlds.txt"
fi
if ! wget https://data.iana.org/TLD/tlds-alpha-by-domain.txt -O "./all_tlds.txt"; then
echo "ERROR: Failed to download TLD list. Please check your internet connection and try again."
exit 1
fi
vi -c ':1d' -c ':%s/^/[.]/g' -c ':wq' "all_tlds.txt"

#Prep packet filter for masscan. If you are using something else, you MUST do this manually.
if [ "$MACOS" != 1 ]; then
if iptables -C INPUT -p tcp --dport 40000:41023 -j DROP 2>/dev/null; then
echo "Packet filter rule already exists. Skipping addition."
else
iptables -A INPUT -p tcp --dport 40000:41023 -j DROP
fi
else
cp /etc/pf.conf /etc/pf.bak
echo 'block in proto tcp from any to any port 40000 >< 41024' >>/etc/pf.conf
pfctl -f /etc/pf.conf
fi

#Initialize variables for summary
TOTAL_IPS=0
RESPONSIVE_IPS=0
DISCOVERED_SERVICES=0

#Process each CIDR range
for CIDR in "${CIDR_RANGES[@]}"; do
echo "Scanning $CIDR..."
#make results directories named after subnet:
DIRNAME="$(sed -e 's///_/g' <<<"$CIDR")"
echo "Creating results directory for $CIDR. . ."
mkdir -p "./results/$DIRNAME"
#Start Masscan. Write to binary file so users can --readscan it to whatever they need later:
echo -e "\n*** Firing ScanCannon. Please keep arms and legs inside the chamber at all times ***"
masscan -c scancannon.conf --open --source-port 40000 -oB "./results/$DIRNAME/masscan_output.bin" "$CIDR"
masscan --readscan "./results/$DIRNAME/masscan_output.bin" -oL "./results/$DIRNAME/masscan_output.txt"

#Update total IPs scanned
TOTAL_IPS=$((TOTAL_IPS + $(echo "$CIDR" | awk -F/ '{print 2^(32-$2)}')))

if [ ! -s "./results/$DIRNAME/masscan_output.txt" ]; then
    echo -e "\nNo IPs are up; skipping nmap. This was a big waste of time.\n"
    continue
fi

#Consolidate IPs and open ports for each IP:
awk '/open/ {print $4,$3,$2,$1}' "./results/$DIRNAME/masscan_output.txt" | awk '
        /.+/{
            if (!($1 in Val)) { Key[++i] = $1; }
            Val[$1] = Val[$1] $2 ",";
            }
    END{
        for (j = 1; j <= i; j++) {
            printf("%s:%s\n%s",  Key[j], Val[Key[j]], (j == i) ? "" : "");
        }
    }' | sed 's/,$//' >>"./results/$DIRNAME/hosts_and_ports.txt"

#Update responsive IPs count
RESPONSIVE_IPS=$((RESPONSIVE_IPS + $(awk '{print $1}' "./results/$DIRNAME/hosts_and_ports.txt" | sort -u | wc -l)))

#Run in-depth nmap enumeration against discovered hosts & ports, and output to all formats
#First we have to do a blind UDP nmap scan of common ports, as masscan does not support UDP. Note we Ping here to reduce scan time.
if [ "$UDP_SCAN" -eq 1 ]; then
    echo -e "\nStarting DNS, SNMP and VPN scan against all hosts"
    nmap -v --open -sV --version-light -sU -T3 -p 53,161,500 -oA ./results/"$DIRNAME"/nmap_"$DIRNAME"_udp "$CIDR"
fi
#Then nmap TCP against masscan-discovered hosts:
while read -r TARGET; do
    IP="$(echo "$TARGET" | awk -F: '{print $1}')"
    PORT="$(echo "$TARGET" | awk -F: '{print $2}')"
    FILENAME="$(echo "$IP" | awk '{print "nmap_"$1}')"
    echo -e "\nBeginning in-depth TCP scan of $IP on port(s) $PORT:\n"
    nmap -v --open -sV --version-light -sT -O -Pn -T3 -p "$PORT" -oA "./results/$DIRNAME/${FILENAME}_tcp" "$IP"
done <"./results/$DIRNAME/hosts_and_ports.txt"

#Generate lists of Hosts:Ports hosting Interesting Services™️ for importing into cred stuffers (or other tools)
mkdir -p "./results/$DIRNAME/interesting_servers/"
mkdir -p "./results/all_interesting_servers/"
#(if you add to this service list, make sure you also add it to the master file generation list at the end.)
for SERVICE in domain msrpc snmp netbios-ssn microsoft-ds isakmp l2f pptp ftp sftp ssh telnet http ssl https; do
    if RESULT="$(grep -h -o -E "$SERVICE/.+/.+\d+/open/.+/$SERVICE" ./results/"$DIRNAME"/*.gnmap)"; then
        SERVIP="$(echo "$RESULT" | tr -d '\n' < <(awk -F" " '{print $2}'))"
        SERVPORT="$(echo "$RESULT" | awk -F"/" '{print $3}')"
    fi
    if [ -n "${SERVIP:-}" ]; then
        echo "$SERVIP":"$SERVPORT" | tee "./results/$DIRNAME/interesting_servers/${SERVICE}_servers.txt" >>"./results/all_interesting_servers/all_${SERVICE}_servers.txt"
        DISCOVERED_SERVICES=$((DISCOVERED_SERVICES + 1))
        unset SERVIP
        unset SERVPORT
    fi
done

#Generate list of discovered sub/domains for this subnet.
echo "Root Domain,IP,CIDR,AS#,IP Owner" | tee "./results/$DIRNAME/resolved_root_domains.csv" >>"./results/all_root_domains.csv"
while read -r TLD; do
    grep -E -i "$TLD" "./results/$DIRNAME"/*.gnmap | awk -F[\(\)] '{print $2}' | sort -u | tee "./results/$DIRNAME/resolved_subdomains.txt" >>"./results/all_subdomains.txt"
done <"./all_tlds.txt"
while read -r DOMAIN; do
    DIG="$(dig "$DOMAIN" +short)"
    if [ -n "$DIG" ]; then
        WHOIS="$(whois "$DIG" | awk -F':[ ]*' '
                /CIDR:/ { cidr = $2 };
                /Organization:/ { org = $2};
                /OriginAS:/ { print cidr","$2","org}')"
        echo "$DOMAIN"",""$DIG"",""$WHOIS" | tee "./results/$DIRNAME/resolved_root_domains.csv" >>"./results/all_root_domains.csv"
    fi
done < <(awk -F. '{ print $(NF-1)"."$NF }' "./results/$DIRNAME/resolved_subdomains.txt")
done

#Restore packet filter backup
echo -e "\nAll scans completed. Reverting packet filter configuration. . . "
if [ "$MACOS" != 1 ]; then
iptables -D INPUT -p tcp --dport 40000:41023 -j DROP
else
mv /etc/pf.bak /etc/pf.conf
pfctl -q -f /etc/pf.conf
fi

#Report unresponsive networks:
comm -3 <(printf "%s\n" .///gnmap | sed 's//[^/]+$//' | sort -u) <(printf "%s\n" .//*) | awk -F"/" '{print $2}' | sed 's/_///g' >>"./results/dead_networks.txt"

#Housekeeping
function cleanup() {
echo -e "\nPerforming cleanup. . . "
rm ./paused.conf
for DIRECTORY in ./results//; do
#mkdir -p "$DIRECTORY"{nmap_files,gnmap_files,nmap_xml_files}
mv -f "$DIRECTORY".nmap "$DIRECTORY"nmap_files/ 2>/dev/null
mv -f "$DIRECTORY".gnmap "$DIRECTORY"gnmap_files/ 2>/dev/null
mv -f "$DIRECTORY".xml "$DIRECTORY"nmap_xml_files/ 2>/dev/null
rm -rf "./results/all_interesting_servers/"*_files 2>/dev/null
done
chmod -R 776 "./results"
}
cleanup

#Print summary
echo -e "\nScan Summary:"
echo "Total IPs Scanned: $TOTAL_IPS"
echo "Responsive IPs: $RESPONSIVE_IPS"
echo "Discovered Services: $DISCOVERED_SERVICES"

echo -e "\n【 Powering down ScanCannon. Please check for any personal belongings before exiting the shell 】"