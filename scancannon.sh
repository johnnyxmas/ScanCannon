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

echo -e "••¤(×[¤ ScanCannon v1.2 by J0hnnyXm4s ¤]×)¤••\n"

# Check for updates
# Use the same branch name for checking and pulling
REMOTE_TIMESTAMP1=$(git log origin/master -n 1 --pretty=format:%cd scancannon.sh | awk '{print $1, $3, $2, $5, $4}')
LOCAL_TIMESTAMP=$(date -r "scancannon.sh" +%s)
#Check if MacOS
if [ "$(uname)" = "Darwin" ]; then
MACOS=1
REMOTE_TIMESTAMP=$(date -j -f "%a %d %b %Y %T" "$REMOTE_TIMESTAMP1" +%s)
else
MACOS=0
REMOTE_TIMESTAMP=$(date -d "$REMOTE_TIMESTAMP1" +%s)
fi

if [[ "$REMOTE_TIMESTAMP" > "$LOCAL_TIMESTAMP" ]]; then
    read -r -p "A new version of ScanCannon is available. Do you want to update? [y/N]: " update_choice
    case "$update_choice" in
        y|Y )
            if git pull origin master; then
                echo "ScanCannon has been updated successfully."
            else
                echo "Failed to update ScanCannon via git. Please manually download the latest version from https://github.com/johnnyxmas/ScanCannon/"
            fi
            ;;
        * )
            echo "Update skipped. Continuing with the current version."
            ;;
    esac
fi

#Help Text:
function helptext() {
echo -e "\nScanCannon: a program to enumerate and parse a large range of public networks, primarily for determining potential attack vectors"
echo "usage: scancannon.sh [-u] [CIDR range | file containing line-separated CIDR ranges]"
echo "  -u  Perform UDP scan on common ports (53, 161, 500) using nmap"
}

#Check if required tools are installed
for tool in masscan nmap dig whois; do
if ! command -v "$tool" >/dev/null 2>&1; then
echo "ERROR: $tool is not installed. Please install it and try again."
exit 1
fi
done

# Check if masscan configuration file exists
if [ ! -f "scancannon.conf" ]; then
    echo "ERROR: scancannon.conf not found. Please ensure the configuration file exists."
    exit 1
fi

# Function to detect network interfaces
function detect_interfaces() {
    if [ "$MACOS" -eq 1 ]; then
        # macOS interface detection
        ifconfig | grep -E "^[a-z]" | grep -v "lo0" | awk -F: '{print $1}' | grep -E "^(en|eth|wlan)"
    else
        # Linux interface detection
        ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | awk -F: '{print $2}' | tr -d ' ' | grep -E "^(eth|ens|enp|wlan|wlp)"
    fi
}

# Function to get interface details
function get_interface_details() {
    local interface="$1"
    if [ "$MACOS" -eq 1 ]; then
        # macOS
        local ip=$(ifconfig "$interface" | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | head -1)
        local mac=$(ifconfig "$interface" | grep "ether" | awk '{print $2}' | head -1)
        echo "$ip|$mac"
    else
        # Linux
        local ip=$(ip addr show "$interface" | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d'/' -f1 | head -1)
        local mac=$(ip link show "$interface" | grep "link/ether" | awk '{print $2}' | head -1)
        echo "$ip|$mac"
    fi
}

# Function to detect default gateway
function detect_gateways() {
    if [ "$MACOS" -eq 1 ]; then
        # macOS
        netstat -rn | grep "default" | awk '{print $2}' | sort -u
    else
        # Linux
        ip route | grep "default" | awk '{print $3}' | sort -u
    fi
}

# Function to get gateway MAC
function get_gateway_mac() {
    local gateway_ip="$1"
    if [ "$MACOS" -eq 1 ]; then
        # macOS - ping first to populate ARP table
        ping -c 1 "$gateway_ip" >/dev/null 2>&1
        arp -n "$gateway_ip" 2>/dev/null | awk '{print $4}' | head -1
    else
        # Linux - ping first to populate ARP table
        ping -c 1 "$gateway_ip" >/dev/null 2>&1
        ip neigh show "$gateway_ip" 2>/dev/null | awk '{print $5}' | head -1
    fi
}

# Function to configure network adapter settings
function configure_adapter() {
    echo ""
    echo "=== Network Adapter Configuration ==="
    echo "For optimal performance, ScanCannon can automatically configure your network adapter settings."
    echo "This helps masscan achieve maximum scanning speed by bypassing the kernel network stack."
    echo ""
    read -r -p "Would you like to automatically configure network adapter settings? [y/N]: " auto_config
    
    if [[ ! $auto_config =~ ^[Yy]$ ]]; then
        echo "Skipping automatic network configuration."
        return
    fi
    
    # Detect interfaces
    echo "Detecting network interfaces..."
    local interfaces=($(detect_interfaces))
    
    if [ ${#interfaces[@]} -eq 0 ]; then
        echo "No suitable network interfaces found. Skipping automatic configuration."
        return
    fi
    
    local selected_interface=""
    local selected_ip=""
    local selected_mac=""
    
    if [ ${#interfaces[@]} -eq 1 ]; then
        selected_interface="${interfaces[0]}"
        echo "Found interface: $selected_interface"
    else
        echo "Multiple network interfaces found:"
        for i in "${!interfaces[@]}"; do
            local details=$(get_interface_details "${interfaces[$i]}")
            local ip=$(echo "$details" | cut -d'|' -f1)
            local mac=$(echo "$details" | cut -d'|' -f2)
            echo "  [$((i+1))] ${interfaces[$i]} - IP: $ip, MAC: $mac"
        done
        echo ""
        read -r -p "Select interface [1-${#interfaces[@]}]: " interface_choice
        
        if [[ "$interface_choice" =~ ^[0-9]+$ ]] && [ "$interface_choice" -ge 1 ] && [ "$interface_choice" -le ${#interfaces[@]} ]; then
            selected_interface="${interfaces[$((interface_choice-1))]}"
        else
            echo "Invalid selection. Skipping automatic configuration."
            return
        fi
    fi
    
    # Get interface details
    local details=$(get_interface_details "$selected_interface")
    selected_ip=$(echo "$details" | cut -d'|' -f1)
    selected_mac=$(echo "$details" | cut -d'|' -f2)
    
    if [ -z "$selected_ip" ] || [ -z "$selected_mac" ]; then
        echo "Could not determine IP or MAC for interface $selected_interface. Skipping automatic configuration."
        return
    fi
    
    echo "Selected interface: $selected_interface"
    echo "  IP: $selected_ip"
    echo "  MAC: $selected_mac"
    
    # Detect gateways
    echo "Detecting default gateways..."
    local gateways=($(detect_gateways))
    
    if [ ${#gateways[@]} -eq 0 ]; then
        echo "No default gateway found. Skipping gateway configuration."
        echo "You may need to manually configure router-mac in scancannon.conf"
    else
        local selected_gateway=""
        local selected_gateway_mac=""
        
        if [ ${#gateways[@]} -eq 1 ]; then
            selected_gateway="${gateways[0]}"
            echo "Found gateway: $selected_gateway"
        else
            echo "Multiple gateways found:"
            for i in "${!gateways[@]}"; do
                echo "  [$((i+1))] ${gateways[$i]}"
            done
            echo ""
            read -r -p "Select gateway [1-${#gateways[@]}]: " gateway_choice
            
            if [[ "$gateway_choice" =~ ^[0-9]+$ ]] && [ "$gateway_choice" -ge 1 ] && [ "$gateway_choice" -le ${#gateways[@]} ]; then
                selected_gateway="${gateways[$((gateway_choice-1))]}"
            else
                echo "Invalid selection. Skipping gateway configuration."
                selected_gateway=""
            fi
        fi
        
        if [ -n "$selected_gateway" ]; then
            echo "Getting MAC address for gateway $selected_gateway..."
            selected_gateway_mac=$(get_gateway_mac "$selected_gateway")
            
            if [ -n "$selected_gateway_mac" ]; then
                echo "Gateway MAC: $selected_gateway_mac"
            else
                echo "Could not determine MAC for gateway $selected_gateway."
                echo "You may need to manually configure router-mac in scancannon.conf"
            fi
        fi
    fi
    
    # Update configuration file
    echo ""
    echo "Updating scancannon.conf with detected settings..."
    
    # Create backup
    cp scancannon.conf scancannon.conf.bak
    
    # Remove existing adapter settings
    sed -i.tmp '/^adapter-ip/d; /^adapter-mac/d; /^router-mac/d; /^# adapter-ip/d; /^# adapter-mac/d; /^# router-mac/d' scancannon.conf
    
    # Add new settings (convert MAC addresses from colon to dash format for masscan)
    echo "" >> scancannon.conf
    echo "# Auto-detected network adapter settings" >> scancannon.conf
    echo "adapter-ip = $selected_ip" >> scancannon.conf
    echo "adapter-mac = $(echo "$selected_mac" | tr ':' '-')" >> scancannon.conf
    
    if [ -n "$selected_gateway_mac" ]; then
        echo "router-mac = $(echo "$selected_gateway_mac" | tr ':' '-')" >> scancannon.conf
    else
        echo "# router-mac = <gateway-mac-address>  # Could not auto-detect, configure manually if needed" >> scancannon.conf
    fi
    
    echo "Configuration updated successfully!"
    echo "Backup saved as scancannon.conf.bak"
    echo ""
}

# Always offer network adapter configuration
configure_adapter

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
if echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/(3[0-2]|[12]?[0-9]))?$'; then
CIDR_RANGES=("$1")
elif [ -s "$1" ]; then
# Replace readarray with a more compatible approach
CIDR_RANGES=()
while IFS= read -r line; do
    [[ -n "$line" ]] && CIDR_RANGES+=("$line")
done < "$1"
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

#Alert for existing Results files
if [ -d "./results" ]; then
echo "Results folder already exists."
echo "Choose an option:"
echo "  [D] Delete existing results and start fresh"
echo "  [M] Merge new results with existing (re-scanning previous subnets will overwrite some files)"
echo "  [C] Cancel and exit"
read -p "Enter your choice [D/M/C]: " -n 1 -r choice
echo
case "$choice" in
    [Dd] )
        echo "Deleting existing results folder..."
        rm -rf "./results"
        mkdir "results"
        ;;
    [Mm] )
        echo "Merging with existing results. Re-scanning previous subnets will overwrite some files."
        ;;
    [Cc] )
        echo "Operation cancelled."
        exit 0
        ;;
    * )
        echo "Invalid choice. Operation cancelled."
        exit 1
        ;;
esac
else
mkdir "results"
fi

#Download and prep the latest list of TLDs from IANA (only if older than 1 day)
TLD_FILE="./all_tlds.txt"
DOWNLOAD_TLD=false

if [ ! -f "$TLD_FILE" ]; then
    echo "TLD file not found. Downloading..."
    DOWNLOAD_TLD=true
else
    # Check if file is older than 1 day (86400 seconds)
    if [ "$MACOS" -eq 1 ]; then
        # macOS
        FILE_AGE=$(stat -f %m "$TLD_FILE")
        CURRENT_TIME=$(date +%s)
    else
        # Linux
        FILE_AGE=$(stat -c %Y "$TLD_FILE")
        CURRENT_TIME=$(date +%s)
    fi
    
    AGE_DIFF=$((CURRENT_TIME - FILE_AGE))
    if [ $AGE_DIFF -gt 86400 ]; then
        echo "TLD file is older than 1 day. Updating..."
        DOWNLOAD_TLD=true
    else
        echo "TLD file is recent (less than 1 day old). Using existing file."
    fi
fi

if [ "$DOWNLOAD_TLD" = true ]; then
    if ! wget https://data.iana.org/TLD/tlds-alpha-by-domain.txt -O "$TLD_FILE"; then
        echo "ERROR: Failed to download TLD list. Please check your internet connection and try again."
        if [ ! -f "$TLD_FILE" ]; then
            echo "No existing TLD file found. Cannot continue without TLD list."
            exit 1
        else
            echo "Using existing TLD file despite download failure."
        fi
    else
        # Process the downloaded file
        # Handle macOS BSD sed vs GNU sed differences
        if [ "$MACOS" -eq 1 ]; then
            sed -i '' '1d' "$TLD_FILE"
            sed -i '' 's/^/[.]/g' "$TLD_FILE"
        else
            sed -i '1d' "$TLD_FILE"
            sed -i 's/^/[.]/g' "$TLD_FILE"
        fi
        echo "TLD file updated and processed successfully."
    fi
fi

#Prep packet filter for masscan. If you are using something else, you MUST do this manually.
if [ "$MACOS" != 1 ]; then
if iptables -C INPUT -p tcp --dport 40000:41023 -j DROP 2>/dev/null; then
echo "Packet filter rule already exists. Skipping addition."
else
iptables -A INPUT -p tcp --dport 40000:41023 -j DROP
fi
else
    # Check if rule already exists before modifying pf.conf
    if ! grep -q 'block in proto tcp from any to any port 40000 >< 41024' /etc/pf.conf; then
        cp /etc/pf.conf /etc/pf.bak
        echo 'block in proto tcp from any to any port 40000 >< 41024' >>/etc/pf.conf
        pfctl -f /etc/pf.conf
    else
        echo "Packet filter rule already exists. Skipping addition."
    fi
fi

#Initialize variables for summary
TOTAL_IPS=0
RESPONSIVE_IPS=0
DISCOVERED_SERVICES=0

#Housekeeping function (defined early so it can be called by ctrl_c)
function cleanup() {
echo -e "\nPerforming cleanup. . . "
# Check if paused.conf exists before removing
if [ -f ./paused.conf ]; then
    rm ./paused.conf
fi
for DIRECTORY in ./results/*/; do
    # Create directories before moving files
    mkdir -p "${DIRECTORY}nmap_files" "${DIRECTORY}gnmap_files" "${DIRECTORY}nmap_xml_files"
    # Use quotes to handle spaces in filenames
    mv -f "${DIRECTORY}"*.nmap "${DIRECTORY}nmap_files/" 2>/dev/null
    mv -f "${DIRECTORY}"*.gnmap "${DIRECTORY}gnmap_files/" 2>/dev/null
    mv -f "${DIRECTORY}"*.xml "${DIRECTORY}nmap_xml_files/" 2>/dev/null
rm -rf "./results/all_interesting_servers/"*_files 2>/dev/null
done
chmod -R 776 "./results"
}

# Handle Ctrl+C
function ctrl_c() {
echo -e "\n\n[!] Ctrl+C detected. Cleaning up..."
cleanup
echo -e "Exiting."
exit 0
}
trap ctrl_c INT

#Process each CIDR range
for CIDR in "${CIDR_RANGES[@]}"; do
echo "Scanning $CIDR..."
#make results directories named after subnet:
# Handle special characters in directory names
DIRNAME="$(echo "$CIDR" | sed -e 's/\//_/g' -e 's/ /_/g' -e 's/[^a-zA-Z0-9_.-]/_/g')"
echo "Creating results directory for $CIDR. . ."
mkdir -p "./results/$DIRNAME"
#Start Masscan. Write to binary file so users can --readscan it to whatever they need later:
echo -e "\n*** Firing ScanCannon. Please keep arms and legs inside the chamber at all times ***"
# Quote variables to handle spaces and special characters
masscan -c scancannon.conf --open --source-port 40000 -oB "./results/${DIRNAME}/masscan_output.bin" "$CIDR"
masscan --readscan "./results/${DIRNAME}/masscan_output.bin" -oL "./results/${DIRNAME}/masscan_output.txt"

#Update total IPs scanned
# Fix IP calculation with error handling
TOTAL_IPS=$((TOTAL_IPS + $(echo "$CIDR" | awk -F/ '{
    if (NF > 1 && $2 != "") {
        print 2^(32-$2)
    } else {
        print 1  # Default to 1 if CIDR notation is missing
    }
}')))

if [ ! -s "./results/${DIRNAME}/masscan_output.txt" ]; then
    echo -e "\nNo IPs are up; skipping nmap. This was a big waste of time.\n"
    continue
fi

#Consolidate IPs and open ports for each IP:
awk '/open/ {print $4,$3,$2,$1}' "./results/${DIRNAME}/masscan_output.txt" | awk '
        /.+/{
            if (!($1 in Val)) { Key[++i] = $1; }
            Val[$1] = Val[$1] $2 ",";
            }
    END{
        for (j = 1; j <= i; j++) {
            printf("%s:%s\n%s",  Key[j], Val[Key[j]], (j == i) ? "" : "");
        }
    }' | sed 's/,$//' >>"./results/${DIRNAME}/hosts_and_ports.txt"

#Update responsive IPs count
RESPONSIVE_IPS=$((RESPONSIVE_IPS + $(awk '{print $1}' "./results/${DIRNAME}/hosts_and_ports.txt" | sort -u | wc -l)))

# Initialize progress bar
TOTAL_HOSTS=$(wc -l < "./results/${DIRNAME}/hosts_and_ports.txt")
CURRENT_HOST=0

#Run in-depth nmap enumeration against discovered hosts & ports, and output to all formats
#First we have to do a blind UDP nmap scan of common ports, as masscan does not support UDP. Note we Ping here to reduce scan time.
if [ "$UDP_SCAN" -eq 1 ]; then
    echo -e "\nStarting DNS, SNMP and VPN scan against all hosts"
    nmap -v --open -sV --version-light -sU -T3 -p 53,161,500 -oA "./results/${DIRNAME}/nmap_${DIRNAME}_udp" "$CIDR"
fi
#Then nmap TCP against masscan-discovered hosts:
while read -r TARGET; do
    IP="$(echo "$TARGET" | awk -F: '{print $1}')"
    PORT="$(echo "$TARGET" | awk -F: '{print $2}')"
    FILENAME="$(echo "$IP" | awk '{print "nmap_"$1}')"
    echo -e "\nBeginning in-depth TCP scan of $IP on port(s) $PORT:\n"
    nmap -v --open -sV --version-light -sT -O -Pn -T3 -p "$PORT" -oA "./results/${DIRNAME}/${FILENAME}_tcp" "$IP"

    # Update progress bar
    CURRENT_HOST=$((CURRENT_HOST + 1))
    PROGRESS=$((CURRENT_HOST * 100 / TOTAL_HOSTS))
    echo -ne "\rProgress: [$PROGRESS%] [$CURRENT_HOST/$TOTAL_HOSTS] hosts scanned..."
done <"./results/${DIRNAME}/hosts_and_ports.txt"
echo -ne "\rProgress: [100%] [$TOTAL_HOSTS/$TOTAL_HOSTS] hosts scanned...Done.\n"

#Generate lists of Hosts:Ports hosting Interesting Services™️ for importing into cred stuffers (or other tools)
mkdir -p "./results/${DIRNAME}/interesting_servers/"
mkdir -p "./results/all_interesting_servers/"
#(if you add to this service list, make sure you also add it to the master file generation list at the end.)
for SERVICE in domain msrpc snmp netbios-ssn microsoft-ds isakmp l2f pptp ftp sftp ssh telnet http ssl https; do
    # Improved service detection to handle multiple matches
    if grep -h -o -E "$SERVICE/.+/.+[0-9]+/open/.+/$SERVICE" "./results/${DIRNAME}"/*.gnmap > /dev/null 2>&1; then
        # Process each match individually
        grep -h -o -E "$SERVICE/.+/.+[0-9]+/open/.+/$SERVICE" "./results/${DIRNAME}"/*.gnmap | while read -r RESULT; do
            SERVIP="$(echo "$RESULT" | awk -F" " '{print $2}')"
            SERVPORT="$(echo "$RESULT" | awk -F"/" '{print $3}')"
            
            if [ -n "$SERVIP" ] && [ -n "$SERVPORT" ]; then
                echo "$SERVIP":"$SERVPORT" | tee -a "./results/${DIRNAME}/interesting_servers/${SERVICE}_servers.txt" >>"./results/all_interesting_servers/all_${SERVICE}_servers.txt"
                DISCOVERED_SERVICES=$((DISCOVERED_SERVICES + 1))
            fi
        done
    fi
done

#Generate list of discovered sub/domains for this subnet.
echo "Root Domain,IP,CIDR,AS#,IP Owner" | tee "./results/${DIRNAME}/resolved_root_domains.csv" >>"./results/all_root_domains.csv"
while read -r TLD; do
    grep -E -i "$TLD" "./results/${DIRNAME}"/*.gnmap | awk -F[\(\)] '{print $2}' | sort -u | tee "./results/${DIRNAME}/resolved_subdomains.txt" >>"./results/all_subdomains.txt"
done <"./all_tlds.txt"
while read -r DOMAIN; do
    DIG="$(dig "$DOMAIN" +short)"
    if [ -n "$DIG" ]; then
        # More robust whois parsing
        WHOIS="$(whois "$DIG" | awk -F':[ ]*' '
                /CIDR:/ { cidr = $2 };
                /Organization:/ { org = $2 };
                /OriginAS:/ { asn = $2 }
                END {
                    if (cidr != "" || asn != "" || org != "") {
                        printf "%s,%s,%s", cidr, asn, org
                    } else {
                        print "N/A,N/A,N/A"
                    }
                }')"
        echo "$DOMAIN"",""$DIG"",""$WHOIS" | tee -a "./results/${DIRNAME}/resolved_root_domains.csv" >>"./results/all_root_domains.csv"
    fi
done < <(awk -F. '{ print $(NF-1)"."$NF }' "./results/${DIRNAME}/resolved_subdomains.txt")
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
# Improved unresponsive networks detection
echo "Identifying unresponsive networks..."
find ./results -type d -name "*_*" | while read -r dir; do
    dirname=$(basename "$dir")
    if [ ! -f "$dir/hosts_and_ports.txt" ]; then
        echo "$dirname" | sed 's/_/\//g' >> "./results/dead_networks.txt"
    fi
done


#Print summary
echo -e "\nScan Summary:"
echo "Total IPs Scanned: $TOTAL_IPS"
echo "Responsive IPs: $RESPONSIVE_IPS"
echo "Discovered Services: $DISCOVERED_SERVICES"

echo -e "\n【 Powering down ScanCannon. Please check for any personal belongings before exiting the shell 】"

# Call cleanup function at the end of script
cleanup
