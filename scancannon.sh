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

echo -e "••¤(×[¤ ScanCannon v1.3 by J0hnnyXm4s ¤]×)¤••\n"

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

if [[ "$REMOTE_TIMESTAMP" -gt "$LOCAL_TIMESTAMP" ]]; then
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

# Function to validate CIDR notation
function validate_cidr() {
    local cidr="$1"
    local line_num="$2"
    local file_name="$3"
    
    # Skip empty lines and comments
    if [[ -z "$cidr" || "$cidr" =~ ^[[:space:]]*# ]]; then
        return 0
    fi
    
    # Single awk call for comprehensive validation
    echo "$cidr" | awk -v line_num="$line_num" -v file_name="$file_name" '
    {
        # Remove leading/trailing whitespace
        gsub(/^[[:space:]]+|[[:space:]]+$/, "")
        
        # Split IP and CIDR parts
        if (match($0, /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]+)?$/)) {
            split($0, parts, "/")
            ip = parts[1]
            cidr = parts[2]
            
            # Validate IP octets
            split(ip, octets, ".")
            if (length(octets) != 4) {
                print "ERROR: Invalid IP address format '\''" $0 "'\'' in " file_name " at line " line_num
                exit 1
            }
            
            for (i in octets) {
                if (octets[i] < 0 || octets[i] > 255 || octets[i] !~ /^[0-9]+$/) {
                    print "ERROR: Invalid IP octet '\''" octets[i] "'\'' in '\''" $0 "'\'' in " file_name " at line " line_num
                    exit 1
                }
            }
            
            # Validate CIDR if present
            if (cidr != "" && (cidr < 0 || cidr > 32)) {
                print "ERROR: Invalid CIDR notation '\''/" cidr "'\'' in '\''" $0 "'\'' in " file_name " at line " line_num
                exit 1
            }
            
            exit 0
        } else {
            print "ERROR: Invalid CIDR format '\''" $0 "'\'' in " file_name " at line " line_num
            print "Expected format: x.x.x.x or x.x.x.x/y (where x is 0-255 and y is 0-32)"
            exit 1
        }
    }'
}

# Function to validate exclude file
function validate_exclude_file() {
    local exclude_file="exclude.txt"
    
    if [ ! -f "$exclude_file" ]; then
        echo "WARNING: Exclude file '$exclude_file' not found. Continuing without exclusions."
        return 0
    fi
    
    echo "Validating exclude file: $exclude_file"
    local line_num=0
    local errors=0
    
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        if ! validate_cidr "$line" "$line_num" "$exclude_file"; then
            errors=$((errors + 1))
        fi
    done < "$exclude_file"
    
    if [ $errors -gt 0 ]; then
        echo "ERROR: Found $errors validation error(s) in $exclude_file"
        echo "Please fix the errors and try again."
        return 1
    fi
    
    echo "Exclude file validation passed."
    return 0
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
        # macOS interface detection - optimized single awk call
        ifconfig | awk -F: '/^[a-z]/ && !/lo0/ && /^(en|eth|wlan)/ {print $1}'
    else
        # Linux interface detection - optimized single awk call
        ip link show | awk -F: '/^[0-9]+:/ && !/lo:/ {gsub(/ /, "", $2); if ($2 ~ /^(eth|ens|enp|wlan|wlp)/) print $2}'
    fi
}

# Function to get interface details
function get_interface_details() {
    local interface="$1"
    if [ "$MACOS" -eq 1 ]; then
        # macOS - single ifconfig call with awk processing
        ifconfig "$interface" | awk '
            /inet / && !/127.0.0.1/ && !ip {ip = $2}
            /ether/ && !mac {mac = $2}
            END {print ip "|" mac}
        '
    else
        # Linux - optimized with single command and awk processing
        {
            ip addr show "$interface" | awk '/inet / && !/127.0.0.1/ {gsub(/\/.*/, "", $2); print $2; exit}'
            ip link show "$interface" | awk '/link\/ether/ {print $2; exit}'
        } | paste -sd'|'
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

# Validate exclude file first
if ! validate_exclude_file; then
    exit 1
fi

#Check if the argument is a valid CIDR range or a file
if echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/(3[0-2]|[12]?[0-9]))?$'; then
    # Validate single CIDR range
    if validate_cidr "$1" "1" "command line argument"; then
        # Add /32 if no CIDR notation is present
        if echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
            CIDR_RANGES=("$1/32")
        else
            CIDR_RANGES=("$1")
        fi
    else
        exit 1
    fi
elif [ -s "$1" ]; then
    echo "Validating CIDR ranges in file: $1"
    # Validate file contents first
    line_num=0
    errors=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        if ! validate_cidr "$line" "$line_num" "$1"; then
            errors=$((errors + 1))
        fi
    done < "$1"
    
    if [ $errors -gt 0 ]; then
        echo "ERROR: Found $errors validation error(s) in $1"
        echo "Please fix the errors and try again."
        exit 1
    fi
    
    echo "Input file validation passed."
    
    # Process validated file
    CIDR_RANGES=()
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            # Clean up whitespace
            line=$(echo "$line" | tr -d '[:space:]')
            # Add /32 if no CIDR notation is present for each line
            if echo "$line" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
                CIDR_RANGES+=("$line/32")
            else
                CIDR_RANGES+=("$line")
            fi
        fi
    done < "$1"
    
    if [ ${#CIDR_RANGES[@]} -eq 0 ]; then
        echo "ERROR: No valid CIDR ranges found in $1"
        exit 1
    fi
    
    echo "Loaded ${#CIDR_RANGES[@]} valid CIDR range(s) from $1"
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
    # Use quotes to handle spaces in filenames and check file existence
    if ls "${DIRECTORY}"*.nmap >/dev/null 2>&1; then
        mv -f "${DIRECTORY}"*.nmap "${DIRECTORY}nmap_files/" 2>/dev/null
    fi
    if ls "${DIRECTORY}"*.gnmap >/dev/null 2>&1; then
        mv -f "${DIRECTORY}"*.gnmap "${DIRECTORY}gnmap_files/" 2>/dev/null
    fi
    if ls "${DIRECTORY}"*.xml >/dev/null 2>&1; then
        mv -f "${DIRECTORY}"*.xml "${DIRECTORY}nmap_xml_files/" 2>/dev/null
    fi
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
# Check if gnmap files exist before processing all services
if ls "./results/${DIRNAME}"/*.gnmap >/dev/null 2>&1; then
    # Process all services in a single pass through gnmap files for efficiency
    for SERVICE in domain msrpc snmp netbios-ssn microsoft-ds isakmp l2f pptp ftp sftp ssh telnet http ssl https; do
        # Optimized service detection with single awk call
        awk -v service="$SERVICE" '
            /open/ && $0 ~ service {
                ip = $2
                # Extract port from the ports section
                for (i = 3; i <= NF; i++) {
                    if ($i ~ "[0-9]+/open/[^/]*/[^/]*" service) {
                        split($i, port_parts, "/")
                        if (port_parts[1] && ip) {
                            print ip ":" port_parts[1]
                        }
                    }
                }
            }
        ' "./results/${DIRNAME}"/*.gnmap > "./results/${DIRNAME}/interesting_servers/${SERVICE}_servers.txt"
        
        # Only append to global file if local file has content
        if [ -s "./results/${DIRNAME}/interesting_servers/${SERVICE}_servers.txt" ]; then
            cat "./results/${DIRNAME}/interesting_servers/${SERVICE}_servers.txt" >> "./results/all_interesting_servers/all_${SERVICE}_servers.txt"
            DISCOVERED_SERVICES=$((DISCOVERED_SERVICES + $(wc -l < "./results/${DIRNAME}/interesting_servers/${SERVICE}_servers.txt")))
        fi
    done
fi

#Generate list of discovered sub/domains for this subnet.
echo "Root Domain,IP,CIDR,AS#,IP Owner" > "./results/${DIRNAME}/resolved_root_domains.csv"
echo "Root Domain,IP,CIDR,AS#,IP Owner" >> "./results/all_root_domains.csv"

# Check if TLD file exists and has content, and if gnmap files exist
if [ -s "./all_tlds.txt" ] && ls "./results/${DIRNAME}"/*.gnmap >/dev/null 2>&1; then
    # Optimized domain extraction with single awk pass
    awk -F'[()]' '
        BEGIN {
            # Read TLD patterns
            while ((getline tld < "./all_tlds.txt") > 0) {
                if (tld !~ /^#/ && tld != "") {
                    tlds[tolower(tld)] = 1
                }
            }
            close("./all_tlds.txt")
        }
        {
            if ($2) {
                domain = tolower($2)
                for (tld in tlds) {
                    if (domain ~ tld) {
                        domains[domain] = 1
                        break
                    }
                }
            }
        }
        END {
            for (domain in domains) {
                print domain
            }
        }
    ' "./results/${DIRNAME}"/*.gnmap | sort -u > "./results/${DIRNAME}/resolved_subdomains.txt"
    
    # Append to global file
    cat "./results/${DIRNAME}/resolved_subdomains.txt" >> "./results/all_subdomains.txt"
else
    # Create empty files if TLD processing can't be done
    touch "./results/${DIRNAME}/resolved_subdomains.txt"
fi
# Only process domains if subdomain file exists and has content
if [ -s "./results/${DIRNAME}/resolved_subdomains.txt" ]; then
    # Create temporary file for batch processing
    temp_domains=$(mktemp)
    
    # Extract root domains and process in batch
    awk -F. '{ print $(NF-1)"."$NF }' "./results/${DIRNAME}/resolved_subdomains.txt" | sort -u | while read -r DOMAIN; do
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
            echo "$DOMAIN,$DIG,$WHOIS" >> "$temp_domains"
        fi
    done
    
    # Append batch results to both files
    if [ -s "$temp_domains" ]; then
        cat "$temp_domains" >> "./results/${DIRNAME}/resolved_root_domains.csv"
        cat "$temp_domains" >> "./results/all_root_domains.csv"
    fi
    
    rm -f "$temp_domains"
fi
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
find ./results -maxdepth 1 -type d -name "*_*" | while read -r dir; do
    dirname=$(basename "$dir")
    # Skip special directories like interesting_servers, all_interesting_servers, etc.
    if [[ "$dirname" == *"interesting"* ]] || [[ "$dirname" == "all_"* ]]; then
        continue
    fi
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
