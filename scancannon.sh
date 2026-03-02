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

echo -e "••¤(×[¤ ScanCannon v1.5 by J0hnnyXm4s ¤]×)¤••\n"

# ===== PROGRESS TRACKING SYSTEM =====

# Progress tracking variables
PROGRESS_FILE="./scancannon_progress.tmp"
SCRIPT_START_TIME=$(date +%s)
TOTAL_PHASES=0
CURRENT_PHASE=0
SPINNER_CHARS="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_INDEX=0
declare -A PHASE_TIMES

# Calculate total phases upfront
calculate_total_phases() {
    local phases=5  # Setup, validation, TLD download, packet filter setup, cleanup
    local per_cidr=4  # masscan, nmap, analysis, domains (always)
    if [ "$UDP_SCAN" -eq 1 ]; then
        per_cidr=$((per_cidr + 1))  # UDP scan phase
    fi
    if [ "$API_SCAN" -eq 1 ]; then
        per_cidr=$((per_cidr + 1))  # API detection phase
    fi
    phases=$((phases + ${#CIDR_RANGES[@]} * per_cidr))
    TOTAL_PHASES=$phases
    echo "$phases" > "$PROGRESS_FILE"
    echo "0" >> "$PROGRESS_FILE"  # current phase
}

# Visual progress bar with spinner
show_progress_with_spinner() {
    local percent="$1"
    local message="$2"
    local bar_length=40
    local filled_length=$((percent * bar_length / 100))
    
    # Create progress bar
    local bar=""
    for ((i=0; i<filled_length; i++)); do bar+="█"; done
    for ((i=filled_length; i<bar_length; i++)); do bar+="░"; done
    
    # Get spinner character
    local spinner_char="${SPINNER_CHARS:$((SPINNER_INDEX % ${#SPINNER_CHARS})):1}"
    SPINNER_INDEX=$((SPINNER_INDEX + 1))
    
    printf "\r%s [%s] %3d%% %s" "$spinner_char" "$bar" "$percent" "$message"
}

# Enhanced progress with time estimation
track_phase_progress() {
    local phase_name="$1"
    local current_target="${2:-}"
    
    CURRENT_PHASE=$((CURRENT_PHASE + 1))
    local current_time=$(date +%s)
    local elapsed=$((current_time - SCRIPT_START_TIME))
    
    # Calculate ETA
    local eta_formatted="calculating..."
    if [ "$CURRENT_PHASE" -gt 1 ]; then
        local avg_time_per_phase=$((elapsed / CURRENT_PHASE))
        local remaining_phases=$((TOTAL_PHASES - CURRENT_PHASE))
        local eta_seconds=$((remaining_phases * avg_time_per_phase))
        local eta_time=$((current_time + eta_seconds))
        
        if [ "$MACOS" -eq 1 ]; then
            eta_formatted=$(date -r "$eta_time" '+%H:%M:%S')
        else
            eta_formatted=$(date -d "@$eta_time" '+%H:%M:%S')
        fi
    fi
    
    local percent=$((CURRENT_PHASE * 100 / TOTAL_PHASES))
    
    # Update progress file
    echo "$CURRENT_PHASE" > "${PROGRESS_FILE}.tmp" && mv "${PROGRESS_FILE}.tmp" "$PROGRESS_FILE"
    echo "$percent" >> "$PROGRESS_FILE"
    
    # Format message with target if provided
    local full_message="$phase_name"
    if [ -n "$current_target" ]; then
        full_message="$phase_name ($current_target)"
    fi
    
    # Show visual progress
    show_progress_with_spinner "$percent" "$full_message"
    
    # Also log detailed progress
    printf "\n[Phase %d/%d] %s | ETA: %s | Elapsed: %dm%ds\n" \
        "$CURRENT_PHASE" "$TOTAL_PHASES" "$full_message" "$eta_formatted" \
        "$((elapsed / 60))" "$((elapsed % 60))"
}

# Cleanup progress files
cleanup_progress() {
    rm -f "$PROGRESS_FILE" "${PROGRESS_FILE}.tmp" 2>/dev/null
}

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
echo "usage: scancannon.sh [-u] [-a] -d domain | -c CIDR  (at least one required)"
echo ""
echo "  -d domain  Resolve a domain to its owning CIDR range via whois (repeatable)"
echo "             Accepts a bare domain (example.com) or URL (https://sub.example.com/path)"
echo "             URLs are automatically stripped to domain + TLD"
echo "  -c CIDR    Specify a CIDR range directly (repeatable)"
echo "  -u         Perform UDP scan on common ports (53, 161, 500) using nmap"
echo "  -a         Perform API endpoint detection on HTTP/HTTPS services (requires curl)"
echo ""
echo "  At least one -d or -c flag is required. You may combine both."
echo "  Examples:"
echo "    scancannon.sh -d example.com"
echo "    scancannon.sh -c 203.0.113.0/24"
echo "    scancannon.sh -d https://example.com -c 10.0.0.0/24"
echo "    scancannon.sh -ua -d example.com"
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

# Function to extract base domain+TLD from a URL or hostname
# e.g. "https://sub.example.com/path?q=1" → "example.com"
# e.g. "mail.example.co.uk" → "example.co.uk"  (best-effort for 2-part TLDs)
function extract_domain() {
    local input="$1"

    # Strip protocol (http://, https://, ftp://, etc.)
    local hostname
    hostname=$(echo "$input" | sed -E 's|^[a-zA-Z]+://||')
    # Strip path, query string, port, trailing slashes
    hostname=$(echo "$hostname" | sed -E 's|[:/].*||; s|/$||')

    # Strip "www." prefix
    hostname=$(echo "$hostname" | sed -E 's|^www\.||i')

    if [ -z "$hostname" ]; then
        echo ""
        return 1
    fi

    # Extract base domain + TLD (last two dot-separated parts)
    # Handles: sub.example.com → example.com
    #          deep.sub.example.com → example.com
    #          example.com → example.com
    local parts
    parts=$(echo "$hostname" | awk -F'.' '{print NF}')
    if [ "$parts" -gt 2 ]; then
        hostname=$(echo "$hostname" | awk -F'.' '{print $(NF-1)"."$NF}')
    fi

    echo "$hostname"
}

# ===== NETWORK DISCOVERY ENGINE =====
# Shared infrastructure for both -d (domain) and -c (CIDR) inputs.
# Pipeline: IP → whois (CIDR + ASN + Org) → RADB (all ASN prefixes) → interactive selection

# Helper: convert an IP range (start - end) to CIDR notation
function inetnum_to_cidr() {
    local start_ip="$1"
    local end_ip="$2"

    local IFS='.'
    read -r a b c d <<< "$start_ip"
    local start_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))
    read -r a b c d <<< "$end_ip"
    local end_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))
    unset IFS

    local diff=$(( end_int - start_int + 1 ))
    local prefix=32
    local size=1
    while [ "$size" -lt "$diff" ] && [ "$prefix" -gt 0 ]; do
        prefix=$((prefix - 1))
        size=$((size * 2))
    done

    echo "${start_ip}/${prefix}"
}

# Helper: extract the first IP from a CIDR (network address)
function cidr_first_ip() {
    echo "$1" | cut -d'/' -f1
}

# Extract ALL CIDRs from whois output (not just the first match)
function extract_cidrs_from_whois() {
    local whois_output="$1"
    local cidrs=()

    # ARIN format: CIDR lines (may contain comma-separated ranges)
    while IFS= read -r line; do
        # Split comma-separated CIDRs on one line
        local cleaned
        cleaned=$(echo "$line" | sed 's/^CIDR:[[:space:]]*//')
        IFS=',' read -ra parts <<< "$cleaned"
        for part in "${parts[@]}"; do
            part=$(echo "$part" | tr -d '[:space:]')
            if [ -n "$part" ]; then
                cidrs+=("$part")
            fi
        done
    done < <(echo "$whois_output" | grep -i '^CIDR:')

    # RIPE/APNIC format: inetnum lines → convert to CIDR
    while IFS= read -r line; do
        local range
        range=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//')
        local range_start range_end
        range_start=$(echo "$range" | awk -F' - ' '{gsub(/[[:space:]]/, "", $1); print $1}')
        range_end=$(echo "$range" | awk -F' - ' '{gsub(/[[:space:]]/, "", $2); print $2}')
        if [ -n "$range_start" ] && [ -n "$range_end" ]; then
            local c
            c=$(inetnum_to_cidr "$range_start" "$range_end")
            if [ -n "$c" ]; then cidrs+=("$c"); fi
        fi
    done < <(echo "$whois_output" | grep -i '^inetnum:')

    # NetRange lines → convert to CIDR
    while IFS= read -r line; do
        local range
        range=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//')
        local range_start range_end
        range_start=$(echo "$range" | awk -F' - ' '{gsub(/[[:space:]]/, "", $1); print $1}')
        range_end=$(echo "$range" | awk -F' - ' '{gsub(/[[:space:]]/, "", $2); print $2}')
        if [ -n "$range_start" ] && [ -n "$range_end" ]; then
            local c
            c=$(inetnum_to_cidr "$range_start" "$range_end")
            if [ -n "$c" ]; then cidrs+=("$c"); fi
        fi
    done < <(echo "$whois_output" | grep -i '^NetRange:')

    # route: field
    while IFS= read -r line; do
        local r
        r=$(echo "$line" | awk '{print $2}')
        if [ -n "$r" ]; then cidrs+=("$r"); fi
    done < <(echo "$whois_output" | grep -iE '^route:')

    # Deduplicate and print
    printf '%s\n' "${cidrs[@]}" 2>/dev/null | sort -u -t'/' -k1,1V -k2,2n
}

# Extract ASN(s) from whois output
function extract_asn_from_whois() {
    local whois_output="$1"
    local asns=()

    # ARIN format: OriginAS
    while IFS= read -r line; do
        local asn
        asn=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//' | grep -oE 'AS[0-9]+')
        if [ -n "$asn" ]; then asns+=("$asn"); fi
    done < <(echo "$whois_output" | grep -i '^OriginAS:')

    # RIPE/APNIC format: origin
    while IFS= read -r line; do
        local asn
        asn=$(echo "$line" | sed 's/^[^:]*:[[:space:]]*//' | grep -oE 'AS[0-9]+')
        if [ -n "$asn" ]; then asns+=("$asn"); fi
    done < <(echo "$whois_output" | grep -i '^origin:')

    # Deduplicate
    printf '%s\n' "${asns[@]}" 2>/dev/null | sort -u
}

# Extract organization name from whois output
function extract_org_from_whois() {
    local whois_output="$1"
    echo "$whois_output" | grep -iE '^(OrgName|org-name|descr|netname):' | head -1 | sed 's/^[^:]*:[[:space:]]*//'
}

# Query RADB (or similar IRR) for all prefixes announced by an ASN
function discover_asn_prefixes() {
    local asn="$1"
    local prefixes=()

    echo "  Querying RADB for all prefixes announced by $asn..."

    local radb_output
    radb_output=$(whois -h whois.radb.net -- "-i origin $asn" 2>/dev/null)

    if [ -n "$radb_output" ]; then
        while IFS= read -r line; do
            local prefix
            prefix=$(echo "$line" | awk '{print $2}')
            if [ -n "$prefix" ]; then
                prefixes+=("$prefix")
            fi
        done < <(echo "$radb_output" | grep -iE '^route:')
    fi

    # Deduplicate and print
    if [ ${#prefixes[@]} -gt 0 ]; then
        printf '%s\n' "${prefixes[@]}" | sort -u -t'/' -k1,1V -k2,2n
    fi
}

# Full network discovery for a single IP address
# Returns all discovered CIDR ranges via DISCOVERED_RANGES array
function discover_networks_for_ip() {
    local ip="$1"
    local source_label="${2:-$ip}"
    DISCOVERED_RANGES=()
    DISCOVERED_ORG=""
    DISCOVERED_ASNS=()

    echo "  Looking up $ip via whois..."
    local whois_output
    whois_output=$(whois "$ip" 2>/dev/null)

    if [ -z "$whois_output" ]; then
        echo "  WARNING: whois returned no data for $ip"
        return 1
    fi

    # Extract organization
    DISCOVERED_ORG=$(extract_org_from_whois "$whois_output")

    # Extract direct CIDRs from whois
    local direct_cidrs
    direct_cidrs=$(extract_cidrs_from_whois "$whois_output")

    # Extract ASNs
    local asn_list
    asn_list=$(extract_asn_from_whois "$whois_output")

    if [ -n "$asn_list" ]; then
        while IFS= read -r asn; do
            DISCOVERED_ASNS+=("$asn")
        done <<< "$asn_list"
    fi

    # Collect all prefixes: direct whois CIDRs + ASN-announced prefixes
    local all_prefixes=()

    # Add direct CIDRs
    if [ -n "$direct_cidrs" ]; then
        while IFS= read -r cidr; do
            all_prefixes+=("$cidr")
        done <<< "$direct_cidrs"
    fi

    # Query RADB for each ASN
    for asn in "${DISCOVERED_ASNS[@]}"; do
        local asn_prefixes
        asn_prefixes=$(discover_asn_prefixes "$asn")
        if [ -n "$asn_prefixes" ]; then
            while IFS= read -r prefix; do
                all_prefixes+=("$prefix")
            done <<< "$asn_prefixes"
        fi
    done

    # Deduplicate final list
    if [ ${#all_prefixes[@]} -gt 0 ]; then
        while IFS= read -r range; do
            DISCOVERED_RANGES+=("$range")
        done < <(printf '%s\n' "${all_prefixes[@]}" | sort -u -t'/' -k1,1V -k2,2n)
    fi
}

# Interactive range selection — present discovered ranges, let user choose
# Sets SELECTED_RANGES array with the user's selections
function interactive_range_selection() {
    local source_label="$1"
    shift
    local ranges=("$@")
    SELECTED_RANGES=()

    if [ ${#ranges[@]} -eq 0 ]; then
        echo "  No CIDR ranges discovered."
        return 1
    fi

    if [ ${#ranges[@]} -eq 1 ]; then
        echo ""
        echo "  Discovered 1 CIDR range for $source_label:"
        echo "    [1] ${ranges[0]}"
        echo ""
        echo "  WARNING: Make sure you have authorization to scan this network!"
        read -r -p "  Proceed with scanning ${ranges[0]}? [y/N]: " confirm
        case "$confirm" in
            y|Y ) SELECTED_RANGES=("${ranges[0]}"); return 0 ;;
            * ) echo "  Scan cancelled."; return 1 ;;
        esac
    fi

    echo ""
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║  Network Discovery Results                                 ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    printf "  ║  Source : %-50s║\n" "${source_label:0:50}"
    if [ -n "$DISCOVERED_ORG" ]; then
        printf "  ║  Org    : %-50s║\n" "${DISCOVERED_ORG:0:50}"
    fi
    if [ ${#DISCOVERED_ASNS[@]} -gt 0 ]; then
        local asn_str
        asn_str=$(printf '%s ' "${DISCOVERED_ASNS[@]}")
        printf "  ║  ASN(s) : %-50s║\n" "${asn_str:0:50}"
    fi
    printf "  ║  Ranges : %-50s║\n" "${#ranges[@]} CIDR block(s) discovered"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Discovered CIDR ranges:"
    for i in "${!ranges[@]}"; do
        printf "    [%2d] %s\n" "$((i + 1))" "${ranges[$i]}"
    done
    echo ""
    echo "  WARNING: Make sure you have authorization to scan these networks!"
    echo ""
    echo "  Enter your selection:"
    echo "    • 'all'                — scan all discovered ranges"
    echo "    • comma-separated nums — e.g. '1,3,5' to select specific ranges"
    echo "    • 'none' or empty      — cancel"
    echo ""
    read -r -p "  Selection: " selection

    # Parse selection
    if [ -z "$selection" ] || [ "$selection" = "none" ]; then
        echo "  Scan cancelled."
        return 1
    fi

    if [ "$selection" = "all" ]; then
        SELECTED_RANGES=("${ranges[@]}")
        echo "  Selected all ${#ranges[@]} range(s)."
        return 0
    fi

    # Parse comma-separated numbers
    IFS=',' read -ra nums <<< "$selection"
    for num in "${nums[@]}"; do
        num=$(echo "$num" | tr -d '[:space:]')
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le ${#ranges[@]} ]; then
            SELECTED_RANGES+=("${ranges[$((num - 1))]}")
        else
            echo "  WARNING: Ignoring invalid selection '$num'"
        fi
    done

    if [ ${#SELECTED_RANGES[@]} -eq 0 ]; then
        echo "  No valid ranges selected. Scan cancelled."
        return 1
    fi

    echo "  Selected ${#SELECTED_RANGES[@]} range(s)."
    return 0
}

# ===== HIGH-LEVEL DISCOVERY FUNCTIONS =====

# Resolve a domain (-d flag) to CIDR ranges via full ASN discovery pipeline
function resolve_domain_to_cidr() {
    local input="$1"

    # Extract clean domain+TLD (strips URLs, subdomains, paths)
    local hostname
    hostname=$(extract_domain "$input")

    if [ -z "$hostname" ]; then
        echo "ERROR: Could not extract domain from '$input'"
        return 1
    fi

    echo "  Input:  $input"
    echo "  Domain: $hostname"
    echo ""

    # Resolve ALL A records for the domain
    echo "  Resolving all A records for $hostname..."
    local all_ips=()
    while IFS= read -r ip; do
        if [ -n "$ip" ]; then
            all_ips+=("$ip")
        fi
    done < <(dig +short "$hostname" A 2>/dev/null | grep -E '^[0-9]+\.')

    if [ ${#all_ips[@]} -eq 0 ]; then
        echo "ERROR: Could not resolve '$hostname' to any IP address."
        echo "Make sure the hostname is correct and DNS is reachable."
        return 1
    fi

    echo "  Found ${#all_ips[@]} IP(s): ${all_ips[*]}"
    echo ""

    # Run full discovery for each unique IP, collect all ranges
    local all_ranges=()
    local all_asns=()
    local org_name=""

    for ip in "${all_ips[@]}"; do
        echo "  ── Discovering networks for IP: $ip ──"
        discover_networks_for_ip "$ip" "$hostname"

        if [ -n "$DISCOVERED_ORG" ] && [ -z "$org_name" ]; then
            org_name="$DISCOVERED_ORG"
        fi

        for asn in "${DISCOVERED_ASNS[@]}"; do
            all_asns+=("$asn")
        done

        for range in "${DISCOVERED_RANGES[@]}"; do
            all_ranges+=("$range")
        done
    done

    # Deduplicate
    local unique_ranges=()
    while IFS= read -r range; do
        unique_ranges+=("$range")
    done < <(printf '%s\n' "${all_ranges[@]}" | sort -u -t'/' -k1,1V -k2,2n)

    local unique_asns=()
    while IFS= read -r asn; do
        unique_asns+=("$asn")
    done < <(printf '%s\n' "${all_asns[@]}" 2>/dev/null | sort -u)

    # Store for display in interactive_range_selection
    DISCOVERED_ORG="$org_name"
    DISCOVERED_ASNS=("${unique_asns[@]}")

    # Interactive selection
    if interactive_range_selection "$hostname" "${unique_ranges[@]}"; then
        RESOLVED_CIDRS=("${SELECTED_RANGES[@]}")
        return 0
    else
        return 1
    fi
}

# Discover related networks for a -c CIDR range via ASN discovery pipeline
function discover_networks_for_cidr() {
    local cidr_input="$1"

    # Get a representative IP from the CIDR (the network address)
    local rep_ip
    rep_ip=$(cidr_first_ip "$cidr_input")

    echo "  ── Discovering networks for CIDR: $cidr_input (via $rep_ip) ──"
    discover_networks_for_ip "$rep_ip" "$cidr_input"

    # Always include the original CIDR in the discovery results
    local all_ranges=("$cidr_input")
    for range in "${DISCOVERED_RANGES[@]}"; do
        all_ranges+=("$range")
    done

    # Deduplicate
    local unique_ranges=()
    while IFS= read -r range; do
        unique_ranges+=("$range")
    done < <(printf '%s\n' "${all_ranges[@]}" | sort -u -t'/' -k1,1V -k2,2n)

    # Interactive selection
    if interactive_range_selection "$cidr_input" "${unique_ranges[@]}"; then
        RESOLVED_CIDRS=("${SELECTED_RANGES[@]}")
        return 0
    else
        return 1
    fi
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
API_SCAN=0
DOMAIN_ARGS=()
CIDR_FLAG_ARGS=()

while getopts ":uad:c:" opt; do
case ${opt} in
u )
UDP_SCAN=1
;;
a )
API_SCAN=1
;;
d )
DOMAIN_ARGS+=("$OPTARG")
;;
c )
CIDR_FLAG_ARGS+=("$OPTARG")
;;
: )
echo "ERROR: Option -$OPTARG requires an argument." 1>&2
helptext
exit 1
;;
? )
echo "Invalid option: $OPTARG" 1>&2
helptext
exit 1
;;
esac
done
shift $((OPTIND -1))

# Check API scan dependencies
if [ "$API_SCAN" -eq 1 ]; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "ERROR: curl is required for API scanning (-a). Please install it."
        exit 1
    fi
fi

# Validate exclude file first
if ! validate_exclude_file; then
    exit 1
fi

# ---- Build CIDR_RANGES from all input sources ----
CIDR_RANGES=()

# Reject unexpected positional arguments
if [ "$#" -gt 0 ]; then
    echo "ERROR: Unexpected argument '$1'. Use -d for domains or -c for CIDR ranges."
    helptext >&2
    exit 1
fi

# Require at least one -d or -c flag
if [ ${#DOMAIN_ARGS[@]} -eq 0 ] && [ ${#CIDR_FLAG_ARGS[@]} -eq 0 ]; then
    echo "ERROR: At least one -d (domain) or -c (CIDR) flag is required."
    helptext >&2
    exit 1
fi

# 1) Process -d (domain) flags — full ASN discovery pipeline
if [ ${#DOMAIN_ARGS[@]} -gt 0 ]; then
    echo ""
    echo "=== Domain Mode: Full Network Discovery ==="
    for domain_input in "${DOMAIN_ARGS[@]}"; do
        RESOLVED_CIDRS=()
        if resolve_domain_to_cidr "$domain_input"; then
            for selected in "${RESOLVED_CIDRS[@]}"; do
                CIDR_RANGES+=("$selected")
            done
        else
            exit 1
        fi
    done
fi

# 2) Process -c (CIDR) flags — validate, then run ASN discovery
if [ ${#CIDR_FLAG_ARGS[@]} -gt 0 ]; then
    echo ""
    echo "=== CIDR Mode: Full Network Discovery ==="
    for cidr_input in "${CIDR_FLAG_ARGS[@]}"; do
        # Validate the input CIDR first
        if ! validate_cidr "$cidr_input" "1" "-c flag"; then
            exit 1
        fi
        # Add /32 if no CIDR notation present
        if echo "$cidr_input" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
            cidr_input="$cidr_input/32"
        fi
        # Run ASN discovery for this CIDR
        RESOLVED_CIDRS=()
        if discover_networks_for_cidr "$cidr_input"; then
            for selected in "${RESOLVED_CIDRS[@]}"; do
                CIDR_RANGES+=("$selected")
            done
        else
            exit 1
        fi
    done
fi

# Final deduplication of all collected CIDR ranges
if [ ${#CIDR_RANGES[@]} -gt 0 ]; then
    local_unique=()
    while IFS= read -r range; do
        local_unique+=("$range")
    done < <(printf '%s\n' "${CIDR_RANGES[@]}" | sort -u -t'/' -k1,1V -k2,2n)
    CIDR_RANGES=("${local_unique[@]}")
fi

if [ ${#CIDR_RANGES[@]} -eq 0 ]; then
    echo "ERROR: No CIDR ranges selected. Cannot proceed."
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Final scan targets: ${#CIDR_RANGES[@]} CIDR range(s)"
echo "═══════════════════════════════════════════════════"
for r in "${CIDR_RANGES[@]}"; do
    echo "  • $r"
done
echo "═══════════════════════════════════════════════════"
echo ""

# Initialize progress tracking now that we know the CIDR ranges
echo "Initializing progress tracking..."
calculate_total_phases
track_phase_progress "Initializing ScanCannon"

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

track_phase_progress "Downloading TLD list"

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

track_phase_progress "Configuring packet filters"

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
DISCOVERED_API_ENDPOINTS=0

#Housekeeping function (defined early so it can be called by ctrl_c)
function cleanup() {
echo -e "\nPerforming cleanup. . . "
cleanup_progress
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

# ===== API ENDPOINT DETECTION FUNCTION =====
function detect_api_endpoints() {
    local dirname="$1"
    local api_output_dir="./results/${dirname}/interesting_servers"
    local api_details_file="${api_output_dir}/api_details.txt"
    local api_servers_file="${api_output_dir}/api_servers.txt"
    local global_api_file="./results/all_interesting_servers/all_api_servers.txt"

    mkdir -p "$api_output_dir"
    echo "=== API Endpoint Detection ===" > "$api_details_file"
    : > "$api_servers_file"

    echo -e "\n--- API Endpoint Detection ---"

    # --- TIER 1: Parse nmap XML for API indicators (single pass, POSIX awk) ---
    echo "[Tier 1] Analyzing nmap output for API indicators..."

    if ls "./results/${dirname}"/*.xml >/dev/null 2>&1; then
        awk '
            /<address / && /addrtype="ipv4"/ {
                s = $0
                idx = index(s, "addr=\"")
                if (idx > 0) {
                    s = substr(s, idx + 6)
                    end = index(s, "\"")
                    if (end > 0) ip = substr(s, 1, end - 1)
                }
            }

            # Track current port — extract from portid="..."
            /<port protocol="tcp" portid=/ {
                s = $0
                idx = index(s, "portid=\"")
                if (idx > 0) {
                    s = substr(s, idx + 8)
                    end = index(s, "\"")
                    if (end > 0) port = substr(s, 1, end - 1)
                }
            }

            # Framework fingerprints in service/version output
            tolower($0) ~ /express|django|flask|fastapi|uvicorn|gunicorn|spring|laravel|rails|graphql|swagger|openapi|asp\.net|kestrel|node\.js|restify|hapi|koa|next\.js|nuxt|tomcat|jetty|werkzeug|tornado|aiohttp|actix|gin-gonic|fiber|echo|chi|gorilla/ {
                if (/product=/ || /extrainfo=/ || /version=/) {
                    info = $0
                    gsub(/.*product="/, "", info)
                    gsub(/".*/, "", info)
                    if (ip != "" && port != "") {
                        print "[Tier 1] Framework: " ip ":" port " " info
                    }
                }
            }

            # NSE http-headers: detect API-related headers
            /id="http-headers"/ || /http-headers/ { in_headers = 1 }
            in_headers && /(Access-Control-Allow-Origin|X-Powered-By|X-API-Version|X-RateLimit|X-Request-Id|Content-Type.*application\/json)/ {
                line = $0
                gsub(/^[[:space:]]+/, "", line)
                if (ip != "" && port != "") {
                    print "[Tier 1] Header: " ip ":" port " " line
                }
            }

            # NSE http-title: detect API documentation pages
            /id="http-title"/ || /http-title/ {
                if (/output=/) {
                    s = $0
                    idx = index(s, "output=\"")
                    if (idx > 0) {
                        s = substr(s, idx + 8)
                        end = index(s, "\"")
                        if (end > 0) {
                            title = substr(s, 1, end - 1)
                            ltitle = tolower(title)
                            if (ltitle ~ /swagger|api.doc|graphql.playground|redoc|rapidoc|graphiql|api.explorer|openapi/) {
                                if (ip != "" && port != "") {
                                    print "[Tier 1] Title: " ip ":" port " " title
                                }
                            }
                        }
                    }
                }
            }

            # NSE http-robots.txt: detect API paths in disallow rules
            /id="http-robots"/ || /http-robots/ { in_robots = 1 }
            in_robots && /\/api/ {
                line = $0
                gsub(/^[[:space:]]+/, "", line)
                if (ip != "" && port != "") {
                    print "[Tier 1] Robots: " ip ":" port " " line
                }
            }

            /<\/script>/ { in_headers = 0; in_robots = 0 }
        ' "./results/${dirname}"/*.xml >> "$api_details_file" 2>/dev/null

        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' "$api_details_file" 2>/dev/null | \
            sort -u >> "$api_servers_file"
    fi

    local tier1_count=0
    if [ -s "$api_servers_file" ]; then
        tier1_count=$(wc -l < "$api_servers_file")
    fi
    echo "[Tier 1] Found $tier1_count host(s) with API indicators in nmap output"

    # --- TIER 2: Targeted curl probing of known API paths ---
    echo "[Tier 2] Probing HTTP/HTTPS hosts for API endpoints..."

    local probe_targets_file
    probe_targets_file=$(mktemp)
    for svc_file in http_servers.txt https_servers.txt ssl_servers.txt; do
        if [ -s "${api_output_dir}/${svc_file}" ]; then
            cat "${api_output_dir}/${svc_file}" >> "$probe_targets_file"
        fi
    done
    sort -u -o "$probe_targets_file" "$probe_targets_file"

    local target_count=0
    if [ -s "$probe_targets_file" ]; then
        target_count=$(wc -l < "$probe_targets_file")
    fi

    if [ "$target_count" -eq 0 ]; then
        echo "[Tier 2] No HTTP/HTTPS hosts found to probe"
        rm -f "$probe_targets_file"
    else
        echo "[Tier 2] Probing ${target_count} HTTP/HTTPS host(s)..."

        local api_paths=(
            "/api"
            "/api/v1"
            "/api/v2"
            "/swagger.json"
            "/swagger-ui.html"
            "/openapi.json"
            "/v3/api-docs"
            "/graphql"
            "/.well-known/openid-configuration"
            "/health"
            "/healthz"
            "/status"
            "/robots.txt"
        )

        local probe_count=0
        local total_probes=$(( target_count * (${#api_paths[@]} + 1) ))  # +1 for root header check
        local max_parallel=10
        local active_jobs=0

        _probe_target() {
            local target="$1"
            local details_file="$2"
            local servers_file="$3"
            local ip port proto
            ip="${target%%:*}"
            port="${target##*:}"

            # Determine protocol based on port
            proto="http"
            if [ "$port" = "443" ] || [ "$port" = "8443" ] || [ "$port" = "990" ]; then
                proto="https"
            fi

            local consecutive_failures=0

            local root_response
            root_response=$(curl -sk --max-time 5 -D - -o /dev/null \
                -w "\n__STATUS__%{http_code}|%{content_type}" \
                "${proto}://${ip}:${port}/" 2>/dev/null || echo "__STATUS__000|")

            local root_status
            root_status=$(echo "$root_response" | grep '__STATUS__' | sed 's/__STATUS__//' | cut -d'|' -f1)
            local root_ctype
            root_ctype=$(echo "$root_response" | grep '__STATUS__' | sed 's/__STATUS__//' | cut -d'|' -f2)

            if [ "$root_status" = "000" ]; then
                consecutive_failures=$((consecutive_failures + 1))
            else
                consecutive_failures=0
                # Check for API headers in root response
                if echo "$root_response" | grep -qiE '(Access-Control-Allow-Origin|X-API-Version|X-RateLimit|X-Request-Id)'; then
                    echo "[Tier 2] API headers on root: ${ip}:${port}" >> "$details_file"
                    echo "${ip}:${port}" >> "$servers_file"
                fi
                # Check if root returns JSON
                if echo "$root_ctype" | grep -qiE 'json'; then
                    echo "[Tier 2] ${ip}:${port}/ [${root_status}] ${root_ctype}" >> "$details_file"
                    echo "${ip}:${port}/" >> "$servers_file"
                fi
            fi

            # Probe each API path
            local path
            for path in "${api_paths[@]}"; do
                if [ "$consecutive_failures" -ge 2 ]; then
                    echo "[Tier 2] ${ip}:${port} circuit breaker tripped (${consecutive_failures} failures), skipping remaining paths" >> "$details_file"
                    break
                fi

                local url="${proto}://${ip}:${port}${path}"
                local response
                response=$(curl -sk --max-time 5 -o /dev/null \
                    -w "%{http_code}|%{content_type}" \
                    "${url}" 2>/dev/null || echo "000|")

                local status_code content_type
                status_code="${response%%|*}"
                content_type="${response#*|}"

                if [ "$status_code" = "000" ]; then
                    consecutive_failures=$((consecutive_failures + 1))
                    continue
                else
                    consecutive_failures=0
                fi

                if [ "$status_code" = "404" ] || [ "$status_code" = "503" ]; then
                    continue
                fi

                echo "[Tier 2] ${ip}:${port}${path} [${status_code}] ${content_type}" >> "$details_file"

                if echo "$content_type" | grep -qiE 'json|xml'; then
                    echo "${ip}:${port}${path}" >> "$servers_file"
                elif [[ "$path" != "/robots.txt" && "$path" != "/status" && "$path" != "/health" && "$path" != "/healthz" ]]; then
                    # Known API paths returning 2xx or auth-required response
                    if [[ "$status_code" =~ ^2[0-9][0-9]$ || "$status_code" == "401" || "$status_code" == "403" ]]; then
                        echo "${ip}:${port}${path}" >> "$servers_file"
                    fi
                fi
            done
        }

        while IFS= read -r target; do
            _probe_target "$target" "$api_details_file" "$api_servers_file" &
            active_jobs=$((active_jobs + 1))

            if [ "$active_jobs" -ge "$max_parallel" ]; then
                wait -n 2>/dev/null || wait
                active_jobs=$((active_jobs - 1))
            fi
        done < "$probe_targets_file"

        wait

        echo "  [Tier 2] Probed ${target_count} host(s) with ${#api_paths[@]} paths each (parallel, max ${max_parallel})...Done."
        rm -f "$probe_targets_file"
    fi

    if [ -s "$api_servers_file" ]; then
        sort -u -o "$api_servers_file" "$api_servers_file"
        cat "$api_servers_file" >> "$global_api_file"
        local total_endpoints
        total_endpoints=$(wc -l < "$api_servers_file")
        DISCOVERED_API_ENDPOINTS=$((DISCOVERED_API_ENDPOINTS + total_endpoints))
        echo "API Detection Complete: $total_endpoints endpoint(s) discovered"
    else
        echo "API Detection Complete: No API endpoints detected"
    fi

    echo "  Details: $api_details_file"
    echo "  Endpoints: $api_servers_file"
    echo "--- End API Detection ---"
}

for CIDR in "${CIDR_RANGES[@]}"; do
track_phase_progress "Masscan scanning" "$CIDR"
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
    track_phase_progress "UDP scanning" "$CIDR"
    echo -e "\nStarting DNS, SNMP and VPN scan against all hosts"
    nmap -v --open -sV --version-light -sU -T3 -p 53,161,500 -oA "./results/${DIRNAME}/nmap_${DIRNAME}_udp" "$CIDR"
fi

track_phase_progress "TCP enumeration" "$CIDR"
NSE_SCRIPT_ARGS=""
if [ "$API_SCAN" -eq 1 ]; then
    NSE_SCRIPT_ARGS="--script=http-headers,http-title,http-robots.txt,http-server-header"
fi

while read -r TARGET; do
    IP="$(echo "$TARGET" | awk -F: '{print $1}')"
    PORT="$(echo "$TARGET" | awk -F: '{print $2}')"
    FILENAME="$(echo "$IP" | awk '{print "nmap_"$1}')"
    echo -e "\nBeginning in-depth TCP scan of $IP on port(s) $PORT:\n"

    if [ -n "$NSE_SCRIPT_ARGS" ] && echo "$PORT" | grep -qE '(^|,)(80|443|8080|8443|8000|8888|3000|5000|9090)(,|$)'; then
        nmap -v --open -sV --version-light -sT -O -Pn -T3 "$NSE_SCRIPT_ARGS" -p "$PORT" -oA "./results/${DIRNAME}/${FILENAME}_tcp" "$IP"
    else
        nmap -v --open -sV --version-light -sT -O -Pn -T3 -p "$PORT" -oA "./results/${DIRNAME}/${FILENAME}_tcp" "$IP"
    fi

    # Update progress bar
    CURRENT_HOST=$((CURRENT_HOST + 1))
    PROGRESS=$((CURRENT_HOST * 100 / TOTAL_HOSTS))
    echo -ne "\rProgress: [$PROGRESS%] [$CURRENT_HOST/$TOTAL_HOSTS] hosts scanned..."
done <"./results/${DIRNAME}/hosts_and_ports.txt"
echo -ne "\rProgress: [100%] [$TOTAL_HOSTS/$TOTAL_HOSTS] hosts scanned...Done.\n"

track_phase_progress "Service analysis" "$CIDR"
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

# ===== API ENDPOINT DETECTION =====
if [ "$API_SCAN" -eq 1 ]; then
    track_phase_progress "API endpoint detection" "$CIDR"
    detect_api_endpoints "$DIRNAME"
fi

track_phase_progress "Domain resolution" "$CIDR"
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

track_phase_progress "Finalizing results"

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

# Final progress update
printf "\r%s [%s] %3d%% %s\n" "✓" "████████████████████████████████████████" "100" "Scan completed successfully!"

#Print summary
echo -e "\nScan Summary:"
echo "Total IPs Scanned: $TOTAL_IPS"
echo "Responsive IPs: $RESPONSIVE_IPS"
echo "Discovered Services: $DISCOVERED_SERVICES"
if [ "$API_SCAN" -eq 1 ]; then
    echo "API Endpoints Discovered: $DISCOVERED_API_ENDPOINTS"
fi
echo ""
echo "Features used:"
echo "  UDP Scanning: $([ "$UDP_SCAN" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
echo "  API Detection: $([ "$API_SCAN" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"

echo -e "\n【 Powering down ScanCannon. Please check for any personal belongings before exiting the shell 】"

# Call cleanup function at the end of script
cleanup
