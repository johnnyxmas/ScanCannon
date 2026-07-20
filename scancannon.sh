#!/bin/bash
set -euo pipefail

# This script is safe to `source`: the top level only defines functions and
# globals. The imperative flow lives in main(), invoked at the very bottom and
# only when the file is executed directly (see the BASH_SOURCE guard there).
# The test suite relies on this to load the real functions without running a scan.

#Logging
LOG_FILE="scancannon.log"

# ===== PROJECT / OUTPUT LAYOUT =====
# Scans are grouped into projects so results from different engagements stay
# separate. A project lives under ./projects/<slug>/ with its own results/ and
# history/ (scan snapshots for diffing). RESULTS_DIR defaults to ./results —
# used by the test suite and as a fallback — and the project menu repoints it
# under the selected project.
PROJECTS_ROOT="./projects"
PROJECT_SLUG=""
PROJECT_DIR=""
RESULTS_DIR="./results"

# Public Suffix List (downloaded on demand for -d runs) for accurate
# registrable-domain extraction; falls back to a built-in table when absent.
PSL_FILE="./public_suffix_list.dat"

# Scan-diff state (populated by _sc_compute_changes, rendered by generate_report).
DELTA_ADDED=0
DELTA_REMOVED=0
DELTA_BASELINE=""

_sc_start() {
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "███████╗ ██████╗ █████╗ ███╗   ██╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗ ██████╗ ███╗   ██╗";
echo "██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔═══██╗████╗  ██║";
echo "███████╗██║     ███████║██╔██╗ ██║██║     ███████║██╔██╗ ██║██╔██╗ ██║██║   ██║██╔██╗ ██║";
echo "╚════██║██║     ██╔══██║██║╚██╗██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██║   ██║██║╚██╗██║";
echo "███████║╚██████╗██║  ██║██║ ╚████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║╚██████╔╝██║ ╚████║";
echo "╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝";

echo -e "••¤(×[¤ ScanCannon v1.9 by J0hnnyXm4s ¤]×)¤••\n"
}

# ===== PROGRESS TRACKING SYSTEM =====

# Progress tracking variables
PROGRESS_FILE="./scancannon_progress.tmp"
SCRIPT_START_TIME=$(date +%s)
TOTAL_PHASES=0
CURRENT_PHASE=0
SPINNER_CHARS="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_INDEX=0

# Calculate total phases upfront. Each CIDR is now a single orchestrated phase
# (the heavy per-CIDR work happens inside scan_cidr), plus a fixed set of
# setup/finalize phases: init, TLD download, packet filters, finalizing,
# aggregating, generating report — 6 in total, padded to 8 for headroom.
calculate_total_phases() {
    local phases=$(( 8 + ${#CIDR_RANGES[@]} ))
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
    local current_time
    current_time=$(date +%s)
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
    [ "$percent" -gt 100 ] && percent=100

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

# Detect OS early — needed by many helpers, and harmless when sourced.
if [ "$(uname)" = "Darwin" ]; then MACOS=1; else MACOS=0; fi

# Check for updates (only when run directly; skipped when sourced by tests).
_sc_check_for_updates() {
    # Use the same branch name for checking and pulling
    REMOTE_TIMESTAMP1=$(git log origin/master -n 1 --pretty=format:%cd scancannon.sh | awk '{print $1, $3, $2, $5, $4}')
    LOCAL_TIMESTAMP=$(date -r "scancannon.sh" +%s)
    if [ "$MACOS" = 1 ]; then
        REMOTE_TIMESTAMP=$(date -j -f "%a %d %b %Y %T" "$REMOTE_TIMESTAMP1" +%s)
    else
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
}

#Help Text:
function helptext() {
echo -e "\nScanCannon: a program to enumerate and parse a large range of public networks, primarily for determining potential attack vectors"
echo "usage: scancannon.sh [-u] [-a] [-V] [-n target] -d domain | -c CIDR | -f file  (at least one target required)"
echo ""
echo "  -d domain  Resolve a domain to its owning CIDR range via whois (repeatable)"
echo "             Accepts a bare domain (example.com) or URL (https://sub.example.com/path)"
echo "             URLs are automatically stripped to domain + TLD"
echo "  -c CIDR    Specify a CIDR range directly (repeatable)"
echo "  -f file    Read CIDR ranges from a file, one per line (repeatable)"
echo "             Blank lines and lines beginning with '#' are ignored"
echo "             File entries are scanned as-is (ASN discovery is skipped)"
echo "  -F         Force ASN-based network discovery on -f file entries"
echo "             (default: file entries scan as-is; use -F to expand them)"
echo "  -u         Perform UDP scan on common ports (53, 161, 500) using nmap"
echo "  -a         Perform API endpoint detection on HTTP/HTTPS services (requires curl)"
echo "             Also harvests TLS certificate SANs to discover more hostnames"
echo "  -V         CVE hinting: run nmap's 'vulners' NSE against detected versions"
echo "  -n target  Notify on completion. 'target' is either 'desktop' (macOS/notify-send)"
echo "             or a webhook URL (ntfy/Slack-style POST, requires curl)"
echo "  -p name    Project name. Results go under ./projects/<name>/ and are diffed"
echo "             against that project's previous scan. Skips the interactive"
echo "             project menu (useful for automation)"
echo ""
echo "  At least one -d, -c, or -f flag is required. You may combine them."
echo ""
echo "  Environment tunables:"
echo "    NMAP_MAX_PARALLEL  hosts scanned concurrently per CIDR (default 4)"
echo "    DNS_MAX_PARALLEL   domains resolved concurrently        (default 8)"
echo "    CIDR_MAX_PARALLEL  CIDR ranges scanned concurrently      (default 1)"
echo "    WHOIS_CACHE_TTL    whois cache lifetime in seconds       (default 86400)"
echo ""
echo "  Examples:"
echo "    scancannon.sh -d example.com"
echo "    scancannon.sh -c 203.0.113.0/24"
echo "    scancannon.sh -f CIDRs.txt"
echo "    scancannon.sh -d https://example.com -c 10.0.0.0/24 -f CIDRs.txt"
echo "    scancannon.sh -uaV -d example.com"
echo "    scancannon.sh -a -n desktop -c 203.0.113.0/24"
echo "    scancannon.sh -n https://ntfy.sh/my-scans -d example.com"
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
# Read a CIDR list file: echo each normalized, validated CIDR (bare IPs -> /32),
# skipping blank lines and '#' comments. Returns 1 (message on stderr) on the
# first invalid entry so callers can abort with file/line context.
read_cidr_file() {
    local file="$1" line num=0
    while IFS= read -r line || [ -n "$line" ]; do
        num=$((num + 1))
        # strip leading/trailing whitespace
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        if ! validate_cidr "$line" "$num" "$file" >&2; then
            return 1
        fi
        # normalize a bare IP to /32
        if [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            line="${line}/32"
        fi
        printf '%s\n' "$line"
    done < "$file"
    return 0
}

# Download/refresh the Public Suffix List (>30 days old or missing). Best-effort:
# on failure extract_domain falls back to the built-in MULTI_LABEL_SUFFIXES table.
ensure_psl() {
    local max_age=$((30 * 86400)) need=1
    if [ -s "$PSL_FILE" ]; then
        local mtime now
        now=$(date +%s)
        if [ "${MACOS:-0}" -eq 1 ]; then
            mtime=$(stat -f %m "$PSL_FILE" 2>/dev/null || echo 0)
        else
            mtime=$(stat -c %Y "$PSL_FILE" 2>/dev/null || echo 0)
        fi
        [ $((now - mtime)) -lt "$max_age" ] && need=0
    fi
    [ "$need" -eq 0 ] && return 0
    echo "Fetching Public Suffix List for accurate domain extraction..."
    if wget -q https://publicsuffix.org/list/public_suffix_list.dat -O "${PSL_FILE}.tmp" 2>/dev/null; then
        mv "${PSL_FILE}.tmp" "$PSL_FILE"
    else
        rm -f "${PSL_FILE}.tmp"
        echo "  WARNING: could not fetch PSL; using the built-in ccTLD table."
    fi
    return 0
}

# Reduce a hostname to its registrable domain using Public Suffix List rules
# (handles wildcard '*' and exception '!' rules). Reads $PSL_FILE.
public_suffix_domain() {
    awk -v host="$1" -v pslfile="$PSL_FILE" '
    function join(A, a, b,   s, k) { s=""; for (k=a; k<=b; k++) s = s (k>a?".":"") A[k]; return s }
    BEGIN {
        while ((getline line < pslfile) > 0) {
            gsub(/\r/, "", line)
            if (line == "" || line ~ /^\/\//) continue
            sub(/[ \t].*/, "", line)              # first field only
            if (line == "") continue
            if (substr(line,1,1) == "!") exc[substr(line,2)] = 1
            else rule[line] = 1
        }
        n = split(host, L, ".")
        if (n < 2) { print host; exit }
        found = 0; ps_start = n                    # default rule "*": suffix = last label
        for (i = 1; i <= n; i++)                    # exception rules take precedence
            if (join(L,i,n) in exc) { ps_start = i + 1; found = 1; break }
        if (!found)
            for (i = 1; i <= n; i++) {              # longest (most-labels) match wins
                if (join(L,i,n) in rule) { ps_start = i; break }
                if (i < n && ("*." join(L,i+1,n)) in rule) { ps_start = i; break }
            }
        reg_start = ps_start - 1
        if (reg_start < 1) reg_start = ps_start     # host is itself a public suffix
        print join(L, reg_start, n)
    }'
}

# Known multi-label public suffixes. IANA's TLD list only contains single
# labels (uk, au, ...), so registrable domains under these (example.co.uk) need
# an explicit table to avoid collapsing to the suffix itself (co.uk). This is a
# pragmatic subset of the Public Suffix List, used when $PSL_FILE is unavailable.
MULTI_LABEL_SUFFIXES=(
    co.uk org.uk gov.uk ac.uk me.uk ltd.uk plc.uk net.uk sch.uk
    com.au net.au org.au edu.au gov.au id.au
    co.nz net.nz org.nz govt.nz ac.nz
    co.za org.za net.za gov.za ac.za
    co.jp or.jp ne.jp go.jp ac.jp ad.jp
    com.br net.br org.br gov.br edu.br
    com.cn net.cn org.cn gov.cn edu.cn
    com.mx com.ar com.tr com.sg com.hk com.tw com.ua com.pl com.ru
    co.in net.in org.in gov.in co.kr or.kr co.il org.il
)

function extract_domain() {
    local input="$1"

    # Strip protocol (http://, https://, ftp://, etc.)
    local hostname
    hostname=$(echo "$input" | sed -E 's|^[a-zA-Z]+://||')
    # Strip path, query string, port, trailing slashes
    hostname=$(echo "$hostname" | sed -E 's|[:/].*||; s|/$||')
    # Strip "www." prefix
    hostname=$(echo "$hostname" | sed -E 's|^www\.||i')
    # Normalize case (domains are case-insensitive)
    hostname=$(echo "$hostname" | tr '[:upper:]' '[:lower:]')

    if [ -z "$hostname" ]; then
        echo ""
        return 1
    fi

    # Prefer the Public Suffix List when present (downloaded during -d setup);
    # fall back to the built-in table offline and in tests.
    if [ -s "$PSL_FILE" ]; then
        local reg
        reg=$(public_suffix_domain "$hostname")
        if [ -n "$reg" ]; then
            echo "$reg"
            return 0
        fi
    fi

    local nlabels
    nlabels=$(echo "$hostname" | awk -F'.' '{print NF}')
    if [ "$nlabels" -le 2 ]; then
        echo "$hostname"
        return 0
    fi

    # If the final two labels form a known multi-label suffix (co.uk, com.au),
    # keep three labels; otherwise the registrable domain is the last two.
    local last2 suffix
    last2=$(echo "$hostname" | awk -F'.' '{print $(NF-1)"."$NF}')
    for suffix in "${MULTI_LABEL_SUFFIXES[@]}"; do
        if [ "$last2" = "$suffix" ]; then
            echo "$hostname" | awk -F'.' '{print $(NF-2)"."$(NF-1)"."$NF}'
            return 0
        fi
    done
    echo "$hostname" | awk -F'.' '{print $(NF-1)"."$NF}'
}

# ===== NETWORK DISCOVERY ENGINE =====
# Shared infrastructure for both -d (domain) and -c (CIDR) inputs.
# Pipeline: IP → whois (CIDR + ASN + Org) → RADB (all ASN prefixes) → interactive selection

# ----- whois with on-disk cache + retry/backoff -----
# Large ASN sweeps fire many whois queries (network discovery AND per-domain
# resolution). whois servers routinely rate-limit, producing empty replies and
# "N/A,N/A,N/A" gaps. cached_whois() serves fresh cached answers, retries with
# backoff on empty replies, and falls back to a stale cache entry rather than
# returning nothing. Same argument vector as `whois`, e.g.:
#     cached_whois 203.0.113.1
#     cached_whois -h whois.radb.net -- "-i origin AS64500"
WHOIS_CACHE_DIR="${WHOIS_CACHE_DIR:-./.scancannon_cache/whois}"
WHOIS_CACHE_TTL="${WHOIS_CACHE_TTL:-86400}"   # seconds; default 1 day
WHOIS_MAX_RETRIES="${WHOIS_MAX_RETRIES:-3}"

cached_whois() {
    mkdir -p "$WHOIS_CACHE_DIR" 2>/dev/null || true
    local key cache_file
    # Key on the full argument vector so IP and RADB queries don't collide.
    key=$(printf '%s' "$*" | cksum | awk '{print $1 "_" $2}')
    cache_file="${WHOIS_CACHE_DIR}/${key}"

    # Serve a fresh, non-empty cache hit.
    if [ -s "$cache_file" ]; then
        local now mtime
        now=$(date +%s)
        if [ "${MACOS:-0}" -eq 1 ]; then
            mtime=$(stat -f %m "$cache_file" 2>/dev/null || echo 0)
        else
            mtime=$(stat -c %Y "$cache_file" 2>/dev/null || echo 0)
        fi
        if [ $((now - mtime)) -lt "$WHOIS_CACHE_TTL" ]; then
            cat "$cache_file"
            return 0
        fi
    fi

    # Query live, retrying with linear backoff on empty replies.
    local attempt=1 out=""
    while [ "$attempt" -le "$WHOIS_MAX_RETRIES" ]; do
        out=$(whois "$@" 2>/dev/null)
        if [ -n "$out" ]; then
            printf '%s' "$out" > "$cache_file" 2>/dev/null || true
            printf '%s' "$out"
            return 0
        fi
        sleep $((attempt * 2))
        attempt=$((attempt + 1))
    done

    # All live attempts failed — better a stale answer than none.
    if [ -s "$cache_file" ]; then
        cat "$cache_file"
        return 0
    fi
    return 1
}

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
    if [ ${#cidrs[@]} -gt 0 ]; then
        printf '%s\n' "${cidrs[@]}" | sort -u -t'/' -k1,1V -k2,2n
    fi
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
    if [ ${#asns[@]} -gt 0 ]; then
        printf '%s\n' "${asns[@]}" | sort -u
    fi
}

# Extract organization name from whois output
# Checks fields in priority order: OrgName > org-name > descr > netname
function extract_org_from_whois() {
    local whois_output="$1"
    local result=""

    # Check in priority order — OrgName is most authoritative. Covers ARIN
    # (OrgName/Organization), RIPE/APNIC (org-name/descr/netname).
    for field in 'OrgName' 'Organization' 'org-name' 'descr' 'netname'; do
        result=$(echo "$whois_output" | grep -i "^${field}:" | head -1 | sed 's/^[^:]*:[[:space:]]*//')
        if [ -n "$result" ]; then
            echo "$result"
            return 0
        fi
    done

    echo ""
}

# Extract ALL org-related strings from whois for cloud detection
# Returns all unique values from OrgName, org-name, netname, descr fields
function extract_all_org_fields() {
    local whois_output="$1"
    echo "$whois_output" | grep -iE '^(OrgName|org-name|descr|netname|Organization):' | \
        sed 's/^[^:]*:[[:space:]]*//' | sort -u
}

# ===== CLOUD / VPS PROVIDER DETECTION =====
# Check if the organization name belongs to a major cloud/VPS provider.
# Scanning these shared-infrastructure ranges is not useful for target enumeration
# because the CIDR ranges belong to the provider, not the target organization.
# Returns 0 (true) if cloud provider detected, 1 (false) otherwise.
CLOUD_PROVIDER_PATTERNS=(
    "amazon"
    "google"
    "microsoft"
    "digitalocean"
    "vultr"
    "choopa"
    "constant company"
    "linode"
    "akamai"
    "oracle"
    "ovh"
    "hetzner"
    "cloudflare"
    "alibaba"
    "alicloud"
    "softlayer"
    "ibm cloud"
    "rackspace"
    "fastly"
    "scaleway"
    "upcloud"
    "kamatera"
    "leaseweb"
    "contabo"
    "hostinger"
    "ionos"
)

function is_cloud_provider() {
    local org_name="$1"
    if [ -z "$org_name" ]; then
        return 1
    fi

    local org_lower
    org_lower=$(echo "$org_name" | tr '[:upper:]' '[:lower:]')

    for pattern in "${CLOUD_PROVIDER_PATTERNS[@]}"; do
        if [[ "$org_lower" == *"$pattern"* ]]; then
            return 0
        fi
    done

    return 1
}

# Query RADB (or similar IRR) for all prefixes announced by an ASN
function discover_asn_prefixes() {
    local asn="$1"
    local prefixes=()

    echo "  Querying RADB for all prefixes announced by $asn..."

    local radb_output
    radb_output=$(cached_whois -h whois.radb.net -- "-i origin $asn")

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
    whois_output=$(cached_whois "$ip")

    if [ -z "$whois_output" ]; then
        echo "  WARNING: whois returned no data for $ip"
        return 1
    fi

    # Extract organization
    DISCOVERED_ORG=$(extract_org_from_whois "$whois_output")

    # Check if the IP belongs to a cloud/VPS provider
    # Check primary org name AND all org-related whois fields for thorough detection
    local cloud_detected=false
    local cloud_match_org="$DISCOVERED_ORG"
    if is_cloud_provider "$DISCOVERED_ORG"; then
        cloud_detected=true
    else
        # Also check all org-related fields (OrgName, netname, descr, Organization)
        while IFS= read -r org_field; do
            if [ -n "$org_field" ] && is_cloud_provider "$org_field"; then
                cloud_detected=true
                cloud_match_org="$org_field"
                break
            fi
        done < <(extract_all_org_fields "$whois_output")
    fi
    if [ "$cloud_detected" = true ]; then
        echo ""
        echo "  ╔══════════════════════════════════════════════════════════════╗"
        echo "  ║  ⚠️  CLOUD/VPS PROVIDER DETECTED                            ║"
        echo "  ╠══════════════════════════════════════════════════════════════╣"
        printf "  ║  IP       : %-49s║\n" "$ip"
        printf "  ║  Org      : %-49s║\n" "${cloud_match_org:0:49}"
        echo "  ╠══════════════════════════════════════════════════════════════╣"
        echo "  ║  This IP is hosted on shared cloud/VPS infrastructure.     ║"
        echo "  ║  The CIDR ranges belong to the provider, NOT the target.   ║"
        echo "  ║  Scanning these ranges would scan the entire provider's    ║"
        echo "  ║  network, which is not useful and potentially dangerous.   ║"
        echo "  ╚══════════════════════════════════════════════════════════════╝"
        echo ""
        read -r -p "  Do you still want to proceed with network discovery for this IP? [y/N]: " cloud_choice
        case "$cloud_choice" in
            y|Y )
                echo "  Proceeding with cloud-hosted network discovery as requested."
                ;;
            * )
                echo "  Skipping this IP."
                return 2  # Cloud provider skipped by user choice
                ;;
        esac
    fi

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
    if [ ${#DISCOVERED_ASNS[@]} -gt 0 ]; then
        for asn in "${DISCOVERED_ASNS[@]}"; do
            local asn_prefixes
            asn_prefixes=$(discover_asn_prefixes "$asn")
            if [ -n "$asn_prefixes" ]; then
                while IFS= read -r prefix; do
                    all_prefixes+=("$prefix")
                done <<< "$asn_prefixes"
            fi
        done
    fi

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

    local cloud_skip_count=0
    for ip in "${all_ips[@]}"; do
        echo "  ── Discovering networks for IP: $ip ──"
        local disc_rc=0
        discover_networks_for_ip "$ip" "$hostname" || disc_rc=$?

        if [ "$disc_rc" -eq 2 ]; then
            # Cloud provider detected for this IP — skip it
            cloud_skip_count=$((cloud_skip_count + 1))
            continue
        elif [ "$disc_rc" -ne 0 ]; then
            echo "  WARNING: Network discovery failed for $ip (exit code $disc_rc), skipping."
            continue
        fi

        if [ -n "$DISCOVERED_ORG" ] && [ -z "$org_name" ]; then
            org_name="$DISCOVERED_ORG"
        fi

        if [ ${#DISCOVERED_ASNS[@]} -gt 0 ]; then
            for asn in "${DISCOVERED_ASNS[@]}"; do
                all_asns+=("$asn")
            done
        fi

        if [ ${#DISCOVERED_RANGES[@]} -gt 0 ]; then
            for range in "${DISCOVERED_RANGES[@]}"; do
                all_ranges+=("$range")
            done
        fi
    done

    # If ALL IPs were cloud-hosted, return error
    if [ "$cloud_skip_count" -eq "${#all_ips[@]}" ]; then
        echo ""
        echo "  ERROR: All ${#all_ips[@]} IP(s) for '$hostname' are hosted on cloud/VPS providers."
        echo "  No scannable networks found. Skipping this domain."
        return 2
    fi

    # Deduplicate
    local unique_ranges=()
    if [ ${#all_ranges[@]} -gt 0 ]; then
        while IFS= read -r range; do
            unique_ranges+=("$range")
        done < <(printf '%s\n' "${all_ranges[@]}" | sort -u -t'/' -k1,1V -k2,2n)
    fi

    local unique_asns=()
    if [ ${#all_asns[@]} -gt 0 ]; then
        while IFS= read -r asn; do
            unique_asns+=("$asn")
        done < <(printf '%s\n' "${all_asns[@]}" | sort -u)
    fi

    # Store for display in interactive_range_selection
    DISCOVERED_ORG="$org_name"
    if [ ${#unique_asns[@]} -gt 0 ]; then
        DISCOVERED_ASNS=("${unique_asns[@]}")
    else
        DISCOVERED_ASNS=()
    fi

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
    local disc_rc=0
    discover_networks_for_ip "$rep_ip" "$cidr_input" || disc_rc=$?

    if [ "$disc_rc" -eq 2 ]; then
        # Cloud provider detected — still allow scanning the user-specified CIDR
        echo "  NOTE: Cloud provider detected, but proceeding with user-specified CIDR: $cidr_input"
    elif [ "$disc_rc" -ne 0 ]; then
        echo "  WARNING: Network discovery failed for $cidr_input, proceeding with specified CIDR only."
    fi

    # Always include the original CIDR in the discovery results
    local all_ranges=("$cidr_input")
    if [ ${#DISCOVERED_RANGES[@]} -gt 0 ]; then
        for range in "${DISCOVERED_RANGES[@]}"; do
            all_ranges+=("$range")
        done
    fi

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

_sc_check_dependencies() {
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
}

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
    
    # Detect interfaces (read loop keeps this Bash 3.2-safe — no mapfile).
    echo "Detecting network interfaces..."
    local interfaces=()
    while IFS= read -r _iface; do
        [ -n "$_iface" ] && interfaces+=("$_iface")
    done < <(detect_interfaces)

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
            local details ip mac
            details=$(get_interface_details "${interfaces[$i]}")
            ip="${details%%|*}"
            mac="${details##*|}"
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
    local details
    details=$(get_interface_details "$selected_interface")
    selected_ip="${details%%|*}"
    selected_mac="${details##*|}"
    
    if [ -z "$selected_ip" ] || [ -z "$selected_mac" ]; then
        echo "Could not determine IP or MAC for interface $selected_interface. Skipping automatic configuration."
        return
    fi
    
    echo "Selected interface: $selected_interface"
    echo "  IP: $selected_ip"
    echo "  MAC: $selected_mac"
    
    # Detect gateways (read loop keeps this Bash 3.2-safe — no mapfile).
    echo "Detecting default gateways..."
    local gateways=()
    while IFS= read -r _gw; do
        [ -n "$_gw" ] && gateways+=("$_gw")
    done < <(detect_gateways)
    
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

# Slugify an arbitrary project name into a safe directory component.
_slugify() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^[-.]+//; s/-+$//'
}

# Choose or create a project; sets PROJECT_SLUG, PROJECT_DIR and RESULTS_DIR.
# Honors -p <name> (PROJECT_NAME) to bypass the interactive menu for automation.
_sc_select_project() {
    mkdir -p "$PROJECTS_ROOT"
    local chosen=""

    if [ -n "${PROJECT_NAME:-}" ]; then
        chosen="$(_slugify "$PROJECT_NAME")"
    else
        local projects=() d
        for d in "$PROJECTS_ROOT"/*/; do
            [ -d "$d" ] || continue
            projects+=("$(basename "$d")")
        done

        echo ""
        echo "═══════════════════════════════════════════════════"
        echo "  Project Selection"
        echo "═══════════════════════════════════════════════════"
        if [ ${#projects[@]} -eq 0 ]; then
            echo "  (no existing projects yet)"
        else
            echo "  Existing projects:"
            local i
            for i in "${!projects[@]}"; do
                printf "    [%2d] %s\n" "$((i + 1))" "${projects[$i]}"
            done
        fi
        echo "    [ n] Create a new project"
        echo ""
        read -r -p "  Select a project number, or 'n' for new: " sel

        case "$sel" in
            n|N|"" )
                read -r -p "  New project name: " newname
                chosen="$(_slugify "$newname")"
                ;;
            * )
                if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#projects[@]} ]; then
                    chosen="${projects[$((sel - 1))]}"
                else
                    echo "  ERROR: invalid selection '$sel'."
                    exit 1
                fi
                ;;
        esac
    fi

    if [ -z "$chosen" ]; then
        echo "  ERROR: empty/invalid project name."
        exit 1
    fi

    PROJECT_SLUG="$chosen"
    PROJECT_DIR="${PROJECTS_ROOT}/${PROJECT_SLUG}"
    RESULTS_DIR="${PROJECT_DIR}/results"
    mkdir -p "$RESULTS_DIR" "${PROJECT_DIR}/history"
    echo "  Using project: ${PROJECT_SLUG}   (results in ${RESULTS_DIR})"
    echo ""
}

_sc_parse_args_and_setup() {
# Always offer network adapter configuration
configure_adapter

#Parse command line options
UDP_SCAN=0
API_SCAN=0
CVE_SCAN=0
FORCE_FILE_DISCOVERY=0
NOTIFY_TARGET=""
PROJECT_NAME=""
DOMAIN_ARGS=()
CIDR_FLAG_ARGS=()
CIDR_FILE_ARGS=()

while getopts ":uaVFd:c:f:n:p:" opt; do
case ${opt} in
u )
UDP_SCAN=1
;;
a )
API_SCAN=1
;;
V )
CVE_SCAN=1
;;
F )
FORCE_FILE_DISCOVERY=1
;;
n )
NOTIFY_TARGET="$OPTARG"
;;
p )
PROJECT_NAME="$OPTARG"
;;
d )
DOMAIN_ARGS+=("$OPTARG")
;;
c )
CIDR_FLAG_ARGS+=("$OPTARG")
;;
f )
CIDR_FILE_ARGS+=("$OPTARG")
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

# A webhook notify target needs curl; validate up front so the run doesn't
# silently fail to notify hours later.
case "$NOTIFY_TARGET" in
    http://*|https://* )
        if ! command -v curl >/dev/null 2>&1; then
            echo "ERROR: curl is required to send webhook notifications (-n <url>). Please install it."
            exit 1
        fi
        ;;
esac

# Select/create the project — repoints RESULTS_DIR under ./projects/<slug>/.
_sc_select_project

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

# Expand -f file arguments. By default file entries skip ASN discovery and are
# scanned as-is; pass -F to run them through the same discovery pipeline as -c.
FILE_DIRECT_RANGES=()
if [ ${#CIDR_FILE_ARGS[@]} -gt 0 ]; then
    for cidr_file in "${CIDR_FILE_ARGS[@]}"; do
        if [ ! -f "$cidr_file" ]; then
            echo "ERROR: CIDR file '$cidr_file' not found."
            exit 1
        fi
        if [ ! -r "$cidr_file" ]; then
            echo "ERROR: CIDR file '$cidr_file' is not readable."
            exit 1
        fi
        # Parse + validate the file into normalized CIDRs (aborts on bad input).
        file_cidrs=""
        if ! file_cidrs="$(read_cidr_file "$cidr_file")"; then
            exit 1
        fi
        file_entries=0
        while IFS= read -r file_line; do
            [ -z "$file_line" ] && continue
            if [ "$FORCE_FILE_DISCOVERY" -eq 1 ]; then
                CIDR_FLAG_ARGS+=("$file_line")
            else
                FILE_DIRECT_RANGES+=("$file_line")
            fi
            file_entries=$((file_entries + 1))
        done <<< "$file_cidrs"
        if [ "$FORCE_FILE_DISCOVERY" -eq 1 ]; then
            echo "Loaded $file_entries CIDR entrie(s) from $cidr_file (ASN discovery forced via -F)"
        else
            echo "Loaded $file_entries CIDR entrie(s) from $cidr_file (scanning as-is; pass -F to force ASN discovery)"
        fi
    done
fi

# Require at least one -d, -c, or -f flag
if [ ${#DOMAIN_ARGS[@]} -eq 0 ] && [ ${#CIDR_FLAG_ARGS[@]} -eq 0 ] && [ ${#FILE_DIRECT_RANGES[@]} -eq 0 ]; then
    echo "ERROR: At least one -d (domain), -c (CIDR), or -f (CIDR file) flag is required."
    helptext >&2
    exit 1
fi

# File entries (no discovery) feed directly into the final scan list
for range in "${FILE_DIRECT_RANGES[@]}"; do
    CIDR_RANGES+=("$range")
done

# 1) Process -d (domain) flags — full ASN discovery pipeline
if [ ${#DOMAIN_ARGS[@]} -gt 0 ]; then
    ensure_psl   # accurate registrable-domain extraction for -d inputs
    echo ""
    echo "=== Domain Mode: Full Network Discovery ==="
    for domain_input in "${DOMAIN_ARGS[@]}"; do
        RESOLVED_CIDRS=()
        resolve_rc=0
        resolve_domain_to_cidr "$domain_input" || resolve_rc=$?
        if [ "$resolve_rc" -eq 0 ]; then
            for selected in "${RESOLVED_CIDRS[@]}"; do
                CIDR_RANGES+=("$selected")
            done
        elif [ "$resolve_rc" -eq 2 ]; then
            # Cloud provider — skip this domain, try next
            echo "  Skipping domain '$domain_input' (cloud/VPS provider)."
            continue
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
        cidr_rc=0
        discover_networks_for_cidr "$cidr_input" || cidr_rc=$?
        if [ "$cidr_rc" -eq 0 ]; then
            for selected in "${RESOLVED_CIDRS[@]}"; do
                CIDR_RANGES+=("$selected")
            done
        elif [ "$cidr_rc" -eq 2 ]; then
            # Cloud provider — but -c was explicit, ranges already handled
            echo "  NOTE: Cloud provider network, but scanning user-specified CIDR."
            CIDR_RANGES+=("$cidr_input")
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
if [ -d "${RESULTS_DIR}" ]; then
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
        rm -rf "${RESULTS_DIR}"
        mkdir -p "${RESULTS_DIR}"
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
mkdir -p "${RESULTS_DIR}"
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
        # Drop the IANA header comment line (first line). TLDs are stored as
        # bare labels; the domain-matching awk keys its hash on these directly.
        if [ "$MACOS" -eq 1 ]; then
            sed -i '' '1d' "$TLD_FILE"
        else
            sed -i '1d' "$TLD_FILE"
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
}  # end _sc_parse_args_and_setup (tools/getopts/inputs/filters)

#Initialize variables for summary
TOTAL_IPS=0
RESPONSIVE_IPS=0
DISCOVERED_SERVICES=0
DISCOVERED_API_ENDPOINTS=0
DISCOVERED_CERT_HOSTS=0
DISCOVERED_CVE_HINTS=0
INTERRUPTED=0

# Send a completion/interruption notification if -n was given.
# Target is either 'desktop' or a webhook URL.
function send_notification() {
    local status_msg="$1"
    local detail="$2"
    [ -z "$NOTIFY_TARGET" ] && return 0
    local title="ScanCannon"
    local body="Scan ${status_msg}. ${detail}"
    case "$NOTIFY_TARGET" in
        http://*|https://* )
            if curl -sf --max-time 10 -H "Title: ${title}" --data-binary "$body" "$NOTIFY_TARGET" >/dev/null 2>&1; then
                echo "Notification delivered to webhook."
            else
                echo "WARNING: notification POST to webhook failed."
            fi
            ;;
        desktop )
            if [ "$MACOS" -eq 1 ]; then
                osascript -e "display notification \"${body}\" with title \"${title}\"" >/dev/null 2>&1 || true
            elif command -v notify-send >/dev/null 2>&1; then
                notify-send "$title" "$body" >/dev/null 2>&1 || true
            else
                echo "WARNING: no desktop notifier available (install notify-send on Linux)."
            fi
            ;;
        * )
            echo "WARNING: unrecognized -n target '$NOTIFY_TARGET' (expected 'desktop' or a URL)."
            ;;
    esac
}

#Housekeeping function (defined early so it can be called by ctrl_c)
function cleanup() {
echo -e "\nPerforming cleanup. . . "
cleanup_progress
# Preserve masscan's paused.conf when interrupted so the scan can be resumed
# later (masscan --resume paused.conf). Only remove it on a clean finish.
if [ -f ./paused.conf ] && [ "$INTERRUPTED" -eq 0 ]; then
    rm ./paused.conf
fi
for DIRECTORY in ${RESULTS_DIR}/*/; do
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
rm -rf "${RESULTS_DIR}/all_interesting_servers/"*_files 2>/dev/null
done
chmod -R 776 "${RESULTS_DIR}"
}

# Handle Ctrl+C
function ctrl_c() {
INTERRUPTED=1
echo -e "\n\n[!] Ctrl+C detected. Cleaning up..."
cleanup
if [ -f ./paused.conf ]; then
    echo "masscan state saved to ./paused.conf — resume later with: masscan --resume paused.conf"
    echo "Or re-run ScanCannon and choose 'Merge' to continue with unfinished CIDRs."
fi
send_notification "interrupted" "Run was cancelled before completion."
echo -e "Exiting."
exit 0
}
# (the INT trap is installed by main, once the scan begins)

# ===== API ENDPOINT DETECTION FUNCTION =====
function detect_api_endpoints() {
    local dirname="$1"
    local api_output_dir="${RESULTS_DIR}/${dirname}/interesting_servers"
    local api_details_file="${api_output_dir}/api_details.txt"
    local api_servers_file="${api_output_dir}/api_servers.txt"

    mkdir -p "$api_output_dir"
    echo "=== API Endpoint Detection ===" > "$api_details_file"
    : > "$api_servers_file"

    echo -e "\n--- API Endpoint Detection ---"

    # --- TIER 1: Parse nmap XML for API indicators (single pass, POSIX awk) ---
    echo "[Tier 1] Analyzing nmap output for API indicators..."

    if ls "${RESULTS_DIR}/${dirname}"/*.xml >/dev/null 2>&1; then
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
        ' "${RESULTS_DIR}/${dirname}"/*.xml >> "$api_details_file" 2>/dev/null

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

            # The status/content-type ride in the last "__STATUS__code|ctype"
            # marker; split it with parameter expansion (no grep|sed|cut forks).
            local root_marker root_status root_ctype
            root_marker="${root_response##*__STATUS__}"
            root_status="${root_marker%%|*}"
            root_ctype="${root_marker#*|}"

            if [ "$root_status" = "000" ]; then
                consecutive_failures=$((consecutive_failures + 1))
            else
                consecutive_failures=0
                # Check for API headers in root response
                if echo "$root_response" | grep -qiE '(Access-Control-Allow-Origin|X-API-Version|X-RateLimit|X-Request-Id)'; then
                    echo "[Tier 2] API headers on root: ${ip}:${port}" >> "$details_file"
                    echo "${ip}:${port}" >> "$servers_file"
                fi
                # Check if root returns JSON (case-insensitive, no subprocess).
                # Character classes keep this Bash 3.2-safe (no ${var,,}).
                if [[ "$root_ctype" == *[Jj][Ss][Oo][Nn]* ]]; then
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

    # Note: the per-CIDR api_servers.txt is the source of truth. Global
    # aggregation (into all_api_servers.txt) and the summary count happen once,
    # after all CIDRs finish, so this stays correct under parallel CIDR scans.
    if [ -s "$api_servers_file" ]; then
        sort -u -o "$api_servers_file" "$api_servers_file"
        local total_endpoints
        total_endpoints=$(wc -l < "$api_servers_file")
        echo "API Detection Complete: $total_endpoints endpoint(s) discovered"
    else
        echo "API Detection Complete: No API endpoints detected"
    fi

    echo "  Details: $api_details_file"
    echo "  Endpoints: $api_servers_file"
    echo "--- End API Detection ---"
}

# Services considered "interesting" — shared by the per-CIDR classifier, the
# aggregation step, and the report. (Add here to extend coverage everywhere.)
# Resolve one root domain to a CSV row "domain,ip,cidr,asn,org", registry
# agnostic: reuses the extract_*_from_whois helpers so RIPE/APNIC/AFRINIC space
# resolves too (the old inline parser only understood ARIN field names).
resolve_root_domain() {
    local domain="$1" outfile="$2"
    local ip whois_data cidr asn org
    ip="$(dig "$domain" +short 2>/dev/null | grep -E '^[0-9]+\.' | head -1)"
    [ -z "$ip" ] && return 0
    whois_data="$(cached_whois "$ip")"
    cidr="$(extract_cidrs_from_whois "$whois_data" | head -1)"
    asn="$(extract_asn_from_whois "$whois_data" | head -1)"
    org="$(extract_org_from_whois "$whois_data")"
    [ -z "$cidr" ] && cidr="N/A"
    [ -z "$asn" ] && asn="N/A"
    [ -z "$org" ] && org="N/A"
    org="${org//,/ }"   # commas would corrupt the CSV row
    printf '%s,%s,%s,%s,%s\n' "$domain" "$ip" "$cidr" "$asn" "$org" > "$outfile"
}

SERVICE_LIST="domain msrpc snmp netbios-ssn microsoft-ds isakmp l2f pptp ftp sftp ssh telnet http ssl https"

# ===== PER-CIDR SCAN PIPELINE =====
# Everything for one CIDR lives in this function so ranges can be scanned
# serially OR concurrently. It mutates NO shell globals: per-CIDR counts are
# written to results/<dir>/.stats and summed afterward by aggregate_results,
# so totals stay correct even when CIDRs run in parallel subshells.
scan_cidr() {
    local CIDR="$1"
    local worker_idx="${2:-0}"
    local DIRNAME
    DIRNAME="$(printf '%s' "$CIDR" | sed -e 's/\//_/g' -e 's/ /_/g' -e 's/[^a-zA-Z0-9_.-]/_/g')"
    mkdir -p "${RESULTS_DIR}/$DIRNAME"

    # Resume checkpoint: skip a CIDR that already finished (Merge re-runs).
    if [ -f "${RESULTS_DIR}/${DIRNAME}/.scan_complete" ]; then
        echo "  [resume] $CIDR already complete — skipping (rm ${RESULTS_DIR}/${DIRNAME}/.scan_complete to force)."
        return 0
    fi

    # Addressable IPs in this CIDR (for the summary).
    local cidr_ips
    cidr_ips=$(printf '%s' "$CIDR" | awk -F/ '{ if (NF>1 && $2!="") print 2^(32-$2); else print 1 }')

    # Distinct source port per worker (inside the firewalled 40000-41023 band).
    local src_port=$((40000 + (worker_idx % 1024)))

    echo "Scanning $CIDR ..."
    echo -e "\n*** Firing ScanCannon. Please keep arms and legs inside the chamber at all times ***"
    masscan -c scancannon.conf --open --rate "$MASSCAN_RATE_SHARE" --source-port "$src_port" -oB "${RESULTS_DIR}/${DIRNAME}/masscan_output.bin" "$CIDR"
    masscan --readscan "${RESULTS_DIR}/${DIRNAME}/masscan_output.bin" -oL "${RESULTS_DIR}/${DIRNAME}/masscan_output.txt"

    if [ ! -s "${RESULTS_DIR}/${DIRNAME}/masscan_output.txt" ]; then
        echo -e "\nNo IPs are up in $CIDR; skipping nmap.\n"
        printf 'cidr=%s\ntotal_ips=%s\nresponsive_ips=0\nservices=0\napi_endpoints=0\ncert_hosts=0\ncve_hints=0\nstatus=dead\n' \
            "$CIDR" "$cidr_ips" > "${RESULTS_DIR}/${DIRNAME}/.stats"
        touch "${RESULTS_DIR}/${DIRNAME}/.scan_complete"
        return 0
    fi

    #Consolidate IPs and open ports for each IP (one line per responsive IP):
    awk '/open/ {print $4,$3,$2,$1}' "${RESULTS_DIR}/${DIRNAME}/masscan_output.txt" | awk '
            /.+/{
                if (!($1 in Val)) { Key[++i] = $1 }
                Val[$1] = Val[$1] $2 ","
            }
        END{ for (j = 1; j <= i; j++) printf("%s:%s\n", Key[j], Val[Key[j]]) }
        ' | sed 's/,$//' > "${RESULTS_DIR}/${DIRNAME}/hosts_and_ports.txt"

    local TOTAL_HOSTS CURRENT_HOST
    TOTAL_HOSTS=$(wc -l < "${RESULTS_DIR}/${DIRNAME}/hosts_and_ports.txt" | tr -d ' ')
    CURRENT_HOST=0

    #First a blind UDP nmap of common ports (masscan is TCP-only).
    if [ "$UDP_SCAN" -eq 1 ]; then
        echo -e "\nStarting DNS, SNMP and VPN UDP scan for $CIDR"
        nmap -v --open -sV --version-light -sU -T3 -p 53,161,500 -oA "${RESULTS_DIR}/${DIRNAME}/nmap_${DIRNAME}_udp" "$CIDR"
    fi

    # NSE script set:
    #   ssl-cert : always on (cheap; feeds TLS-cert SAN harvesting below)
    #   http-*   : only with -a (API detection)
    #   vulners  : only with -V (CVE hinting; relies on -sV, already enabled)
    # Every script carries its own portrule, so nmap only runs each where it
    # applies — listing them all for every host is safe.
    local scripts="ssl-cert"
    [ "$API_SCAN" -eq 1 ] && scripts="${scripts},http-headers,http-title,http-robots.txt,http-server-header"
    [ "$CVE_SCAN" -eq 1 ] && scripts="${scripts},vulners"
    local nse_arg="--script=${scripts}"
    local DIRNAME_L="$DIRNAME"

    # Run one nmap per host, several hosts concurrently (NMAP_MAX_PARALLEL).
    _scan_host() {
        local target="$1"
        local ip="${target%%:*}"
        local port="${target#*:}"
        echo -e "\nBeginning in-depth TCP scan of $ip on port(s) $port:\n"
        nmap -v --open -sV --version-light -sT -O -Pn -T3 "$nse_arg" -p "$port" -oA "${RESULTS_DIR}/${DIRNAME_L}/nmap_${ip}_tcp" "$ip"
    }

    local active_jobs=0
    while read -r TARGET; do
        [ -z "$TARGET" ] && continue
        _scan_host "$TARGET" &
        active_jobs=$((active_jobs + 1))
        if [ "$active_jobs" -ge "$NMAP_MAX_PARALLEL" ]; then
            wait -n 2>/dev/null || wait
            active_jobs=$((active_jobs - 1))
            CURRENT_HOST=$((CURRENT_HOST + 1))
            PROGRESS=$((CURRENT_HOST * 100 / TOTAL_HOSTS))
            echo -ne "\r[$CIDR] Progress: [$PROGRESS%] [$CURRENT_HOST/$TOTAL_HOSTS] hosts scanned..."
        fi
    done <"${RESULTS_DIR}/${DIRNAME}/hosts_and_ports.txt"
    wait
    echo -ne "\r[$CIDR] Progress: [100%] [$TOTAL_HOSTS/$TOTAL_HOSTS] hosts scanned...Done.\n"

    #Classify Interesting Services™️ in a SINGLE pass over the gnmap files.
    #Per-CIDR files only; global aggregation runs after all CIDRs finish.
    mkdir -p "${RESULTS_DIR}/${DIRNAME}/interesting_servers/"
    local svc_count=0
    if ls "${RESULTS_DIR}/${DIRNAME}"/*.gnmap >/dev/null 2>&1; then
        local INTERESTING_DIR="${RESULTS_DIR}/${DIRNAME}/interesting_servers"
        # nmap gnmap ports are "port/state/proto/owner/service/rpc/version"; the
        # service name is field 5 (owner is usually empty). Match on that field.
        awk -v services="$SERVICE_LIST" -v outdir="$INTERESTING_DIR" '
            BEGIN { n = split(services, svc, " ") }
            /open/ {
                ip = $2
                if (ip == "") { next }
                for (i = 3; i <= NF; i++) {
                    m = split($i, port_parts, "/")
                    if (m < 5) { continue }
                    if (port_parts[2] != "open") { continue }
                    if (port_parts[1] !~ /^[0-9]+$/) { continue }
                    svc_field = port_parts[5]
                    if (svc_field == "") { continue }
                    for (s = 1; s <= n; s++) {
                        if (index(svc_field, svc[s]) > 0) {
                            fname = outdir "/" svc[s] "_servers.txt"
                            print ip ":" port_parts[1] > fname
                        }
                    }
                }
            }
        ' "${RESULTS_DIR}/${DIRNAME}"/*.gnmap

        local SERVICE service_file
        for SERVICE in $SERVICE_LIST; do
            service_file="${INTERESTING_DIR}/${SERVICE}_servers.txt"
            [ -f "$service_file" ] || : > "$service_file"
            if [ -s "$service_file" ]; then
                sort -u -o "$service_file" "$service_file"
                svc_count=$((svc_count + $(wc -l < "$service_file")))
            fi
        done
    fi

    # ===== API ENDPOINT DETECTION =====
    local api_count=0
    if [ "$API_SCAN" -eq 1 ]; then
        detect_api_endpoints "$DIRNAME"
        [ -s "${RESULTS_DIR}/${DIRNAME}/interesting_servers/api_servers.txt" ] && \
            api_count=$(wc -l < "${RESULTS_DIR}/${DIRNAME}/interesting_servers/api_servers.txt" | tr -d ' ')
    fi

    # ===== TLS CERTIFICATE SAN HARVESTING =====
    # Pull DNS names from ssl-cert NSE output. These frequently reveal hostnames
    # (and sibling domains) that PTR records miss, and they feed the domain
    # resolution below to enrich discovered-domain output.
    : > "${RESULTS_DIR}/${DIRNAME}/cert_sans.txt"
    if ls "${RESULTS_DIR}/${DIRNAME}"/*.nmap >/dev/null 2>&1; then
        # '|| true': grep exits non-zero when a CIDR has no certs, which would
        # otherwise abort the run under 'set -e'/pipefail.
        grep -hoiE 'DNS:[^,[:space:]]+' "${RESULTS_DIR}/${DIRNAME}"/*.nmap 2>/dev/null \
            | sed -e 's/^[Dd][Nn][Ss]://' -e 's/^\*\.//' \
            | tr 'A-Z' 'a-z' | sort -u > "${RESULTS_DIR}/${DIRNAME}/cert_sans.txt" || true
    fi
    local cert_hosts=0
    [ -s "${RESULTS_DIR}/${DIRNAME}/cert_sans.txt" ] && cert_hosts=$(wc -l < "${RESULTS_DIR}/${DIRNAME}/cert_sans.txt" | tr -d ' ')

    # ===== CVE HINTS (count unique CVE IDs found by the vulners NSE) =====
    local cve_hints=0
    if [ "$CVE_SCAN" -eq 1 ] && ls "${RESULTS_DIR}/${DIRNAME}"/*.nmap >/dev/null 2>&1; then
        # '|| true' so a CIDR with zero CVE hits doesn't abort under 'set -e'.
        cve_hints=$( { grep -hoiE 'CVE-[0-9]{4}-[0-9]+' "${RESULTS_DIR}/${DIRNAME}"/*.nmap 2>/dev/null | sort -u | wc -l | tr -d ' '; } || true )
    fi

    # ===== DOMAIN RESOLUTION =====
    echo "Root Domain,IP,CIDR,AS#,IP Owner" > "${RESULTS_DIR}/${DIRNAME}/resolved_root_domains.csv"
    : > "${RESULTS_DIR}/${DIRNAME}/resolved_subdomains.txt"
    if [ -s "./all_tlds.txt" ] && ls "${RESULTS_DIR}/${DIRNAME}"/*.gnmap >/dev/null 2>&1; then
        awk -F'[()]' '
            BEGIN {
                while ((getline tld < "./all_tlds.txt") > 0) {
                    if (tld ~ /^#/ || tld == "") { continue }
                    tld = tolower(tld); gsub(/^[^a-z0-9]+/, "", tld)
                    if (tld != "") { tlds[tld] = 1 }
                }
                close("./all_tlds.txt")
            }
            { if ($2) { domain = tolower($2); n = split(domain, labels, "."); if (n >= 2 && (labels[n] in tlds)) domains[domain] = 1 } }
            END { for (domain in domains) print domain }
        ' "${RESULTS_DIR}/${DIRNAME}"/*.gnmap | sort -u > "${RESULTS_DIR}/${DIRNAME}/resolved_subdomains.txt"
    fi
    # Fold harvested TLS-cert SAN hostnames into the subdomain set so they get
    # resolved/whois'd too — this is the cert data feeding back into discovery.
    if [ -s "${RESULTS_DIR}/${DIRNAME}/cert_sans.txt" ]; then
        cat "${RESULTS_DIR}/${DIRNAME}/cert_sans.txt" >> "${RESULTS_DIR}/${DIRNAME}/resolved_subdomains.txt"
        sort -u -o "${RESULTS_DIR}/${DIRNAME}/resolved_subdomains.txt" "${RESULTS_DIR}/${DIRNAME}/resolved_subdomains.txt"
    fi

    if [ -s "${RESULTS_DIR}/${DIRNAME}/resolved_subdomains.txt" ]; then
        local temp_domains resolve_dir
        temp_domains=$(mktemp)
        resolve_dir=$(mktemp -d)

        # Independent, network-bound dig+whois per domain — resolve several at
        # once (DNS_MAX_PARALLEL); each job writes its own file to avoid mangling.
        local active_jobs=0 domain_idx=0
        while IFS= read -r DOMAIN; do
            [ -z "$DOMAIN" ] && continue
            domain_idx=$((domain_idx + 1))
            resolve_root_domain "$DOMAIN" "${resolve_dir}/${domain_idx}" &
            active_jobs=$((active_jobs + 1))
            if [ "$active_jobs" -ge "$DNS_MAX_PARALLEL" ]; then
                wait -n 2>/dev/null || wait
                active_jobs=$((active_jobs - 1))
            fi
        done < <(awk -F. '{ print $(NF-1)"."$NF }' "${RESULTS_DIR}/${DIRNAME}/resolved_subdomains.txt" | sort -u)
        wait

        cat "${resolve_dir}"/* 2>/dev/null >> "$temp_domains"
        rm -rf "$resolve_dir"
        [ -s "$temp_domains" ] && cat "$temp_domains" >> "${RESULTS_DIR}/${DIRNAME}/resolved_root_domains.csv"
        rm -f "$temp_domains"
    fi

    # Persist per-CIDR stats and mark complete (for resume + aggregation).
    printf 'cidr=%s\ntotal_ips=%s\nresponsive_ips=%s\nservices=%s\napi_endpoints=%s\ncert_hosts=%s\ncve_hints=%s\nstatus=scanned\n' \
        "$CIDR" "$cidr_ips" "$TOTAL_HOSTS" "$svc_count" "$api_count" "$cert_hosts" "$cve_hints" > "${RESULTS_DIR}/${DIRNAME}/.stats"
    touch "${RESULTS_DIR}/${DIRNAME}/.scan_complete"
}

# ===== AGGREGATION =====
# Rebuild the global all_* files and summary totals from every completed CIDR's
# per-CIDR outputs. Runs once after scanning, so it is correct regardless of
# whether CIDRs ran serially or in parallel.
aggregate_results() {
    TOTAL_IPS=0; RESPONSIVE_IPS=0; DISCOVERED_SERVICES=0
    DISCOVERED_API_ENDPOINTS=0; DISCOVERED_CERT_HOSTS=0; DISCOVERED_CVE_HINTS=0
    mkdir -p "${RESULTS_DIR}/all_interesting_servers"

    : > "${RESULTS_DIR}/all_subdomains.txt"
    : > "${RESULTS_DIR}/all_cert_sans.txt"
    : > "${RESULTS_DIR}/all_interesting_servers/all_api_servers.txt"
    echo "Root Domain,IP,CIDR,AS#,IP Owner" > "${RESULTS_DIR}/all_root_domains.csv"
    local SERVICE
    for SERVICE in $SERVICE_LIST; do
        : > "${RESULTS_DIR}/all_interesting_servers/all_${SERVICE}_servers.txt"
    done

    local d base k v
    for d in ${RESULTS_DIR}/*/; do
        base=$(basename "$d")
        case "$base" in
            all_interesting_servers|*interesting*) continue ;;
        esac
        [ -f "${d}.stats" ] || continue
        while IFS='=' read -r k v; do
            case "$k" in
                total_ips)       TOTAL_IPS=$((TOTAL_IPS + v)) ;;
                responsive_ips)  RESPONSIVE_IPS=$((RESPONSIVE_IPS + v)) ;;
                services)        DISCOVERED_SERVICES=$((DISCOVERED_SERVICES + v)) ;;
                api_endpoints)   DISCOVERED_API_ENDPOINTS=$((DISCOVERED_API_ENDPOINTS + v)) ;;
                cert_hosts)      DISCOVERED_CERT_HOSTS=$((DISCOVERED_CERT_HOSTS + v)) ;;
                cve_hints)       DISCOVERED_CVE_HINTS=$((DISCOVERED_CVE_HINTS + v)) ;;
            esac
        done < "${d}.stats"

        for SERVICE in $SERVICE_LIST; do
            [ -s "${d}interesting_servers/${SERVICE}_servers.txt" ] && \
                cat "${d}interesting_servers/${SERVICE}_servers.txt" >> "${RESULTS_DIR}/all_interesting_servers/all_${SERVICE}_servers.txt"
        done
        [ -s "${d}interesting_servers/api_servers.txt" ] && cat "${d}interesting_servers/api_servers.txt" >> "${RESULTS_DIR}/all_interesting_servers/all_api_servers.txt"
        [ -s "${d}resolved_subdomains.txt" ] && cat "${d}resolved_subdomains.txt" >> "${RESULTS_DIR}/all_subdomains.txt"
        [ -s "${d}cert_sans.txt" ] && cat "${d}cert_sans.txt" >> "${RESULTS_DIR}/all_cert_sans.txt"
        [ -f "${d}resolved_root_domains.csv" ] && tail -n +2 "${d}resolved_root_domains.csv" >> "${RESULTS_DIR}/all_root_domains.csv"
    done

    local f
    for f in "${RESULTS_DIR}/all_subdomains.txt" "${RESULTS_DIR}/all_cert_sans.txt" ${RESULTS_DIR}/all_interesting_servers/all_*_servers.txt; do
        [ -s "$f" ] && sort -u -o "$f" "$f"
    done
    # Return 0 explicitly: the loop above can leave a non-zero status (last file
    # empty), which would abort the caller under 'set -e'.
    return 0
}

# ===== SCAN DIFF (changes since last scan) =====
# Canonical "service ip:port" findings list for the current run (sorted, deduped)
# — the unit that project-to-project scan diffs compare.
build_findings_snapshot() {
    local out="$1" svc f
    : > "$out"
    for svc in $SERVICE_LIST; do
        f="${RESULTS_DIR}/all_interesting_servers/all_${svc}_servers.txt"
        [ -s "$f" ] && awk -v s="$svc" 'NF{print s" "$0}' "$f" >> "$out"
    done
    sort -u -o "$out" "$out"
}

# Diff two findings snapshots into added/removed files. Pure (no globals) so it
# is easy to test. With no/empty baseline, everything current counts as added.
compute_findings_delta() {
    local baseline="$1" current="$2" added_out="$3" removed_out="$4"
    if [ -s "$baseline" ]; then
        comm -13 <(sort -u "$baseline") <(sort -u "$current") > "$added_out"
        comm -23 <(sort -u "$baseline") <(sort -u "$current") > "$removed_out"
    else
        cp "$current" "$added_out" 2>/dev/null || : > "$added_out"
        : > "$removed_out"
    fi
    return 0
}

# Orchestration: build the current snapshot, diff it against the project's most
# recent history snapshot, and record the delta for the report + summary.
_sc_compute_changes() {
    local cur="${RESULTS_DIR}/.findings_current"
    build_findings_snapshot "$cur"

    DELTA_BASELINE=""
    if [ -n "$PROJECT_DIR" ]; then
        local latest
        latest=$(ls -1d "${PROJECT_DIR}/history/"*/ 2>/dev/null | sort | tail -1)
        [ -n "$latest" ] && DELTA_BASELINE="${latest}services.txt"
    fi

    compute_findings_delta "${DELTA_BASELINE:-/nonexistent}" "$cur" \
        "${RESULTS_DIR}/.changes_added" "${RESULTS_DIR}/.changes_removed"
    DELTA_ADDED=$(wc -l < "${RESULTS_DIR}/.changes_added" | tr -d ' ')
    DELTA_REMOVED=$(wc -l < "${RESULTS_DIR}/.changes_removed" | tr -d ' ')
}

# Persist the current run as a timestamped snapshot for the next diff.
_sc_save_snapshot() {
    [ -n "$PROJECT_DIR" ] || return 0
    local snap
    snap="${PROJECT_DIR}/history/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$snap"
    cp "${RESULTS_DIR}/.findings_current" "${snap}/services.txt" 2>/dev/null || :
    cp "${RESULTS_DIR}/findings.csv" "${snap}/findings.csv" 2>/dev/null || :
    cp "${RESULTS_DIR}/report.html" "${snap}/report.html" 2>/dev/null || :
    echo "  Snapshot saved: ${snap}"
}

# ===== CONSOLIDATED REPORT (HTML + CSV) =====
# HTML-escape stdin for safe embedding (cert SANs etc. are attacker-influenced).
_html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

generate_report() {
    local report="${RESULTS_DIR}/report.html"
    local csv="${RESULTS_DIR}/findings.csv"
    local now
    now=$(date '+%Y-%m-%d %H:%M:%S %Z')

    # ---- findings.csv : service,ip,port ----
    echo "service,ip,port" > "$csv"
    local SERVICE f line
    for SERVICE in $SERVICE_LIST; do
        f="${RESULTS_DIR}/all_interesting_servers/all_${SERVICE}_servers.txt"
        [ -s "$f" ] || continue
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            printf '%s,%s,%s\n' "$SERVICE" "${line%%:*}" "${line##*:}" >> "$csv"
        done < "$f"
    done

    # ---- report.html ----
    {
        cat <<HTMLHEAD
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanCannon Report</title>
<style>
:root{color-scheme:light dark}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:0 1rem 4rem;background:#0f1115;color:#e6e6e6}
@media(prefers-color-scheme:light){body{background:#f7f7f9;color:#1a1a1a}}
h1{font-size:1.6rem;margin:1.2rem 0 .2rem}h2{font-size:1.15rem;margin:2rem 0 .6rem;border-bottom:1px solid #8883;padding-bottom:.3rem}
.sub{opacity:.7;font-size:.85rem}
.cards{display:flex;flex-wrap:wrap;gap:.75rem;margin:1rem 0}
.card{flex:1 1 130px;background:#1c1f27;border:1px solid #ffffff14;border-radius:10px;padding:.8rem 1rem}
@media(prefers-color-scheme:light){.card{background:#fff;border-color:#0001}}
.card .n{font-size:1.5rem;font-weight:700}.card .l{opacity:.7;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.9rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #8883;vertical-align:top}
th{opacity:.75;font-weight:600}
.wrap{overflow-x:auto}
code{background:#8882;padding:.05rem .3rem;border-radius:4px}
.empty{opacity:.6;font-style:italic}
details{margin:.4rem 0}summary{cursor:pointer}
</style></head><body>
<h1>ScanCannon Report</h1>
<div class="sub">Generated $now</div>
<div class="cards">
<div class="card"><div class="n">$TOTAL_IPS</div><div class="l">IPs in scope</div></div>
<div class="card"><div class="n">$RESPONSIVE_IPS</div><div class="l">Responsive IPs</div></div>
<div class="card"><div class="n">$DISCOVERED_SERVICES</div><div class="l">Service hits</div></div>
<div class="card"><div class="n">$DISCOVERED_API_ENDPOINTS</div><div class="l">API endpoints</div></div>
<div class="card"><div class="n">$DISCOVERED_CERT_HOSTS</div><div class="l">Cert SAN hosts</div></div>
<div class="card"><div class="n">$DISCOVERED_CVE_HINTS</div><div class="l">CVE hints</div></div>
<div class="card"><div class="n">+$DELTA_ADDED / -$DELTA_REMOVED</div><div class="l">Change vs last scan</div></div>
</div>
HTMLHEAD

        # Changes since last scan (scan-diff)
        echo '<h2>Changes Since Last Scan</h2>'
        if [ -z "$DELTA_BASELINE" ]; then
            echo '<p class="empty">No previous scan for this project — this run is the baseline.</p>'
        else
            echo "<p><strong>${DELTA_ADDED}</strong> new finding(s), <strong>${DELTA_REMOVED}</strong> gone since the last scan.</p>"
            if [ -s "${RESULTS_DIR}/.changes_added" ]; then
                echo '<h3>New</h3><div class="wrap"><table><tr><th>service &nbsp; host:port</th></tr>'
                _html_escape < "${RESULTS_DIR}/.changes_added" | awk '{print "<tr><td><code>"$0"</code></td></tr>"}'
                echo '</table></div>'
            fi
            if [ -s "${RESULTS_DIR}/.changes_removed" ]; then
                echo '<h3>Gone</h3><div class="wrap"><table><tr><th>service &nbsp; host:port</th></tr>'
                _html_escape < "${RESULTS_DIR}/.changes_removed" | awk '{print "<tr><td><code>"$0"</code></td></tr>"}'
                echo '</table></div>'
            fi
        fi

        # Per-CIDR table
        echo '<h2>Scanned Ranges</h2><div class="wrap"><table>'
        echo '<tr><th>CIDR</th><th>Status</th><th>Responsive</th><th>Services</th><th>API</th><th>Cert SANs</th><th>CVEs</th></tr>'
        local d cidr status resp svc api certs cves
        for d in ${RESULTS_DIR}/*/; do
            base=$(basename "$d")
            case "$base" in all_interesting_servers|*interesting*) continue ;; esac
            [ -f "${d}.stats" ] || continue
            cidr=""; status=""; resp=0; svc=0; api=0; certs=0; cves=0
            while IFS='=' read -r k v; do
                case "$k" in
                    cidr) cidr="$v" ;; status) status="$v" ;;
                    responsive_ips) resp="$v" ;; services) svc="$v" ;;
                    api_endpoints) api="$v" ;; cert_hosts) certs="$v" ;; cve_hints) cves="$v" ;;
                esac
            done < "${d}.stats"
            printf '<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                "$(printf '%s' "$cidr" | _html_escape)" "$status" "$resp" "$svc" "$api" "$certs" "$cves"
        done
        echo '</table></div>'

        # Services summary
        echo '<h2>Interesting Services</h2><div class="wrap"><table><tr><th>Service</th><th>Hosts:Ports</th></tr>'
        for SERVICE in $SERVICE_LIST; do
            f="${RESULTS_DIR}/all_interesting_servers/all_${SERVICE}_servers.txt"
            local c=0; [ -s "$f" ] && c=$(wc -l < "$f")
            [ "$c" -gt 0 ] && printf '<tr><td>%s</td><td>%s</td></tr>\n' "$SERVICE" "$c"
        done
        echo '</table></div>'

        # API endpoints
        echo '<h2>API Endpoints</h2>'
        if [ -s "${RESULTS_DIR}/all_interesting_servers/all_api_servers.txt" ]; then
            echo '<div class="wrap"><table><tr><th>Endpoint</th></tr>'
            _html_escape < "${RESULTS_DIR}/all_interesting_servers/all_api_servers.txt" | awk '{print "<tr><td><code>"$0"</code></td></tr>"}'
            echo '</table></div>'
        else
            echo '<p class="empty">None discovered (or -a not used).</p>'
        fi

        # Resolved domains
        echo '<h2>Resolved Domains</h2>'
        if [ "$(wc -l < ${RESULTS_DIR}/all_root_domains.csv 2>/dev/null || echo 0)" -gt 1 ]; then
            echo '<div class="wrap"><table><tr><th>Root Domain</th><th>IP</th><th>CIDR</th><th>AS#</th><th>Owner</th></tr>'
            tail -n +2 ${RESULTS_DIR}/all_root_domains.csv | sort -u | _html_escape | awk -F, '{printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",$1,$2,$3,$4,$5}'
            echo '</table></div>'
        else
            echo '<p class="empty">None resolved.</p>'
        fi

        # Cert SANs
        echo '<h2>TLS Certificate SAN Hosts</h2>'
        if [ -s "${RESULTS_DIR}/all_cert_sans.txt" ]; then
            echo '<details><summary>'"$(wc -l < ${RESULTS_DIR}/all_cert_sans.txt | tr -d ' ')"' hostname(s)</summary><div class="wrap"><table>'
            _html_escape < "${RESULTS_DIR}/all_cert_sans.txt" | awk '{print "<tr><td><code>"$0"</code></td></tr>"}'
            echo '</table></div></details>'
        else
            echo '<p class="empty">None harvested.</p>'
        fi

        # Dead networks
        echo '<h2>Unresponsive Ranges</h2>'
        if [ -s "${RESULTS_DIR}/dead_networks.txt" ]; then
            echo '<div class="wrap"><table>'
            _html_escape < "${RESULTS_DIR}/dead_networks.txt" | awk '{print "<tr><td><code>"$0"</code></td></tr>"}'
            echo '</table></div>'
        else
            echo '<p class="empty">None.</p>'
        fi

        echo '</body></html>'
    } > "$report"

    echo "Report written: $report"
    echo "Findings CSV : $csv"
    return 0
}

_sc_run_scan() {
# ===== ORCHESTRATE SCANNING ACROSS ALL CIDR RANGES =====
NMAP_MAX_PARALLEL="${NMAP_MAX_PARALLEL:-4}"
DNS_MAX_PARALLEL="${DNS_MAX_PARALLEL:-8}"
CIDR_MAX_PARALLEL="${CIDR_MAX_PARALLEL:-1}"
[ "$CIDR_MAX_PARALLEL" -lt 1 ] && CIDR_MAX_PARALLEL=1

# Read masscan's configured rate and split it across concurrent CIDR workers so
# total packet rate never exceeds the configured budget.
MASSCAN_RATE=$(awk -F= '/^[[:space:]]*rate[[:space:]]*=/{gsub(/[^0-9.]/,"",$2); print int($2); exit}' scancannon.conf)
[ -z "$MASSCAN_RATE" ] && MASSCAN_RATE=5000
MASSCAN_RATE_SHARE=$(( MASSCAN_RATE / CIDR_MAX_PARALLEL ))
[ "$MASSCAN_RATE_SHARE" -lt 100 ] && MASSCAN_RATE_SHARE=100

cidr_total=${#CIDR_RANGES[@]}
if [ "$CIDR_MAX_PARALLEL" -le 1 ]; then
    idx=0
    for CIDR in "${CIDR_RANGES[@]}"; do
        track_phase_progress "Scanning CIDR $((idx + 1))/$cidr_total" "$CIDR"
        scan_cidr "$CIDR" "$idx"
        idx=$((idx + 1))
    done
else
    echo ""
    echo "Scanning up to $CIDR_MAX_PARALLEL CIDR(s) concurrently (masscan rate/worker: ${MASSCAN_RATE_SHARE} pps; total budget ${MASSCAN_RATE} pps)."
    track_phase_progress "Scanning $cidr_total CIDR(s), $CIDR_MAX_PARALLEL at a time"
    cidr_active=0; idx=0
    for CIDR in "${CIDR_RANGES[@]}"; do
        scan_cidr "$CIDR" "$idx" &
        idx=$((idx + 1)); cidr_active=$((cidr_active + 1))
        if [ "$cidr_active" -ge "$CIDR_MAX_PARALLEL" ]; then
            wait -n 2>/dev/null || wait
            cidr_active=$((cidr_active - 1))
        fi
    done
    wait
    echo "All CIDR workers finished."
fi

track_phase_progress "Finalizing results"

#Restore packet filter backup
echo -e "\nAll scans completed. Reverting packet filter configuration. . . "
if [ "$MACOS" != 1 ]; then
iptables -D INPUT -p tcp --dport 40000:41023 -j DROP
else
mv /etc/pf.bak /etc/pf.conf
pfctl -q -f /etc/pf.conf
fi

#Report unresponsive networks (read the exact CIDR from each range's .stats).
echo "Identifying unresponsive networks..."
: > "${RESULTS_DIR}/dead_networks.txt"
for d in ${RESULTS_DIR}/*/; do
    base=$(basename "$d")
    case "$base" in all_interesting_servers|*interesting*) continue ;; esac
    [ -f "${d}.stats" ] || continue
    if grep -q '^status=dead$' "${d}.stats"; then
        grep '^cidr=' "${d}.stats" | sed 's/^cidr=//' >> "${RESULTS_DIR}/dead_networks.txt"
    fi
done
true  # keep exit status clean for 'set -e' (loop may end on a false grep -q)

# Roll per-CIDR outputs up into global files + summary totals.
track_phase_progress "Aggregating results"
aggregate_results

# Diff this run against the project's previous scan (if any).
track_phase_progress "Diffing against previous scan"
_sc_compute_changes

# Build the consolidated HTML + CSV report.
track_phase_progress "Generating report"
generate_report

# Save this run as the baseline for the next scan-diff.
_sc_save_snapshot

# Final progress update
printf "\r%s [%s] %3d%% %s\n" "✓" "████████████████████████████████████████" "100" "Scan completed successfully!"

#Print summary
echo -e "\nScan Summary:"
[ -n "$PROJECT_SLUG" ] && echo "Project: $PROJECT_SLUG"
echo "Total IPs Scanned: $TOTAL_IPS"
echo "Responsive IPs: $RESPONSIVE_IPS"
echo "Discovered Services: $DISCOVERED_SERVICES"
echo "TLS Cert SAN Hosts: $DISCOVERED_CERT_HOSTS"
if [ -n "$DELTA_BASELINE" ]; then
    echo "Changes since last scan: +$DELTA_ADDED new, -$DELTA_REMOVED gone"
else
    echo "Changes since last scan: (baseline — no previous scan)"
fi
if [ "$API_SCAN" -eq 1 ]; then
    echo "API Endpoints Discovered: $DISCOVERED_API_ENDPOINTS"
fi
if [ "$CVE_SCAN" -eq 1 ]; then
    echo "CVE Hints (vulners): $DISCOVERED_CVE_HINTS"
fi
echo ""
echo "Report: ${RESULTS_DIR}/report.html   CSV: ${RESULTS_DIR}/findings.csv"
echo ""
echo "Features used:"
echo "  UDP Scanning: $([ "$UDP_SCAN" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
echo "  API Detection: $([ "$API_SCAN" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
echo "  CVE Hinting: $([ "$CVE_SCAN" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
echo "  CIDR Concurrency: $CIDR_MAX_PARALLEL"

# Notify (if -n was given) with a one-line summary.
send_notification "completed" "Responsive IPs: ${RESPONSIVE_IPS}, services: ${DISCOVERED_SERVICES}, API: ${DISCOVERED_API_ENDPOINTS}, cert hosts: ${DISCOVERED_CERT_HOSTS}."

echo -e "\n【 Powering down ScanCannon. Please check for any personal belongings before exiting the shell 】"

# Call cleanup function at the end of script
cleanup
}  # end _sc_run_scan

# ===== ENTRY POINT =====
# Orchestrates the whole run. Kept as a single main() so the imperative flow is
# in one place; each step is a named function defined above.
main() {
    _sc_start                        # logging + banner
    _sc_check_for_updates            # optional self-update prompt
    _sc_check_dependencies           # required tools + config file
    _sc_parse_args_and_setup "$@"    # adapter config, getopts, targets, filters
    trap ctrl_c INT                  # clean up on interrupt once scanning starts
    _sc_run_scan                     # masscan/nmap orchestration, aggregate, report
}

# Run only when executed directly; sourcing (e.g. the test suite) just loads
# the functions and globals above.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
