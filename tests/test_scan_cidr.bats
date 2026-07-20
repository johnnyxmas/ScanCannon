#!/usr/bin/env bats
# scan_cidr(): full per-CIDR pipeline with stubbed masscan/nmap/dig/whois.

setup() {
    load helpers
    common_setup
    use_stubs
    export NMAP_FIXTURES="${REPO_ROOT}/tests/fixtures/nmap"
    printf 'COM\nORG\nNET\n' > ./all_tlds.txt   # minimal TLD list
}

DIR="results/203.0.113.0_24"

@test "scan_cidr consolidates masscan output into hosts_and_ports" {
    export MASSCAN_OPEN="203.0.113.5:22 203.0.113.5:443"
    run scan_cidr "203.0.113.0/24" 0
    [ "$status" -eq 0 ]
    [ "$(cat "$DIR/hosts_and_ports.txt")" = "203.0.113.5:22,443" ]
}

@test "scan_cidr classifies services correctly (regression: ssh + https)" {
    export MASSCAN_OPEN="203.0.113.5:22 203.0.113.5:443"
    scan_cidr "203.0.113.0/24" 0
    # The old regex never matched real gnmap and left these empty.
    grep -q '203.0.113.5:22' "$DIR/interesting_servers/ssh_servers.txt"
    grep -q '203.0.113.5:443' "$DIR/interesting_servers/https_servers.txt"
    grep -q '203.0.113.5:443' "$DIR/interesting_servers/ssl_servers.txt"
}

@test "scan_cidr harvests TLS-cert SANs (wildcard stripped, lowercased)" {
    export MASSCAN_OPEN="203.0.113.5:443"
    scan_cidr "203.0.113.0/24" 0
    grep -q '^example.com$'     "$DIR/cert_sans.txt"
    grep -q '^api.example.com$' "$DIR/cert_sans.txt"
    grep -q '^cdn.example.com$' "$DIR/cert_sans.txt"   # from *.cdn.example.com
    grep -q '^mail.example.com$' "$DIR/cert_sans.txt"  # from mail.EXAMPLE.com
    [ "$(wc -l < "$DIR/cert_sans.txt" | tr -d ' ')" -eq 4 ]
}

@test "scan_cidr folds cert SANs into resolved subdomains" {
    export MASSCAN_OPEN="203.0.113.5:443"
    scan_cidr "203.0.113.0/24" 0
    grep -q '^host5.example.com$' "$DIR/resolved_subdomains.txt"  # from PTR
    grep -q '^api.example.com$'   "$DIR/resolved_subdomains.txt"  # from cert SAN
}

@test "scan_cidr counts CVE hints only with -V" {
    export MASSCAN_OPEN="203.0.113.5:22"
    CVE_SCAN=1
    scan_cidr "203.0.113.0/24" 0
    grep -q '^cve_hints=2$' "$DIR/.stats"   # two unique CVE IDs in the fixture
}

@test "scan_cidr writes stats and a completion marker" {
    export MASSCAN_OPEN="203.0.113.5:22 203.0.113.5:443"
    scan_cidr "203.0.113.0/24" 0
    grep -q '^status=scanned$' "$DIR/.stats"
    grep -q '^cidr=203.0.113.0/24$' "$DIR/.stats"
    grep -q '^cert_hosts=4$' "$DIR/.stats"
    [ -f "$DIR/.scan_complete" ]
}

@test "scan_cidr skips a CIDR that is already complete (resume)" {
    mkdir -p "$DIR"
    touch "$DIR/.scan_complete"
    export MASSCAN_OPEN="203.0.113.5:22"
    run scan_cidr "203.0.113.0/24" 0
    [ "$status" -eq 0 ]
    [[ "$output" == *"resume"* ]]
    # masscan must not have run.
    [ ! -f "$DIR/masscan_output.txt" ]
}

@test "scan_cidr marks an unresponsive range as dead" {
    unset MASSCAN_OPEN   # no open ports
    run scan_cidr "192.0.2.0/30" 0
    [ "$status" -eq 0 ]
    grep -q '^status=dead$' results/192.0.2.0_30/.stats
    grep -q '^total_ips=4$' results/192.0.2.0_30/.stats
    [ ! -f results/192.0.2.0_30/hosts_and_ports.txt ]
}
