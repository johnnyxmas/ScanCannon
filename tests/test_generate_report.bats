#!/usr/bin/env bats
# generate_report(): HTML report + findings.csv, with output escaping.

setup() {
    load helpers
    common_setup
    _make_aggregated
    # Summary counters the report renders.
    TOTAL_IPS=512; RESPONSIVE_IPS=2; DISCOVERED_SERVICES=3
    DISCOVERED_API_ENDPOINTS=1; DISCOVERED_CERT_HOSTS=2; DISCOVERED_CVE_HINTS=1
}

_make_aggregated() {
    mkdir -p results/all_interesting_servers
    printf '203.0.113.5:22\n' > results/all_interesting_servers/all_ssh_servers.txt
    printf '203.0.113.6:443\n' > results/all_interesting_servers/all_https_servers.txt
    printf '203.0.113.6:443/api\n' > results/all_interesting_servers/all_api_servers.txt
    # A hostile SAN to prove HTML escaping.
    printf 'good.example.com\nevil<script>alert(1)</script>.example.org\n' > results/all_cert_sans.txt
    printf 'Root Domain,IP,CIDR,AS#,IP Owner\nexample.com,203.0.113.5,203.0.113.0/24,AS64500,Example Inc\n' \
        > results/all_root_domains.csv
    printf '192.0.2.0/30\n' > results/dead_networks.txt
}

@test "generate_report writes report.html and findings.csv" {
    generate_report
    [ -s results/report.html ]
    [ -s results/findings.csv ]
}

@test "generate_report escapes hostile content (no raw <script>)" {
    generate_report
    [ "$(grep -c '<script>' results/report.html)" -eq 0 ]
    grep -q 'evil&lt;script&gt;' results/report.html
}

@test "generate_report renders the summary counters" {
    generate_report
    grep -q '512' results/report.html         # IPs in scope
    grep -q 'Responsive IPs' results/report.html
}

@test "findings.csv contains service,ip,port rows" {
    generate_report
    head -1 results/findings.csv | grep -q '^service,ip,port$'
    grep -q '^ssh,203.0.113.5,22$' results/findings.csv
    grep -q '^https,203.0.113.6,443$' results/findings.csv
}
