#!/usr/bin/env bats
# aggregate_results(): roll per-CIDR .stats + files into global totals/files.

setup() {
    load helpers
    common_setup
    _make_tree
}

# Build a synthetic results/ tree: two scanned CIDRs + one dead.
_make_tree() {
    mkdir -p results/203.0.113.0_24/interesting_servers \
             results/198.51.100.0_24/interesting_servers \
             results/192.0.2.0_30

    printf 'cidr=203.0.113.0/24\ntotal_ips=256\nresponsive_ips=2\nservices=3\napi_endpoints=1\ncert_hosts=2\ncve_hints=4\nstatus=scanned\n' \
        > results/203.0.113.0_24/.stats
    printf '203.0.113.5:22\n' > results/203.0.113.0_24/interesting_servers/ssh_servers.txt
    printf '203.0.113.5:80\n203.0.113.6:443\n' > results/203.0.113.0_24/interesting_servers/http_servers.txt
    printf '203.0.113.6:443/api\n' > results/203.0.113.0_24/interesting_servers/api_servers.txt
    printf 'api.example.com\nwww.example.com\n' > results/203.0.113.0_24/cert_sans.txt
    printf 'Root Domain,IP,CIDR,AS#,IP Owner\nexample.com,203.0.113.5,203.0.113.0/24,AS64500,Example Inc\n' \
        > results/203.0.113.0_24/resolved_root_domains.csv

    printf 'cidr=198.51.100.0/24\ntotal_ips=256\nresponsive_ips=1\nservices=1\napi_endpoints=0\ncert_hosts=1\ncve_hints=0\nstatus=scanned\n' \
        > results/198.51.100.0_24/.stats
    printf '198.51.100.9:22\n' > results/198.51.100.0_24/interesting_servers/ssh_servers.txt
    printf 'api.example.com\n' > results/198.51.100.0_24/cert_sans.txt

    printf 'cidr=192.0.2.0/30\ntotal_ips=4\nresponsive_ips=0\nservices=0\napi_endpoints=0\ncert_hosts=0\ncve_hints=0\nstatus=dead\n' \
        > results/192.0.2.0_30/.stats
}

@test "aggregate_results sums stats across all CIDRs" {
    aggregate_results
    [ "$TOTAL_IPS" -eq 516 ]           # 256 + 256 + 4
    [ "$RESPONSIVE_IPS" -eq 3 ]        # 2 + 1 + 0
    [ "$DISCOVERED_SERVICES" -eq 4 ]   # 3 + 1
    [ "$DISCOVERED_API_ENDPOINTS" -eq 1 ]
    [ "$DISCOVERED_CERT_HOSTS" -eq 3 ]
    [ "$DISCOVERED_CVE_HINTS" -eq 4 ]
}

@test "aggregate_results merges + dedupes global files" {
    aggregate_results
    # ssh from both CIDRs
    grep -q '203.0.113.5:22' results/all_interesting_servers/all_ssh_servers.txt
    grep -q '198.51.100.9:22' results/all_interesting_servers/all_ssh_servers.txt
    # api.example.com appears in both cert_sans but should be deduped to one line
    [ "$(grep -c '^api.example.com$' results/all_cert_sans.txt)" -eq 1 ]
    # root-domains CSV keeps a single header
    [ "$(grep -c '^Root Domain,' results/all_root_domains.csv)" -eq 1 ]
}

@test "aggregate_results returns 0 under set -e (regression: empty-file loop)" {
    # The dedup loop used to leave a non-zero status when the last global file
    # was empty, aborting the caller under 'set -e'. Guard that here.
    run bash -euo pipefail -c "source '${SCANCANNON_SH}'; cd '${BATS_TEST_TMPDIR}'; aggregate_results; echo DONE_OK"
    [ "$status" -eq 0 ]
    [[ "$output" == *"DONE_OK"* ]]
}
