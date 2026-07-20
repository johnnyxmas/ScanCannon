#!/usr/bin/env bats
# build_findings_snapshot() / compute_findings_delta(): scan-to-scan diff core.

setup() {
    load helpers
    common_setup
}

@test "build_findings_snapshot merges per-service files into 'service ip:port'" {
    mkdir -p results/all_interesting_servers
    printf '10.0.0.1:22\n'  > results/all_interesting_servers/all_ssh_servers.txt
    printf '10.0.0.2:443\n' > results/all_interesting_servers/all_https_servers.txt
    build_findings_snapshot "${BATS_TEST_TMPDIR}/snap"
    grep -q '^ssh 10.0.0.1:22$'    "${BATS_TEST_TMPDIR}/snap"
    grep -q '^https 10.0.0.2:443$' "${BATS_TEST_TMPDIR}/snap"
}

@test "compute_findings_delta reports added and removed lines" {
    printf 'ssh 10.0.0.1:22\nhttp 10.0.0.1:80\n'   > base
    printf 'http 10.0.0.1:80\nhttps 10.0.0.2:443\n' > cur
    compute_findings_delta base cur added removed
    [ "$(cat added)"   = "https 10.0.0.2:443" ]
    [ "$(cat removed)" = "ssh 10.0.0.1:22" ]
}

@test "compute_findings_delta treats everything as added when no baseline" {
    printf 'ssh 10.0.0.1:22\n' > cur
    compute_findings_delta /nonexistent cur added removed
    [ "$(cat added)" = "ssh 10.0.0.1:22" ]
    [ ! -s removed ]
}

@test "compute_findings_delta yields empty delta for identical scans" {
    printf 'ssh 10.0.0.1:22\n' > base
    cp base cur
    compute_findings_delta base cur added removed
    [ ! -s added ]
    [ ! -s removed ]
}
