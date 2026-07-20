# tests/helpers.bash — shared setup for ScanCannon bats tests.
#
# scancannon.sh guards every imperative block behind an SC_EXECUTED flag
# (`[ "${BASH_SOURCE[0]}" = "${0}" ]`), so sourcing it defines the functions and
# globals with no side effects: no banner, no update check, no scan, no INT
# trap. We source it directly, then reset shell options — the script runs
# `set -euo pipefail` for direct execution, which we don't want leaking into the
# test shell (functions like is_cloud_provider intentionally return non-zero).

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
SCANCANNON_SH="${REPO_ROOT}/scancannon.sh"

load_scancannon() {
    # shellcheck disable=SC1090
    source "$SCANCANNON_SH"
    set +e +u +o pipefail
}

# Defaults for globals the functions expect to be set by the (untested) main flow.
# These are read by the sourced scancannon.sh functions, not within this file.
# shellcheck disable=SC2034
scan_env_defaults() {
    MACOS=$([ "$(uname)" = "Darwin" ] && echo 1 || echo 0)
    API_SCAN=0
    CVE_SCAN=0
    UDP_SCAN=0
    NOTIFY_TARGET=""
    NMAP_MAX_PARALLEL=2
    DNS_MAX_PARALLEL=2
    MASSCAN_RATE=5000
    MASSCAN_RATE_SHARE=5000
    DISCOVERED_API_ENDPOINTS=0
    # Tests operate on ./results within the per-test tmpdir (no project menu).
    RESULTS_DIR="./results"
    PROJECTS_ROOT="./projects"
    WHOIS_CACHE_DIR="${BATS_TEST_TMPDIR}/wcache"
    WHOIS_CACHE_TTL=86400
    WHOIS_MAX_RETRIES=1
}

# Put the stub tools on PATH (copied so tests can overwrite them if needed).
use_stubs() {
    cp -R "${REPO_ROOT}/tests/stubs" "${BATS_TEST_TMPDIR}/bin"
    chmod +x "${BATS_TEST_TMPDIR}/bin/"*
    PATH="${BATS_TEST_TMPDIR}/bin:${PATH}"
}

# Standard setup: isolated workdir, functions loaded, sane defaults.
common_setup() {
    cd "$BATS_TEST_TMPDIR" || return 1
    mkdir -p results
    load_scancannon
    scan_env_defaults
}
