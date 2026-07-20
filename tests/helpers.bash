# tests/helpers.bash — shared setup for ScanCannon bats tests.
#
# WHY WE EXTRACT INSTEAD OF `source scancannon.sh`:
#   scancannon.sh interleaves top-level imperative code (tool checks,
#   configure_adapter, getopts, the scan orchestrator, the INT trap) with its
#   function definitions, so sourcing it would execute the whole program.
#   Until the script guards its main flow behind `main()` + a BASH_SOURCE check,
#   we lift the pure/testable functions into a temp lib and source THAT. The
#   lib is validated with `bash -n` on every run, so if a function's shape
#   drifts, the suite fails loudly instead of silently testing stale code.

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
SCANCANNON_SH="${REPO_ROOT}/scancannon.sh"

# Emit one function's definition (handles both `function name()` and `name()`).
_extract_fn() {
    awk -v fn="$1" '
        !inx && $0 ~ ("^(function )?" fn "\\(\\) \\{") { inx = 1 }
        inx { print }
        inx && /^\}/ { exit }
    ' "$SCANCANNON_SH"
}

# Assemble the testable subset of scancannon.sh into $BATS_TEST_TMPDIR/scanlib.sh
# and source it.
load_scanlib() {
    local lib="${BATS_TEST_TMPDIR}/scanlib.sh"
    {
        echo '#!/usr/bin/env bash'
        # Globals the functions read.
        grep -E '^SERVICE_LIST=' "$SCANCANNON_SH"
        grep -E '^WHOIS_CACHE_DIR=|^WHOIS_CACHE_TTL=|^WHOIS_MAX_RETRIES=' "$SCANCANNON_SH"
        sed -n '/^CLOUD_PROVIDER_PATTERNS=(/,/^)/p' "$SCANCANNON_SH"
        # One-liner function.
        grep -E '^_html_escape\(\)' "$SCANCANNON_SH"
        # Multi-line functions.
        local fn
        for fn in validate_cidr extract_domain inetnum_to_cidr cidr_first_ip \
                  extract_cidrs_from_whois extract_asn_from_whois extract_org_from_whois \
                  extract_all_org_fields is_cloud_provider cached_whois \
                  detect_api_endpoints scan_cidr aggregate_results generate_report; do
            _extract_fn "$fn"
            echo
        done
    } > "$lib"

    if ! bash -n "$lib" 2>/dev/null; then
        echo "extracted scanlib.sh failed 'bash -n' — function shape may have drifted:" >&2
        bash -n "$lib" >&2 || true
        return 1
    fi
    # shellcheck disable=SC1090
    source "$lib"
}

# Defaults for globals the functions expect to be set by the (untested) main flow.
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
    load_scanlib
    scan_env_defaults
}
