#!/usr/bin/env bats
# cached_whois(): on-disk cache + retry/backoff + stale fallback.

setup() {
    load helpers
    common_setup
    use_stubs
    export WHOIS_CALLLOG="${BATS_TEST_TMPDIR}/whois_calls.log"
    : > "$WHOIS_CALLLOG"
}

@test "cached_whois serves the second identical query from cache" {
    run cached_whois "203.0.113.1"
    [ "$status" -eq 0 ]
    [[ "$output" == *"203.0.113.0/24"* ]]

    run cached_whois "203.0.113.1"
    [ "$status" -eq 0 ]
    [[ "$output" == *"203.0.113.0/24"* ]]

    # whois should have been invoked exactly once for two identical queries.
    [ "$(wc -l < "$WHOIS_CALLLOG" | tr -d ' ')" -eq 1 ]
}

@test "cached_whois keys distinct queries separately" {
    cached_whois "203.0.113.1" >/dev/null
    cached_whois -h whois.radb.net -- "-i origin AS64500" >/dev/null
    [ "$(wc -l < "$WHOIS_CALLLOG" | tr -d ' ')" -eq 2 ]
}

@test "cached_whois falls back to a stale cache entry on empty replies" {
    # Prime the cache.
    cached_whois "198.51.100.9" >/dev/null
    # Now force live queries to return empty; the cached answer should be served.
    export WHOIS_EMPTY=1
    run cached_whois "198.51.100.9"
    [ "$status" -eq 0 ]
    [[ "$output" == *"203.0.113.0/24"* ]]
}
