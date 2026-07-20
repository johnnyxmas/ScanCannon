#!/usr/bin/env bats
# resolve_root_domain(): registry-agnostic domain -> CSV row.

setup() {
    load helpers
    common_setup
    use_stubs
    export DIG_RESULT="203.0.113.5"
    OUT="${BATS_TEST_TMPDIR}/row"
}

@test "resolve_root_domain parses ARIN-style whois" {
    resolve_root_domain "example.com" "$OUT"
    [ "$(cat "$OUT")" = "example.com,203.0.113.5,203.0.113.0/24,AS64500,Example Inc" ]
}

@test "resolve_root_domain parses RIPE-style whois (registry-agnostic)" {
    export WHOIS_OUTPUT=$'inetnum: 203.0.113.0 - 203.0.113.255\nnetname: EXAMPLE-NET\ndescr: Example Org BV\norigin: AS64500'
    resolve_root_domain "example.eu" "$OUT"
    [ "$(cat "$OUT")" = "example.eu,203.0.113.5,203.0.113.0/24,AS64500,Example Org BV" ]
}

@test "resolve_root_domain emits N/A fields when whois is empty" {
    export WHOIS_EMPTY=1
    resolve_root_domain "example.net" "$OUT"
    [ "$(cat "$OUT")" = "example.net,203.0.113.5,N/A,N/A,N/A" ]
}

@test "resolve_root_domain skips a domain that does not resolve" {
    export DIG_RESULT=""
    resolve_root_domain "nxdomain.invalid" "$OUT"
    [ ! -s "$OUT" ]
}

@test "resolve_root_domain sanitizes commas in org names" {
    export WHOIS_OUTPUT=$'CIDR: 203.0.113.0/24\nOrgName: Example, Inc.\nOriginAS: AS64500'
    resolve_root_domain "example.com" "$OUT"
    # comma in org replaced with space so the CSV stays 5 columns
    [ "$(awk -F, '{print NF}' "$OUT")" -eq 5 ]
    grep -q 'Example  Inc.' "$OUT"
}
