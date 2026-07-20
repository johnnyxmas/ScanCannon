#!/usr/bin/env bats
# extract_*_from_whois(): pull CIDRs, ASNs and org from whois text.

setup() {
    load helpers
    common_setup
}

@test "extract_cidrs_from_whois reads an ARIN CIDR line" {
    out="$(extract_cidrs_from_whois "$(printf 'NetName: EXAMPLE\nCIDR: 203.0.113.0/24\n')")"
    [ "$out" = "203.0.113.0/24" ]
}

@test "extract_cidrs_from_whois converts a RIPE inetnum range" {
    out="$(extract_cidrs_from_whois "$(printf 'inetnum: 203.0.113.0 - 203.0.113.255\n')")"
    [ "$out" = "203.0.113.0/24" ]
}

@test "extract_asn_from_whois reads OriginAS" {
    out="$(extract_asn_from_whois "$(printf 'OriginAS: AS64500\n')")"
    [ "$out" = "AS64500" ]
}

@test "extract_org_from_whois prefers OrgName" {
    out="$(extract_org_from_whois "$(printf 'OrgName: Example Inc\nnetname: EX\n')")"
    [ "$out" = "Example Inc" ]
}

@test "extract_org_from_whois falls back to netname" {
    out="$(extract_org_from_whois "$(printf 'netname: EXAMPLE-NET\n')")"
    [ "$out" = "EXAMPLE-NET" ]
}
