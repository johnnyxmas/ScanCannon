#!/usr/bin/env bats
# public_suffix_domain(): registrable-domain extraction via the Public Suffix List.

setup() {
    load helpers
    common_setup
    PSL_FILE="${REPO_ROOT}/tests/fixtures/psl.dat"
}

@test "public_suffix_domain keeps the SLD for a two-label ccTLD" {
    run public_suffix_domain "mail.example.co.uk"
    [ "$output" = "example.co.uk" ]
}

@test "public_suffix_domain handles deep subdomains under com.au" {
    run public_suffix_domain "a.b.example.com.au"
    [ "$output" = "example.com.au" ]
}

@test "public_suffix_domain reduces a plain .com correctly" {
    run public_suffix_domain "deep.sub.example.com"
    [ "$output" = "example.com" ]
}

@test "public_suffix_domain honors wildcard rules (*.ck)" {
    # *.ck makes 'test.ck' a public suffix, so the registrable domain is b.test.ck
    run public_suffix_domain "a.b.test.ck"
    [ "$output" = "b.test.ck" ]
}

@test "public_suffix_domain honors exception rules (!www.ck)" {
    run public_suffix_domain "www.ck"
    [ "$output" = "www.ck" ]
}

@test "extract_domain uses the PSL when present" {
    run extract_domain "https://mail.example.co.uk/path?q=1"
    [ "$output" = "example.co.uk" ]
}
