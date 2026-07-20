#!/usr/bin/env bats
# extract_domain(): strip URL/scheme/path/subdomains to a base domain.

setup() {
    load helpers
    common_setup
}

@test "extract_domain strips scheme, subdomain and path" {
    run extract_domain "https://sub.example.com/path?q=1"
    [ "$status" -eq 0 ]
    [ "$output" = "example.com" ]
}

@test "extract_domain strips www" {
    run extract_domain "www.example.com"
    [ "$output" = "example.com" ]
}

@test "extract_domain passes through a bare domain" {
    run extract_domain "example.com"
    [ "$output" = "example.com" ]
}

@test "extract_domain collapses deep subdomains" {
    run extract_domain "deep.sub.example.com"
    [ "$output" = "example.com" ]
}

@test "extract_domain strips a port" {
    run extract_domain "http://example.org:8080/x"
    [ "$output" = "example.org" ]
}
