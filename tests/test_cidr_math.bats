#!/usr/bin/env bats
# inetnum_to_cidr() / cidr_first_ip(): range<->CIDR helpers.

setup() {
    load helpers
    common_setup
}

@test "inetnum_to_cidr converts a full /24 range" {
    run inetnum_to_cidr "203.0.113.0" "203.0.113.255"
    [ "$output" = "203.0.113.0/24" ]
}

@test "inetnum_to_cidr converts a single address to /32" {
    run inetnum_to_cidr "10.0.0.7" "10.0.0.7"
    [ "$output" = "10.0.0.7/32" ]
}

@test "inetnum_to_cidr converts a /23-sized range" {
    run inetnum_to_cidr "10.0.0.0" "10.0.1.255"
    [ "$output" = "10.0.0.0/23" ]
}

@test "cidr_first_ip returns the network address" {
    run cidr_first_ip "203.0.113.0/24"
    [ "$output" = "203.0.113.0" ]
}
