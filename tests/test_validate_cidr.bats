#!/usr/bin/env bats
# validate_cidr(): CIDR/IP notation validation.

setup() {
    load helpers
    common_setup
}

@test "validate_cidr accepts a normal /24" {
    run validate_cidr "203.0.113.0/24" 1 testfile
    [ "$status" -eq 0 ]
}

@test "validate_cidr accepts a bare IP (no mask)" {
    run validate_cidr "203.0.113.5" 1 testfile
    [ "$status" -eq 0 ]
}

@test "validate_cidr accepts /32 and /0 boundaries" {
    run validate_cidr "10.0.0.1/32" 1 testfile
    [ "$status" -eq 0 ]
    run validate_cidr "0.0.0.0/0" 1 testfile
    [ "$status" -eq 0 ]
}

@test "validate_cidr skips blank lines and comments" {
    run validate_cidr "" 1 testfile
    [ "$status" -eq 0 ]
    run validate_cidr "   # a comment" 1 testfile
    [ "$status" -eq 0 ]
}

@test "validate_cidr rejects a mask above /32" {
    run validate_cidr "203.0.113.0/33" 7 testfile
    [ "$status" -ne 0 ]
    [[ "$output" == *"ERROR"* ]]
    [[ "$output" == *"line 7"* ]]
}

@test "validate_cidr rejects an octet above 255" {
    run validate_cidr "256.0.0.1/24" 1 testfile
    [ "$status" -ne 0 ]
}

@test "validate_cidr rejects non-IP garbage" {
    run validate_cidr "not-an-ip" 1 testfile
    [ "$status" -ne 0 ]
}
