#!/usr/bin/env bats
# read_cidr_file(): parse/validate/normalize a -f CIDR list file.

setup() {
    load helpers
    common_setup
}

@test "read_cidr_file yields CIDRs, skipping blanks and comments" {
    printf '# a comment\n\n203.0.113.0/24\n  10.0.0.0/8  \n' > list.txt
    run read_cidr_file list.txt
    [ "$status" -eq 0 ]
    [ "${lines[0]}" = "203.0.113.0/24" ]
    [ "${lines[1]}" = "10.0.0.0/8" ]
    [ "${#lines[@]}" -eq 2 ]
}

@test "read_cidr_file normalizes a bare IP to /32" {
    printf '198.51.100.7\n' > list.txt
    run read_cidr_file list.txt
    [ "$status" -eq 0 ]
    [ "$output" = "198.51.100.7/32" ]
}

@test "read_cidr_file fails on an invalid entry" {
    printf '203.0.113.0/24\n999.1.1.1/24\n' > list.txt
    run read_cidr_file list.txt
    [ "$status" -ne 0 ]
}

@test "read_cidr_file handles a file with no trailing newline" {
    printf '203.0.113.0/24' > list.txt
    run read_cidr_file list.txt
    [ "$status" -eq 0 ]
    [ "$output" = "203.0.113.0/24" ]
}
