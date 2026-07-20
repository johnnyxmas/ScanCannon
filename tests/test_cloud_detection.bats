#!/usr/bin/env bats
# is_cloud_provider(): recognize shared cloud/VPS org names.

setup() {
    load helpers
    common_setup
}

@test "is_cloud_provider matches Amazon" {
    run is_cloud_provider "Amazon Technologies Inc."
    [ "$status" -eq 0 ]
}

@test "is_cloud_provider matches DigitalOcean" {
    run is_cloud_provider "DigitalOcean, LLC"
    [ "$status" -eq 0 ]
}

@test "is_cloud_provider is case-insensitive" {
    run is_cloud_provider "GOOGLE LLC"
    [ "$status" -eq 0 ]
}

@test "is_cloud_provider rejects a normal org" {
    run is_cloud_provider "Acme Widgets Incorporated"
    [ "$status" -ne 0 ]
}

@test "is_cloud_provider rejects an empty string" {
    run is_cloud_provider ""
    [ "$status" -ne 0 ]
}
