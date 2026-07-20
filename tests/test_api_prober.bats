#!/usr/bin/env bats
# detect_api_endpoints(): Tier-2 curl probing of HTTP/HTTPS hosts.

setup() {
    load helpers
    common_setup
    use_stubs
    API_SCAN=1
    mkdir -p results/net/interesting_servers
    printf '203.0.113.5:80\n' > results/net/interesting_servers/http_servers.txt
}

@test "detect_api_endpoints records a JSON endpoint" {
    export CURL_STATUS=200 CURL_CTYPE="application/json"
    detect_api_endpoints net
    [ -s results/net/interesting_servers/api_servers.txt ]
    grep -q '203.0.113.5:80' results/net/interesting_servers/api_servers.txt
}

@test "detect_api_endpoints finds nothing when hosts are unreachable" {
    export CURL_STATUS=000
    detect_api_endpoints net
    [ ! -s results/net/interesting_servers/api_servers.txt ]
}

@test "detect_api_endpoints handles a host list with no web ports" {
    : > results/net/interesting_servers/http_servers.txt   # empty
    export CURL_STATUS=200 CURL_CTYPE="application/json"
    run detect_api_endpoints net
    [ "$status" -eq 0 ]
    [ ! -s results/net/interesting_servers/api_servers.txt ]
}
