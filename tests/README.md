# ScanCannon test suite

Functional tests for `scancannon.sh`, written with [bats-core](https://github.com/bats-core/bats-core).
They stub the external tools (`masscan`, `nmap`, `dig`, `whois`, `curl`) so the
script's parsing, classification, aggregation, and reporting logic can be
exercised without root, real scanning, or network access. CI runs them on every
push/PR (`.github/workflows/lint.yml`, job `bats`).

## Running locally

```bash
# install bats-core (once)
git clone --depth 1 --branch v1.11.1 https://github.com/bats-core/bats-core.git ~/bats-core

# run the whole suite
~/bats-core/bin/bats tests/

# run one file
~/bats-core/bin/bats tests/test_scan_cidr.bats
```

## Layout

| Path | Purpose |
|------|---------|
| `helpers.bash`  | Shared setup: loads the functions, sets defaults, installs stubs |
| `stubs/`        | Fake `masscan`/`nmap`/`dig`/`whois`/`curl`, driven by env vars |
| `fixtures/`     | Realistic `nmap` output samples (gnmap + ssl-cert/vulners) |
| `test_*.bats`   | One file per unit / area |

## How functions are loaded

`scancannon.sh` gates every imperative block behind an `SC_EXECUTED` flag set
from `[ "${BASH_SOURCE[0]}" = "${0}" ]`. When the file is **sourced** (as the
tests do) that flag is `0`, so nothing runs — no banner, no update check, no
scan, no `INT` trap — and only the function definitions and globals load.
`helpers.bash` sources the real script directly, then resets shell options (the
script sets `set -euo pipefail` for direct execution, which we don't want
leaking into the test shell). Tests therefore exercise the exact production
functions, not a copy.

## What's covered

- **Parsers:** `validate_cidr`, `extract_domain`, `inetnum_to_cidr`,
  `cidr_first_ip`, the `extract_*_from_whois` family, `is_cloud_provider`.
- **whois cache:** `cached_whois` cache hits, key separation, stale fallback.
- **Per-CIDR pipeline (`scan_cidr`):** masscan consolidation, service
  classification, TLS-cert SAN harvesting, CVE counting, resume-skip, dead-range
  handling.
- **Aggregation & reporting:** stat summing, global-file dedupe, HTML escaping,
  `findings.csv`.

### Regression guards (bugs fixed, now locked in)

- **Service classification** matches real `nmap` gnmap output — the old regex
  silently matched nothing (`test_scan_cidr.bats`).
- **`aggregate_results` returns 0 under `set -e`** — an empty-file loop used to
  abort the run (`test_aggregate_results.bats`).
- **`generate_report` escapes hostile SAN content** — no raw `<script>` reaches
  the HTML (`test_generate_report.bats`).

## Adding a test

Stub behavior is env-driven: e.g. `MASSCAN_OPEN="ip:port ip:port"` makes the
masscan stub report open ports; `NMAP_FIXTURES=<dir>` serves per-IP nmap output;
`WHOIS_EMPTY=1` simulates a rate-limited whois. See `helpers.bash` and `stubs/`.
