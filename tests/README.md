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

`scancannon.sh` interleaves top-level imperative code (tool checks,
`configure_adapter`, `getopts`, the scan orchestrator, the `INT` trap) with its
function definitions, so it **cannot be sourced** without running the whole
program. Until it is refactored to guard its main flow behind
`main()` + a `BASH_SOURCE` check, `helpers.bash` extracts the testable functions
into a temporary lib and sources that. The lib is validated with `bash -n` on
every run, so if a function's shape drifts the suite fails loudly instead of
testing stale code.

> **Follow-up:** wrapping the imperative flow in a `main()` guarded by
> `[ "${BASH_SOURCE[0]}" = "${0}" ]` would let the tests `source scancannon.sh`
> directly and retire the extraction step.

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
