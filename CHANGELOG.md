# Changelog

All notable changes to ScanCannon are documented here. Versions follow the
in-script banner (`scancannon.sh`).

## v1.8

### Added
- **Projects.** Every run belongs to a project; a startup menu selects or creates
  one (`-p <name>` skips it for automation). Results are isolated under
  `./projects/<name>/results/`.
- **Scan-diff.** Each run is snapshotted to `./projects/<name>/history/`, and the
  report gains a **Changes Since Last Scan** section (new / disappeared
  `service host:port` findings vs. the project's previous scan).
- Test suite grew to cover the API prober (`detect_api_endpoints`), the `-f`
  CIDR-file loader (`read_cidr_file`), registry-agnostic domain resolution, and
  the scan-diff core; CI now shellchecks the test harness and stubs too.

### Fixed
- `extract_domain` no longer collapses two-label ccTLDs (`mail.example.co.uk`
  now yields `example.co.uk`, not `co.uk`) and lowercases its output.
- Domain resolution is registry-agnostic: it reuses the `extract_*_from_whois`
  helpers, so RIPE/APNIC/AFRINIC space resolves instead of showing `N/A`.

### Changed
- All result paths funnel through a single `RESULTS_DIR`, repointed per project.

## v1.7

### Changed
- `scancannon.sh` is now safe to `source`: the imperative flow lives in `main()`,
  invoked only under a `BASH_SOURCE` guard. The test suite loads the real
  functions directly instead of extracting them.

## v1.6

### Added
- Scan resume/checkpointing (per-CIDR `.scan_complete`, `paused.conf` preserved
  on interrupt).
- TLS certificate SAN harvesting, fed back into domain discovery.
- Consolidated HTML + CSV report (`report.html`, `findings.csv`).
- Bounded parallel CIDR scanning (`CIDR_MAX_PARALLEL`, rate-split).
- Completion notifications (`-n desktop|<webhook>`), CVE hinting (`-V`, nmap
  vulners), whois caching with retry/backoff.
- shellcheck CI and a bats functional test suite.

### Fixed
- Service classification matched no real nmap gnmap output; now keys on the
  correct service field.
- `aggregate_results` returned non-zero under `set -e`, aborting the run.
