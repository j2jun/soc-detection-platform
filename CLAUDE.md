# CLAUDE.md

Mini SOC home lab: Sigma rules tested against recorded ATT&CK attacks, later a live Wazuh lab. README.md holds the research, decisions, and results; keep it current when decisions or results change.

## Constraints

- **Zero cost.** Free tiers only: GitHub Actions/Codespaces now, Azure for Students (no card) in phase 2.
- **Zero laptop disk.** Never download Chainsaw, SigmaHQ, or attack datasets locally. Everything heavy runs in CI.
- Public repo: no secrets, no `CLAUDE.local.md`, no downloaded datasets committed.

## How it runs

`.github/workflows/detect.yml` runs on every push: downloads Chainsaw (pinned `CHAINSAW_VERSION`), SigmaHQ rules, and EVTX-ATTACK-SAMPLES, hunts twice (`rules/` and SigmaHQ), then `attack_coverage.py` writes the ATT&CK table to the run summary.

- Test a change by pushing and checking the run: `gh run watch <id>` then `gh run view <id> --log`.
- Local check (no downloads needed): `python3 test_coverage.py`.
- CI fails if any rule in `rules/` matches nothing. A new rule must fire on at least one sample log.

## Writing rules (`rules/*.yml`)

- Sigma format, one rule per file. Required: unique `id` (uuid4), `tags` with `attack.<tactic>` and `attack.tNNNN[.NNN]`, `author: j2jun`, `level`, `falsepositives`.
- Chainsaw ties `logsource.service` to a specific provider (`service: security` = `Microsoft-Windows-Security-Auditing`). Events from other providers (e.g. log cleared, 1102/104, from `Microsoft-Windows-Eventlog`) never match a service-scoped rule. Use `product: windows` plus a `Channel` selection instead, and comment why.
- Selection-name wildcards must be prefixes (`1 of cleared_*`); suffix wildcards (`1 of *_cleared`) fail to load.
- Check field names against Chainsaw's mapping: `mappings/sigma-event-logs-all.yml` at the pinned tag.

## Scope

The 12 target techniques live in `TECHNIQUES` in `attack_coverage.py` and the README table. Change both together.
