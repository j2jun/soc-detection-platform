# Write-up: detection-as-code SOC lab, phase 1

**Goal:** build a small version of a company security team's detection pipeline: write rules as code, test them against real attack telemetry, and prove which ATT&CK techniques they catch, at **zero cost** and with **zero laptop disk**.

## What I built

| Piece | What it does |
|---|---|
| **CI detection pipeline** ([`detect.yml`](.github/workflows/detect.yml)) | On every push, GitHub Actions downloads Chainsaw, SigmaHQ rules, and recorded attack logs, then hunts with my rules and the community's |
| **Coverage report** ([`attack_coverage.py`](attack_coverage.py)) | Maps hits to 12 target techniques, writes a table and an [ATT&CK Navigator layer](attack-layer.json), and **fails the build if any of my rules stops firing** |
| **Attack simulation** ([`linux-sim` job](.github/simulate-pyenv-attack.sh)) | Where no recorded logs exist, CI generates its own: auditd plus real pyenv, then the attack, then evasion attempts |
| **Custom rules** ([`rules/`](rules/)) | Windows log cleared (T1070.001); pyenv shim tampering (T1554, the Binance attack chain) |
| **Playbooks** ([`PLAYBOOKS.md`](PLAYBOOKS.md)) | Step-by-step response for each custom rule |

## Results

- **11 of 12** target techniques are detected by SigmaHQ community rules on recorded attacks. T1548.003 (Linux sudo abuse) has no sample data and waits for the live lab.
- **Log-cleared rule:** fires on cleared Security and System logs where **SigmaHQ's rules show zero hits**, a real gap.
- **Pyenv shim rule:** catches **3 of 3** attacker writes, including a renamed binary and a bash dropper, with **0 of 9** false positives from real pyenv.

To view the coverage map, open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose *Open Existing Layer → Upload from local*, and pick `attack-layer.json`.

## Lessons

1. **A rule that silently matches nothing looks the same as a quiet network.** My first log-cleared rule never fired: Chainsaw ties `service: security` to a different Windows provider. That's why CI now fails on silent rules.
2. **Measure before you filter.** I assumed pyenv writes shims as `pyenv-*`. auditd showed `bash`, `cp`, `chmod`, and `rm`.
3. **Every field you allowlist is a field the attacker controls.** Process names (`comm`) can be faked, so I filter on the kernel's `exe`. But allowing `bash` by `exe` alone let any bash script through, so each filter also requires a pyenv command line.
4. **Tests find what reasoning misses.** CI caught a false positive from a second pyenv prototype file I didn't know existed.

## Known gaps

- The pyenv rule trusts the command line (argv), which an attacker can forge. A process tree (phase 2) or a shim integrity check would close it.
- Recorded logs prove a rule matches, not that the lab's own telemetry pipeline works. That needs live victims.

## Next: phase 2

A live lab with victim machines, Wazuh, dashboards, and Atomic Red Team attacks. See *Open decisions* in the [README](README.md).
