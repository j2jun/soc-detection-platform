# SOC Detection & Response Platform

A mini Security Operations Center (SOC) home lab built with **Sigma rules**, **Wazuh**, and **Elastic Stack**, tested with **attack simulations** mapped to **MITRE ATT&CK**.

> Status: phase 1 running (detection-as-code in GitHub Actions). Phase 2 (live Wazuh lab) is next.

## Goal

Build a small version of a company security team's detection pipeline: collect logs from victim machines, detect attacker behavior with rules, simulate real attack techniques, and show which ATT&CK techniques the lab can detect, with evidence.

## Architecture

```
 Victim VMs (Windows + Sysmon, Linux)
        │  Wazuh agents ship logs
        ▼
 Wazuh Manager ── runs detection rules
        │
        ▼
 Indexer + Dashboards (Wazuh Indexer/OpenSearch or Elastic Stack)
        ▲
        │  Sigma rules converted with sigma-cli
 Sigma rule repo (detection-as-code)

 Attacker side: Atomic Red Team / Caldera ──► Victim VMs
```

1. **Telemetry:** victim VMs produce logs (process starts, logins, network connections).
2. **Collection and detection:** Wazuh agents send logs to the Wazuh manager, which runs rules.
3. **Storage, search and dashboards:** logs and alerts are indexed for searching and visualization.
4. **Attack simulation:** controlled attacks run on the victims, and each detection is tagged with the ATT&CK technique it covers.

### Core loop

Simulate an attack → check that the logs arrived → write or convert a Sigma rule → confirm the alert fires → map it to ATT&CK → document the response → repeat.

## Planned deliverables

- [ ] Detection rules stored as code (Sigma YAML + converted queries)
- [ ] ATT&CK Navigator layer showing detection coverage
- [ ] Dashboards (screenshots)
- [ ] Incident response playbooks for 1–2 simulated attacks
- [ ] Write-up of the results

## Resources

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma): the official Sigma rule repository, with thousands of community detection rules in YAML. `sigma-cli` / pySigma converts them into queries for specific SIEMs.
- [Wazuh documentation](https://documentation.wazuh.com/)
- [Elastic Stack](https://www.elastic.co/elastic-stack)
- [MITRE ATT&CK](https://attack.mitre.org/) and [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE Caldera](https://github.com/mitre/caldera)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with the [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) or [Olaf Hartong](https://github.com/olafhartong/sysmon-modular) config

## Phase 1: detection-as-code in GitHub Actions

Every push runs [`.github/workflows/detect.yml`](.github/workflows/detect.yml) on GitHub's free runners. Nothing is stored in the repo or on a laptop:

1. Downloads [Chainsaw](https://github.com/WithSecureLabs/chainsaw) (runs Sigma rules directly against Windows `.evtx` logs), the SigmaHQ rules, and [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (logs recorded during real ATT&CK attacks).
2. Hunts the samples twice: once with my rules in [`rules/`](rules/), once with SigmaHQ's Windows rules.
3. [`attack_coverage.py`](attack_coverage.py) maps the hits to the 12 techniques and writes the coverage table to the run summary. **The build fails if any of my rules stops firing**, so a broken rule can't slip in.

| Path | What it is |
|---|---|
| `rules/` | My Sigma rules |
| `attack_coverage.py` | Builds the coverage table from the hunt results |
| `test_coverage.py` | Self-check for the technique-matching logic |
| `.github/workflows/detect.yml` | The CI pipeline |
| `rules/linux/`, `linux_hunt.py`, `.github/simulate-pyenv-attack.sh` | Linux rules, tested by simulating the attack under auditd |

### First results (2026-11-04)

- **11 of 12 techniques** are detected by SigmaHQ community rules on the recorded attacks. **T1548.003 (Linux sudo abuse)** has no sample data: it needs the live lab in phase 2.
- **My first rule**, [`windows_security_log_cleared.yml`](rules/windows_security_log_cleared.yml) (T1070.001), fires on cleared Security (1102) and System (104) logs.
- **Lesson learned:** the first version of the rule never matched. Chainsaw ties `logsource: service: security` to the `Microsoft-Windows-Security-Auditing` provider, but Windows writes the log-cleared events under `Microsoft-Windows-Eventlog`. Matching on `Channel` instead fixed it. The SigmaHQ rules for T1070.001 show **zero hits** in the same run, probably for the same reason, so this is a real gap my rule fills.

### Linux attack simulation: the Binance pyenv-shim swap (2026-11-05)

The [$6.3B Binance heist](https://www.bleepingcomputer.com/news/security/binance-says-fake-job-interview-led-to-63-billion-crypto-heist/) started when a fake take-home assignment swapped a pyenv component on an engineer's laptop. No recorded dataset covers that, so the `linux-sim` CI job **records its own telemetry**:

1. Installs auditd on the runner and watches `~/.pyenv/shims`.
2. Runs **real pyenv** (`pyenv rehash`) to capture benign shim writes, then overwrites a shim like the malware did. Then it repeats the overwrite two ways to try to evade the rule: python3 renamed to `cp`, and a plain bash script. The payload is inert.
3. Converts [`rules/linux/`](rules/linux/) to SQL with sigma-cli and runs it over the logs with [`linux_hunt.py`](linux_hunt.py). **The build fails if any attacker write is missed or any benign write alerts.**

Result: [`pyenv_shim_tampering.yml`](rules/linux/pyenv_shim_tampering.yml) (T1554) catches **3 of 3** attacker writes with **0 of 9** false positives from real pyenv. auditd splits each event across several records, so `linux_hunt.py` merges them into one row per event (as auditbeat and Laurel do). That lets the rule check the binary and the command line together.

- **Lesson 1:** measure before you filter. I assumed pyenv writes shims as a process named `pyenv-*`. The audit log showed it actually uses `bash`, `cp`, `chmod`, and `rm`.
- **Lesson 2:** filter on `exe` (the binary's real path, set by the kernel), not `comm` (a name any process can change). Allowing a binary alone isn't enough either: allowing `bash` let every bash script through, so each filter now also requires a pyenv command line.
- **Lesson 3:** CI caught a false positive I didn't know about. Current pyenv has a second prototype file (`.pyenv-source-shim`).
- **Known gap:** the command line is argv, which an attacker can forge. Closing that needs process ancestry (phase 2, Wazuh) or a file-integrity check against pyenv's shim template.

## Decisions made

### #1 Where it runs: free cloud, zero laptop disk (decided 2026-11-04)

Constraint: **no cost**, and as little laptop disk as possible (the laptop has ~15 GB free; a full local lab needs 50–100 GB).

| Option | Laptop disk | Cost | Live attacks | Wazuh |
|---|---|---|---|---|
| Simulation in GitHub Codespaces | 0 | Free quota | No (recorded logs) | No |
| Simulation in GitHub Actions | 0 | Free for public repos | No (recorded logs) | No |
| Oracle Cloud Always Free | 0 | Free forever (card for identity check) | Linux only (ARM) | Yes |
| Azure for Students | 0 | $100 credit/year, no card | Windows + Linux | Yes |

- **Phase 1:** GitHub Actions (and Codespaces for editing) running Sigma rules against recorded attack logs.
- **Phase 2:** Azure for Students for a live Wazuh lab with Windows and Linux victims. Stop VMs after each session and allow only my IP.

### #2 SIEM backend: Sigma tools first, then Wazuh, Elastic as a stretch goal (decided 2026-11-04, updated for the zero-cost plan)

| | Wazuh only | Wazuh + Elastic | Elastic only |
|---|---|---|---|
| RAM | ~4–8 GB | ~10–16 GB | ~6–8 GB |
| Setup effort | Low (all-in-one installer) | High (two stacks + forwarding) | Medium (Fleet + agents) |
| Sigma rules | No official Wazuh converter; hand-port to XML or convert to OpenSearch queries | Official, mature pySigma Elasticsearch backend | Same as Wazuh + Elastic |
| ATT&CK mapping | Built-in MITRE ATT&CK dashboard view | Both | Elastic rule ATT&CK tags |
| Response | Wazuh Active Response | Wazuh Active Response | Elastic Defend (some features paid) |

- **Phase 1:** Sigma rules run with Chainsaw in GitHub Actions against recorded attacks (see above).
- **Phase 2:** Wazuh only, on Azure for Students. Get logs, alerts and live attack simulations working end to end.
- **Stretch:** add Elastic Stack as a second Sigma backend (pySigma's Elasticsearch backend), only if the free credits have room.

**Why:** Wazuh makes collection and response easy; Elastic makes running Sigma rules easy. Phasing gives a working lab before the hardest integration work, and the final setup still uses every tool in the project brief.

### #7 Technique scope: frequent techniques linked into one attack chain (decided 2026-11-04)

Approaches considered: breadth across tactics, one attack chain, emulating a threat group, or the most common real-world techniques. Chosen: **most common techniques** (prioritized using Red Canary's Threat Detection Report) **linked into one ransomware-style attack chain**: brute force in → run PowerShell → persist → dump credentials → move laterally → delete backups.

| Tactic | Technique | Simulated with | Detection source | Detected? |
|---|---|---|---|---|
| Execution | T1059.001 PowerShell (encoded commands) | Atomic Red Team | | |
| Persistence | T1053.005 Scheduled Task | Atomic | | |
| Persistence | T1547.001 Registry Run Keys | Atomic | | |
| Persistence | T1136.001 Create Local Account | Atomic | | |
| Privilege escalation (Linux) | T1548.003 Sudo abuse | Atomic | | |
| Defense evasion | T1218.011 Rundll32 (LOLBin) | Atomic | | |
| Defense evasion | T1070.001 Clear Windows Event Logs | Atomic | | |
| Credential access | T1003.001 LSASS memory dump | Atomic (Mimikatz / procdump) | | |
| Credential access | T1110 Brute force (SSH / RDP) | Hydra / Atomic | | |
| Discovery | T1087 Account Discovery | Atomic | | |
| Lateral movement | T1021.002 SMB / admin shares | Atomic / PsExec | | |
| Impact | T1490 Inhibit System Recovery (delete shadow copies) | Atomic | | |

**Detection source** will be one of: **built-in** (Wazuh/Elastic prebuilt rule), **Sigma** (converted community rule), or **custom** (written by me). This keeps the coverage map honest about which detections are my own work.

## Open decisions

| # | Decision | Options | Leaning toward |
|---|---|---|---|
| 1 | Where it runs | Laptop VMs (VirtualBox/UTM), home server, or cloud (AWS/Azure free tier) | **Decided:** GitHub Actions now, Azure for Students later (see above) |
| 2 | SIEM backend | Wazuh's built-in indexer (OpenSearch) or a separate Elastic Stack | **Decided:** Sigma tools, then Wazuh, Elastic as stretch (see above) |
| 3 | Victim machines | Windows, Linux, or both | Both. Most ATT&CK techniques and Sigma rules target Windows. |
| 4 | Windows telemetry | Default event logs, or add Sysmon | Add Sysmon. Without it, most Sigma rules have nothing to match. |
| 5 | Sigma rule use | Convert to Wazuh XML, to Elastic/OpenSearch queries, or both | Convert to the chosen backend with `sigma-cli`. Wazuh has no official Sigma backend, so Wazuh XML needs community tools or hand-porting. |
| 6 | Attack tool | Atomic Red Team (single techniques), Caldera (attack chains), or manual | Atomic Red Team first, Caldera later for a full attack-chain demo. |
| 7 | Technique scope | All of ATT&CK, or a focused set | **Decided:** 12 frequent techniques as one attack chain (see above) |
| 8 | Response depth | Detection only, or automated response | Detection plus written playbooks. Wazuh Active Response is an optional extra. |
| 9 | Network isolation | Isolated host-only network, or bridged to the home network | Isolated. Never run attack simulations on a network with real devices. |
| 10 | Deliverable format | GitHub repo, blog post, or demo video | GitHub repo with rules, Navigator layer, screenshots and a write-up. |

## Glossary

### Organizations and roles

- **SOC (Security Operations Center):** the team, and its tooling, that monitors an organization's systems around the clock, sorts alerts, and responds to incidents.
- **Blue team / red team / purple team:** defenders / attackers / both working together. This project is a purple-team exercise.
- **Detection engineering:** writing, testing and tuning the rules that turn raw logs into alerts.

### Tools

- **SIEM (Security Information and Event Management):** a central system that collects logs, runs detection rules, and supports search and correlation. Examples: Splunk, Elastic Security, Microsoft Sentinel.
- **Wazuh:** free, open-source security platform with agents on each machine. Does log collection, intrusion detection, file integrity monitoring, vulnerability detection and active response.
- **Elastic Stack (ELK):** **E**lasticsearch (stores and searches data), **L**ogstash (ingests and transforms it), **K**ibana (dashboards and UI), plus **Beats** (lightweight log shippers).
- **OpenSearch:** open-source fork of Elasticsearch and Kibana. Wazuh's indexer and dashboard are built on it.
- **Sigma:** vendor-neutral YAML format for detection rules ("the YARA of logs"). Write a rule once, convert it to Splunk, Elastic or other query languages with **pySigma / sigma-cli**.
- **Sysmon (System Monitor):** free Microsoft tool that records detailed Windows activity: process creation with full command lines, network connections, registry changes.
- **Atomic Red Team:** library of small, safe tests, each simulating one ATT&CK technique.
- **Caldera:** MITRE's platform for automating multi-step attack simulations.
- **EDR (Endpoint Detection and Response):** security software on each machine that detects and responds to threats. Wazuh plus Sysmon is a rough lab version.

### Frameworks

- **MITRE ATT&CK:** public catalog of real-world attacker behavior.
  - **Tactic:** the attacker's goal, e.g. *Persistence*.
  - **Technique:** how they achieve it, e.g. *T1053 Scheduled Task*.
  - **Sub-technique:** a more specific variant, e.g. *T1053.005*.
- **ATT&CK Navigator:** web tool for coloring in the ATT&CK matrix to show detection coverage.
- **TTPs (Tactics, Techniques and Procedures):** how an attacker operates, as opposed to specific indicators.
- **Cyber Kill Chain:** Lockheed Martin's 7-stage attack model, an older alternative to ATT&CK.

### Detection concepts

- **Log / event / telemetry:** raw records of system activity. Telemetry is the overall stream.
- **Alert:** a rule matched an event and needs attention.
- **Incident:** a confirmed security problem that needs a response.
- **True positive / false positive / false negative:** a correct alert / an alert on harmless activity / a missed attack. Tuning reduces false positives without creating false negatives.
- **Triage:** quickly judging whether an alert is real and how urgent it is.
- **IOC (Indicator of Compromise):** a concrete attack artifact such as a malicious IP, file hash or domain. Easy for attackers to change.
- **Behavioral detection:** detecting what an attacker *does* (TTPs) rather than specific IOCs. Harder to evade; the focus of Sigma and ATT&CK.
- **Correlation:** linking several events into one detection, e.g. 5 failed logins followed by a success.
- **Threat hunting:** proactively searching logs for attacks the rules didn't catch.
- **Detection coverage:** the share of relevant ATT&CK techniques the lab can reliably detect.

### Response concepts

- **Incident response (IR):** a structured process for handling incidents. NIST phases: Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity.
- **Playbook / runbook:** step-by-step instructions for handling a specific alert type.
- **SOAR (Security Orchestration, Automation and Response):** tools that automate playbook steps. Wazuh Active Response is a lightweight version.
- **Containment:** stopping the spread, e.g. isolating a host or disabling an account.
- **MTTD / MTTR:** mean time to detect / mean time to respond, the standard SOC performance metrics.

### Techniques to simulate

- **Credential dumping (T1003):** stealing passwords or hashes from memory, e.g. Mimikatz attacking LSASS.
- **Lateral movement:** moving from one compromised machine to others.
- **Persistence:** surviving reboots, e.g. through scheduled tasks or registry run keys.
- **Privilege escalation:** gaining admin or root rights.
- **Living off the land (LOLBins):** abusing built-in tools like PowerShell, certutil or rundll32 so activity blends in.
