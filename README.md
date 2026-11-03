# SOC Detection & Response Platform

A mini Security Operations Center (SOC) home lab built with **Sigma rules**, **Wazuh**, and **Elastic Stack**, tested with **attack simulations** mapped to **MITRE ATT&CK**.

> Status: research and planning. This document records what I've researched so far.

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

## Open decisions

| # | Decision | Options | Leaning toward |
|---|---|---|---|
| 1 | Where it runs | Laptop VMs (VirtualBox/UTM), home server, or cloud (AWS/Azure free tier) | Local VMs if 16GB+ RAM, otherwise cloud. Apple Silicon needs ARM Windows builds, which limits some tools. |
| 2 | SIEM backend | Wazuh's built-in indexer (OpenSearch) or a separate Elastic Stack | Wazuh indexer first (one install). Add Elastic only for Kibana/Elastic Security experience; running both doubles RAM and setup. |
| 3 | Victim machines | Windows, Linux, or both | Both. Most ATT&CK techniques and Sigma rules target Windows. |
| 4 | Windows telemetry | Default event logs, or add Sysmon | Add Sysmon. Without it, most Sigma rules have nothing to match. |
| 5 | Sigma rule use | Convert to Wazuh XML, to Elastic/OpenSearch queries, or both | Convert to the chosen backend with `sigma-cli`. Wazuh has no official Sigma backend, so Wazuh XML needs community tools or hand-porting. |
| 6 | Attack tool | Atomic Red Team (single techniques), Caldera (attack chains), or manual | Atomic Red Team first, Caldera later for a full attack-chain demo. |
| 7 | Technique scope | All of ATT&CK, or a focused set | 10–20 techniques across several tactics (credential dumping, PowerShell, persistence, lateral movement). |
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
