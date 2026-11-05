# Incident response playbooks

One playbook per custom rule. Each follows the same phases: **triage → contain → scope → eradicate → recover → lessons**. Commands are for the lab's Linux and Windows hosts; adapt the paths to your fleet.

---

## PB-1: Pyenv shim modified by an unexpected process

**Alert:** [`pyenv_shim_tampering.yml`](rules/linux/pyenv_shim_tampering.yml) (T1554, medium)
**Why it matters:** a pyenv shim runs every time the developer types `python`. Replacing one is how the [2026 Binance heist](https://www.bleepingcomputer.com/news/security/binance-says-fake-job-interview-led-to-63-billion-crypto-heist/) got its foothold: a fake take-home assignment swapped a pyenv component on a wallet engineer's laptop. Months later, a container deployment token reachable from that foothold led to the wallet signing service. **Assume the developer's credentials are already stolen until proven otherwise.**

### 1. Triage (first 15 minutes)

| Question | How to answer it |
|---|---|
| What wrote the shim? | `ausearch -k pyenv_shim -i --start today`: read `exe`, `proctitle`, `pid`, `ppid`, `auid` (the original login user) |
| Is the shim actually changed? | All pyenv shims are copies of one template, so the odd one out is the tampered one: `md5sum ~/.pyenv/shims/* \| sort \| uniq -c -w32` |
| Where did the writer come from? | Walk the parents: `ps -o pid,ppid,lstart,args -p <ppid>`, then look in shell history, `~/Downloads`, and recent `git clone` folders for a take-home or interview repo |
| Is it calling home? | `ss -tpn \| grep <pid>`, and outbound connections in proxy or DNS logs since the first write |

**Benign if:** the writer is `pyenv rehash` or a known pyenv plugin, AND every shim hash matches. Close it as a false positive and note the plugin so the rule can be tuned.
**Escalate to incident if:** any shim hash differs, or the writer is anything else.

### 2. Contain

1. **Isolate the host on the network** (EDR network containment or a switch port). **Don't power it off**: memory holds the malware and its keys.
2. **Revoke the developer's active sessions:** SSO, VPN, cloud console, git hosting, and any internal AI or developer tools.
3. Tell the developer **not to wipe the machine or delete the repo**. The repo is evidence.

### 3. Rotate everything the laptop could reach

The Binance attackers stole a token months after first contact, so rotate broadly rather than guessing:

- [ ] Deployment and CI tokens (container registry, Kubernetes, CI secrets)
- [ ] Cloud keys (`~/.aws`, `~/.config/gcloud`, `~/.azure`)
- [ ] SSH keys (`~/.ssh`), and remove the public keys from servers and git hosting
- [ ] Git and package tokens (`~/.netrc`, `~/.npmrc`, `~/.pypirc`, `gh auth`)
- [ ] API keys for internal AI tools, plus browser sessions (session cookies can be replayed)

### 4. Scope

- **Fleet hunt:** run the same rule across all hosts, plus the shim hash check. Other engineers may have received the same "assignment."
- **Credential use:** search access logs for every rotated credential from the first shim write until rotation. Look for new IPs, new user agents, and odd hours.
- **Lateral movement:** check what the developer's identity touched in internal tools during that window (Binance's attackers pivoted through an internal AI tool).
- **Initial access:** identify the recruiter account and job platform, and report them to the platform.

### 5. Eradicate and recover

- **Reimage the laptop**; don't try to clean it. Reinstall pyenv from its official source.
- Reissue credentials only after the reimage, and short-lived ones where possible.

### 6. Lessons and hardening

- Run take-home assignments in a sandbox ([`sniff`](https://github.com/j2jun/sniff) scans first, then runs them in a container with no network or credentials).
- No standing production credentials on developer laptops: short-lived tokens, approved per use.
- Developer machines should have no network route to production signing or deployment systems.

**Evidence to keep:** the audit log, the tampered shim (copy it and record its hash), a process list, network connections, shell history, and the assignment repo.

---

## PB-2: Windows event log cleared

**Alert:** [`windows_security_log_cleared.yml`](rules/windows_security_log_cleared.yml) (T1070.001, high)
**Why it matters:** attackers clear logs to hide what they just did. The log is gone from the host, but any events already forwarded to the SIEM survive, and that is the whole point of central logging.

### 1. Triage

| Question | How to answer it |
|---|---|
| Who cleared it? | Event 1102 (Security) records `SubjectUserName` and `SubjectDomainName`; event 104 (System) records the user too |
| Was it planned? | Check change tickets and maintenance windows. An admin with a ticket means a false positive |
| What happened just before? | In the **SIEM copy** (not the host), review the preceding hour: logons (4624, and which logon type), new processes (4688 / Sysmon 1), and especially `wevtutil cl` or `Clear-EventLog` |

**Escalate if:** there's no ticket, the account isn't a known admin, or the clear followed a remote logon or credential-access activity.

### 2. Contain

1. Isolate the host.
2. Disable the account that cleared the log, and reset its credentials. If it's a domain admin, treat the domain as compromised.

### 3. Scope

- Look for the same account clearing logs on other hosts, and for logons from the same source.
- Rebuild the timeline from the SIEM. Check for LSASS access (T1003.001) and new local accounts (T1136.001), which commonly come just before a log clear.

### 4. Eradicate, recover, lessons

- Reimage if any malicious activity is confirmed.
- Make sure every host forwards logs in near real time, so a clear can't erase anything the SIEM hasn't already received.
- Alert on `wevtutil` and `Clear-EventLog` process starts too. That catches the attempt, not just its result.
