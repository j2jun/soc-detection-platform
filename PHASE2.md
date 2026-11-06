# Phase 2 plan: live lab on Azure for Students

**Goal:** real victims sending real telemetry to Wazuh, attacked with Atomic Red Team, producing dashboards and evidence. This closes what phase 1 can't: process ancestry (the pyenv rule's known gap), T1548.003 (no recorded sample), and the dashboards deliverable.

**Budget:** the $100/year student credit. **Rule: nothing is created until the guardrails in step 0 are in place.**

> Prices and limits below are my estimates for East US. Check them in the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) and your subscription's quota page before creating anything.

## Architecture

```
 Your IP only ──(SSH / HTTPS / RDP)──► NSG ──► VNet 10.10.0.0/24   (one resource group: soc-lab-rg)
                                                │
              ┌─────────────────────────────────┼──────────────────────────────┐
              ▼                                 ▼                              ▼
   wazuh-01  Ubuntu 24.04             win-victim  Windows 11/Server     lin-victim  Ubuntu (optional)
   B2ms: 2 vCPU, 8 GB                 B2s: 2 vCPU, 4 GB                 B1s: 1 vCPU, 1 GB
   Wazuh manager + indexer + dash     Sysmon + Wazuh agent              auditd + Wazuh agent
                                      Atomic Red Team                   sudo / pyenv attacks
```

- **Why these sizes:** Wazuh suggests 4 vCPU / 8 GB for up to 25 agents. A 2-agent lab should run on 2 vCPU / 8 GB, and this keeps the total at 4–5 vCPUs, which is likely inside a student subscription's regional quota (**verify the quota before you start**).
- **One resource group** means a single `az group delete -n soc-lab-rg` tears down everything.

## Step 0: cost and safety guardrails (before any VM exists)

Run every `az` command in **Azure Cloud Shell** (the `>_` icon in the portal; choose Bash, then *No storage account required*), so nothing is installed on the laptop. Before the guardrails below: check that vCPU quota has at least 5 free in your region, then create the resource group and the NSG (both free):

```sh
az group create -n soc-lab-rg -l eastus --tags project=soc-lab
az network nsg create -g soc-lab-rg -n soc-lab-nsg --tags project=soc-lab
az network nsg rule create -g soc-lab-rg --nsg-name soc-lab-nsg -n allow-me \
  --priority 100 --protocol Tcp --access Allow \
  --source-address-prefixes YOUR.IP/32 --destination-port-ranges 22 443
```

Get `YOUR.IP` by running `curl -s https://ifconfig.me` on the laptop, not in Cloud Shell.

| Guardrail | How | Why |
|---|---|---|
| Confirm the **spending limit is on** | Azure portal → Subscriptions → your subscription. Credit-based offers stop resources when the credit runs out instead of charging a card | The worst case becomes losing credit, not money |
| **Budget alerts** at $10, $25, $50 | Cost Management → Budgets, if your offer supports budgets (some sponsored offers don't; then check the balance at microsoftazuresponsorships.com weekly) | Early warning |
| **Auto-shutdown** on every VM | `az vm auto-shutdown -g soc-lab-rg -n <vm> --time 0500` (UTC; about 9–10 pm Pacific, depending on daylight saving) | A forgotten VM stops by itself |
| **Deallocate, don't just shut down** | `az vm deallocate -g soc-lab-rg -n <vm>`. Shutting down from inside the OS keeps billing compute | The most common surprise bill |
| **Your IP only** | NSG inbound rules allow 22, 443, and 3389 from your current IP only; nothing else from the internet | Lab VMs get scanned within minutes of going public |
| **No public IP on victims** | Reach `win-victim` through `wazuh-01` (SSH tunnel for RDP), or allow RDP from your IP only if tunnelling is too awkward | Victims run attack tools; keep them off the internet |
| **Tag everything** | `--tags project=soc-lab` | Find stray resources in the cost view |

**Session routine:** `az vm start` → work → screenshots → `az vm deallocate` for each VM. Rough cost: about $0.13–0.18/hour with both main VMs running, plus a few dollars a month for disks and any static public IP, even while stopped. That should fit 15–25 four-hour sessions in the credit.

## Steps

| # | Step | Done when | Closes |
|---|---|---|---|
| 1 | **Guardrails** (step 0) | Spending limit confirmed, alerts set (or the weekly check scheduled), auto-shutdown on | — |
| 2 | **Wazuh server:** Ubuntu B2ms, all-in-one install from the Wazuh quickstart (pin the 4.x version) | The dashboard loads over HTTPS from your IP | Decision #2 |
| 3 | **Windows victim:** Sysmon with a community config (SwiftOnSecurity or olafhartong) + Wazuh agent | Sysmon events appear in the Wazuh dashboard | Decisions #3, #4 |
| 4 | **First attacks:** Atomic Red Team for T1059.001, T1003.001, T1070.001 | Each one alerts in Wazuh; screenshot plus a timeline | Decision #6 |
| 5 | **Port my rules:** hand-port the two custom Sigma rules to Wazuh XML (no official Sigma→Wazuh backend exists) | Both fire on live attacks | Decision #5 |
| 6 | **Linux victim (optional):** B1s, auditd + agent; run T1548.003 and the pyenv shim swap | Pyenv alert includes the **parent process**, which fixes the forged-argv gap | Pyenv rule gap, T1548.003 |
| 7 | **Dashboards and write-up:** one coverage dashboard plus PLAYBOOKS walkthroughs with real screenshots | The README's last deliverable is ticked | Decisions #8, #10 |

## Decisions this plan proposes

| # | Decision | Proposal |
|---|---|---|
| 3 | Victims | Windows first (most techniques), Linux optional |
| 4 | Windows telemetry | Sysmon with a community config |
| 5 | Sigma use | Hand-port my 2 rules to Wazuh XML; keep using sigma-cli + CI for testing |
| 6 | Attack tool | Atomic Red Team; Caldera only if time remains |
| 8 | Response | Detection plus playbooks; Wazuh Active Response is optional |
| 9 | Network | NSG allows your IP only; no public IP on victims; victims' outbound internet open only while installing tools |

## Teardown

At the end of the project, or if the credit gets low: `az group delete -n soc-lab-rg --yes`. **This permanently deletes every lab VM and disk**, so export screenshots and logs first.
