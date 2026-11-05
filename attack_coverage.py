"""Build the ATT&CK coverage table from Chainsaw hunt results.

Usage: python3 attack_coverage.py custom.json sigma.json rules/
Prints a Markdown table. Exits 1 if any rule in rules/ never fired,
so a broken custom rule fails CI.
"""
import json
import pathlib
import re
import sys

# The 12-technique attack chain from the README (decision #7).
TECHNIQUES = {
    "T1059.001": "PowerShell",
    "T1053.005": "Scheduled Task",
    "T1547.001": "Registry Run Keys",
    "T1136.001": "Create Local Account",
    "T1548.003": "Sudo abuse (Linux)",
    "T1218.011": "Rundll32",
    "T1070.001": "Clear Windows Event Logs",
    "T1003.001": "LSASS memory dump",
    "T1110": "Brute force",
    "T1087": "Account Discovery",
    "T1021.002": "SMB / admin shares",
    "T1490": "Inhibit System Recovery",
}


def matches(tags, technique):
    """True if a rule's tags cover the technique (parent IDs include sub-techniques)."""
    want = "attack." + technique.lower()
    return any(t == want or t.startswith(want + ".") for t in tags)


def summarize(hits, technique):
    rules = sorted({h["name"] for h in hits if matches(h.get("tags", []), technique)})
    files = sorted({pathlib.Path(h["document"]["path"]).name
                    for h in hits if matches(h.get("tags", []), technique)})
    return rules, files


def table(custom, sigma):
    rows = ["| Technique | Name | Custom rules fired | SigmaHQ rules fired | Sample logs |",
            "|---|---|---|---|---|"]
    for tid, name in TECHNIQUES.items():
        mine, f1 = summarize(custom, tid)
        theirs, f2 = summarize(sigma, tid)
        files = sorted(set(f1) | set(f2))
        rows.append(f"| {tid} | {name} | {', '.join(mine) or '—'} | "
                    f"{len(theirs) or '—'} | {', '.join(files[:3]) or 'no sample: needs live lab'} |")
    return "\n".join(rows)


def silent_rules(custom, rules_dir):
    fired = {h["id"] for h in custom}
    ids = {}
    for f in pathlib.Path(rules_dir).glob("*.yml"):
        m = re.search(r"^id:\s*(\S+)", f.read_text(), re.M)
        if m:
            ids[m.group(1)] = f.name
    return [name for rid, name in ids.items() if rid not in fired]


if __name__ == "__main__":
    custom, sigma = (json.loads(pathlib.Path(p).read_text() or "[]") for p in sys.argv[1:3])
    print(table(custom, sigma))
    silent = silent_rules(custom, sys.argv[3])
    if silent:
        print(f"\n**FAIL:** these custom rules matched nothing: {', '.join(silent)}")
        sys.exit(1)
