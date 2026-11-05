"""Run sigma-cli SQLite queries against auditd logs.

Usage: python3 linux_hunt.py legit.log attack.log queries.sql
Each query must match nothing in legit.log and EVERY attacker write in attack.log, or this exits 1.
Self-check: python3 linux_hunt.py --test
"""
import re
import sqlite3
import sys

FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')


def value(k, v):
    if k == "proctitle" and not v.startswith('"'):  # unquoted proctitle is hex argv, NUL-separated
        return bytes.fromhex(v).replace(b"\0", b" ").decode(errors="replace")
    return v.strip('"')


def parse(lines):
    """auditd lines -> one row per event. auditd splits an event into SYSCALL, PATH, PROCTITLE...
    records sharing msg=audit(time:serial); they're merged (SYSCALL fields win) like auditbeat or
    Laurel do, so a rule can see exe and the command line together. ENRICHED-format uppercase
    duplicates (ARCH, UID...) are dropped: SQLite column names ignore case."""
    events = {}
    for line in lines:
        if "type=" not in line:
            continue
        rec = {k: value(k, v) for k, v in FIELD.findall(line) if not k.isupper()}
        merged = events.setdefault(rec.get("msg"), {})
        if rec.get("type") == "SYSCALL":
            merged.update(rec)
        else:
            for k, v in rec.items():
                merged.setdefault(k, v)
    return list(events.values())


def hunt(records, query):
    cols = sorted({k for r in records for k in r})
    db = sqlite3.connect(":memory:")
    db.execute(f"CREATE TABLE logs ({', '.join(f'[{c}] TEXT' for c in cols) or 'x TEXT'})")
    db.executemany(f"INSERT INTO logs ({', '.join(f'[{c}]' for c in cols)}) VALUES ({', '.join('?' * len(cols))})",
                   [[r.get(c) for c in cols] for r in records])
    db.row_factory = sqlite3.Row
    return [dict(row) for row in db.execute(query.replace("<TABLE_NAME>", "logs"))]


def show(rows):
    return "; ".join(f"exe={r.get('exe')} cmd={(r.get('proctitle') or '')[:70]!r}" for r in rows) or "none"


def main(legit_path, attack_path, sql_path):
    legit, attack = (parse(open(p, errors="replace")) for p in (legit_path, attack_path))
    events = [r for r in legit + attack if r.get("key") == "pyenv_shim"]
    print("Shim writes seen: " + show(events))
    ok = True
    for query in (q.strip() for q in open(sql_path) if q.startswith("SELECT")):
        fp, tp = hunt(legit, query), hunt(attack, query)
        print(f"\n`{query}`\n- benign pyenv activity: {len(fp)} hits ({show(fp)})\n"
              f"- simulated attack: {len(tp)} hits ({show(tp)})")
        writes = [r for r in attack if r.get("type") == "SYSCALL" and r.get("key") == "pyenv_shim"]
        ok &= not fp and len(tp) == len(writes) > 0
    print("\nPASS" if ok else "\n**FAIL:** a rule missed the attack or alerted on benign activity")
    return 0 if ok else 1


def test():
    rec = parse(['type=SYSCALL msg=audit(1.2:3): syscall=257 comm="python3" exe="/usr/bin/python3.12" key="pyenv_shim" ARCH=x86_64',
                 "type=PROCTITLE msg=audit(1.2:3): proctitle=707974686F6E33002D63",  # "python3\0-c"
                 'type=PATH msg=audit(1.2:3): item=0 name="/h/.pyenv/shims/python"',
                 "noise without fields"])
    assert rec == [{"type": "SYSCALL", "msg": "audit(1.2:3):", "syscall": "257", "comm": "python3",
                    "exe": "/usr/bin/python3.12", "key": "pyenv_shim", "proctitle": "python3 -c",
                    "item": "0", "name": "/h/.pyenv/shims/python"}], rec
    q = "SELECT * FROM <TABLE_NAME> WHERE type='SYSCALL' AND key='pyenv_shim' AND NOT exe='/usr/bin/cp'"
    assert len(hunt(rec, q)) == 1 and hunt([dict(rec[0], exe="/usr/bin/cp")], q) == []
    assert len(hunt([dict(rec[0], comm="cp", exe="/tmp/cp")], q)) == 1  # renamed binary still caught
    print("ok")


if __name__ == "__main__":
    test() if sys.argv[1:] == ["--test"] else sys.exit(main(*sys.argv[1:4]))
