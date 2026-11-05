"""Run sigma-cli SQLite queries against auditd logs.

Usage: python3 linux_hunt.py legit.log attack.log queries.sql
Each query must match nothing in legit.log and something in attack.log, or this exits 1.
Self-check: python3 linux_hunt.py --test
"""
import re
import sqlite3
import sys

FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')


def parse(lines):
    """auditd lines -> list of {field: value}. Quotes stripped. ENRICHED-format duplicates
    (ARCH, UID, ...: uppercase copies of raw fields) are dropped; SQLite column names ignore case."""
    return [{k: v.strip('"') for k, v in FIELD.findall(line) if not k.isupper()}
            for line in lines if "type=" in line]


def hunt(records, query):
    cols = sorted({k for r in records for k in r})
    db = sqlite3.connect(":memory:")
    db.execute(f"CREATE TABLE logs ({', '.join(f'[{c}] TEXT' for c in cols) or 'x TEXT'})")
    db.executemany(f"INSERT INTO logs ({', '.join(f'[{c}]' for c in cols)}) VALUES ({', '.join('?' * len(cols))})",
                   [[r.get(c) for c in cols] for r in records])
    db.row_factory = sqlite3.Row
    return [dict(row) for row in db.execute(query.replace("<TABLE_NAME>", "logs"))]


def show(rows):
    return "; ".join(f"comm={r.get('comm')} exe={r.get('exe')}" for r in rows) or "none"


def main(legit_path, attack_path, sql_path):
    legit, attack = (parse(open(p, errors="replace")) for p in (legit_path, attack_path))
    events = [r for r in legit + attack if r.get("key") == "pyenv_shim"]
    print("Shim writes seen: " + show(events))
    ok = True
    for query in (q.strip() for q in open(sql_path) if q.startswith("SELECT")):
        fp, tp = hunt(legit, query), hunt(attack, query)
        print(f"\n`{query}`\n- benign pyenv activity: {len(fp)} hits ({show(fp)})\n"
              f"- simulated attack: {len(tp)} hits ({show(tp)})")
        ok &= not fp and bool(tp)
    print("\nPASS" if ok else "\n**FAIL:** a rule missed the attack or alerted on benign activity")
    return 0 if ok else 1


def test():
    rec = parse(['type=SYSCALL msg=audit(1.2:3): syscall=257 comm="python3" exe="/usr/bin/python3.12" key="pyenv_shim" ARCH=x86_64',
                 "noise without fields"])
    assert rec == [{"type": "SYSCALL", "msg": "audit(1.2:3):", "syscall": "257", "comm": "python3",
                    "exe": "/usr/bin/python3.12", "key": "pyenv_shim"}], rec
    q = "SELECT * FROM <TABLE_NAME> WHERE type='SYSCALL' AND key='pyenv_shim' AND NOT comm LIKE 'pyenv%'"
    assert len(hunt(rec, q)) == 1 and hunt([dict(rec[0], comm="pyenv-rehash")], q) == []
    print("ok")


if __name__ == "__main__":
    test() if sys.argv[1:] == ["--test"] else sys.exit(main(*sys.argv[1:4]))
