from attack_coverage import matches, summarize

hit = {"name": "R", "id": "x", "tags": ["attack.t1110.003"],
       "document": {"path": "/a/kerberos_pwd_spray_4771.evtx"}}

assert matches(["attack.t1110.003"], "T1110")          # parent covers sub-technique
assert not matches(["attack.t1110"], "T1110.003")      # but not the reverse
assert not matches(["attack.t11100"], "T1110")         # no false prefix match
assert summarize([hit], "T1110") == (["R"], ["kerberos_pwd_spray_4771.evtx"])
print("ok")
