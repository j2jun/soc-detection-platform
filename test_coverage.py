from attack_coverage import GREEN, LIGHT, RED, layer, matches, simulated, summarize

hit = {"name": "R", "id": "x", "tags": ["attack.t1110.003"],
       "document": {"path": "/a/kerberos_pwd_spray_4771.evtx"}}

assert matches(["attack.t1110.003"], "T1110")          # parent covers sub-technique
assert not matches(["attack.t1110"], "T1110.003")      # but not the reverse
assert not matches(["attack.t11100"], "T1110")         # no false prefix match
assert summarize([hit], "T1110") == (["R"], ["kerberos_pwd_spray_4771.evtx"])
lay = {t["techniqueID"]: t["color"] for t in layer([dict(hit, tags=["attack.t1070.001"])], [hit], ["T1554"])["techniques"]}
assert (lay["T1070.001"], lay["T1110"], lay["T1548.003"], lay["T1554"]) == (GREEN, LIGHT, RED, GREEN), lay
assert "T1554" in simulated("rules")  # the pyenv rule's tags are picked up
print("ok")
