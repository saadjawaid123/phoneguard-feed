"""Checks the parts of build_feed.py the phones depend on. Runs before every build."""
import json, random, struct
import build_feed as b

# fnv must match Intel.fnv in the app (value checked against the Kotlin engine).
assert b.fnv("") == -3750763034362895579
r = lambda n: {random.randint(-2**63, 2**63 - 1) for _ in range(n)}
old = sorted(r(2000))
new = sorted(set(old[300:]) | r(500))
d = b.make_delta(123, old, new)
assert struct.unpack(">q", d[:8])[0] == 123
assert b.apply_delta(old, d) == new
assert b.unpack(b.pack(new)) == new
b.check_apps(open("apps.json", "rb").read())
try:
    b.check_apps(json.dumps({"v": 1, "apps": [{"pkg": "x", "names": ["X"], "certs": ["nothex"]}]}).encode())
    raise SystemExit("bad cert was accepted")
except AssertionError:
    pass
print("build_feed tests passed")
