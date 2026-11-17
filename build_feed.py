#!/usr/bin/env python3
"""Builds and signs the PhoneGuard scam website list.

Output (all in this folder):
  block.bin       4-byte count, then sorted 64-bit FNV-1a fingerprints of website names (big-endian)
  delta.bin       the change since the previous list: 8-byte previous seq, 4-byte added count, added
                  fingerprints, 4-byte removed count, removed fingerprints (all big-endian). Phones that
                  have the previous list download this small file instead of the whole block.bin.
  allow.bin       same format as block.bin: websites that are never called a scam (own-allow.txt)
  apps.out.json   the official apps list for App Authenticity Check (checked copy of apps.json)
  feed.json       the note: version, sequence number, time made, SHA-256 and size of every file above
  feed.json.sig   Ed25519 signature of feed.json (base64). The app checks it with its public key.

Because the note names the SHA-256 of every file, one valid signature proves every file. The app also
checks that block.bin rebuilt from delta.bin has exactly the SHA-256 the note names.

Sources:
  own-block.txt                     our own reviewed list
  Phishing.Database ACTIVE domains  MIT licence
  URLhaus host file (abuse.ch)      CC0, used only when the URLHAUS_KEY secret is set
never-block.txt (the 10,000 most visited sites) and own-allow.txt are removed from every source, so a
mistake in a public feed can never make the app call a famous or known-good website a scam.

The signing key comes from the environment (FEED_SIGNING_KEY, base64 of the 32-byte seed).
It is a GitHub Actions secret and is never written to disk or printed.
"""
import base64, hashlib, json, os, struct, sys, time, urllib.request
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = [
    # (name, url, required, secret holding an auth key or None)
    ("phishing-database", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", True, None),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", False, "URLHAUS_KEY"),
]
MIN_TOTAL = 50_000      # fewer than this means a source broke: do not publish
MAX_TOTAL = 2_500_000   # keeps block.bin under the app's 24 MB limit
MAX_SHRINK = 0.5        # refuse a list less than half the size of the last one
MAX_ALLOW = 200_000
MASK = (1 << 64) - 1


def fnv(s):
    """64-bit FNV-1a as a signed number. Must match Intel.fnv in the app."""
    h = 0xcbf29ce484222325
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x100000001b3) & MASK
    return h - (1 << 64) if h >= (1 << 63) else h


def clean(host):
    host = host.strip().lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host or " " in host or "/" in host or len(host) > 253:
        return None
    return host


def lines_of(text):
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Host files look like "127.0.0.1 bad.example"; links look like "http://bad.example/x".
        part = line.split()[-1]
        if "://" in part:
            part = urlsplit(part).hostname or ""
        yield part


def fetch(url, key=None):
    headers = {"User-Agent": "phoneguard-feed"}
    if key:
        headers["Auth-Key"] = key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", errors="ignore")


def pack(hashes):
    return struct.pack(">i", len(hashes)) + b"".join(struct.pack(">q", h) for h in hashes)


def unpack(data):
    n = struct.unpack(">i", data[:4])[0]
    return list(struct.unpack(">%dq" % n, data[4:4 + 8 * n]))


def make_delta(prev_seq, old, new):
    old_s, new_s = set(old), set(new)
    added, removed = sorted(new_s - old_s), sorted(old_s - new_s)
    return (struct.pack(">q", prev_seq)
            + struct.pack(">i", len(added)) + b"".join(struct.pack(">q", h) for h in added)
            + struct.pack(">i", len(removed)) + b"".join(struct.pack(">q", h) for h in removed))


def apply_delta(old, delta):
    """Same steps as the app, used here to prove the delta before it is published."""
    i = 8
    na = struct.unpack(">i", delta[i:i + 4])[0]; i += 4
    added = struct.unpack(">%dq" % na, delta[i:i + 8 * na]); i += 8 * na
    nr = struct.unpack(">i", delta[i:i + 4])[0]; i += 4
    removed = set(struct.unpack(">%dq" % nr, delta[i:i + 8 * nr]))
    return sorted((set(old) - removed) | set(added))


def read(name):
    p = os.path.join(HERE, name)
    return open(p, "rb").read() if os.path.exists(p) else None


def file_entry(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def check_apps(data):
    """apps.json must be valid before it is signed, or every phone keeps its built-in list."""
    o = json.loads(data)
    assert o["v"] == 1 and isinstance(o["apps"], list) and o["apps"], "apps.json: bad format"
    seen = set()
    for a in o["apps"]:
        assert a["pkg"] and a["pkg"] not in seen, "apps.json: empty or repeated pkg"
        seen.add(a["pkg"])
        assert a["names"] and all(isinstance(n, str) and n for n in a["names"]), "apps.json: names"
        for c in a.get("certs", []):
            assert len(c) == 64 and all(ch in "0123456789abcdef" for ch in c), "apps.json: cert " + a["pkg"]


def main():
    never = {l.strip().lower() for l in open(os.path.join(HERE, "never-block.txt")) if l.strip()}
    allow = set()
    for h in lines_of(open(os.path.join(HERE, "own-allow.txt")).read()):
        h = clean(h)
        if h:
            allow.add(h)
    block, counts = set(), {}

    def add_all(name, text):
        n = 0
        for h in lines_of(text):
            h = clean(h)
            if h and h not in never and h not in allow:
                block.add(h)
                n += 1
        counts[name] = n

    add_all("own", open(os.path.join(HERE, "own-block.txt")).read())
    for name, url, required, secret in SOURCES:
        key = os.environ.get(secret, "").strip() if secret else None
        if secret and not key:
            print(f"source {name} skipped: no {secret} set")
            continue
        try:
            add_all(name, fetch(url, key))
        except Exception as e:  # one broken source must not stop the others
            print(f"source {name} failed: {e}")
            if required:
                sys.exit(f"required source {name} failed, not publishing")

    hashes = sorted({fnv(h) for h in block})
    print("counts", counts, "total", len(hashes), "allow", len(allow))
    if not MIN_TOTAL <= len(hashes) <= MAX_TOTAL:
        sys.exit(f"list size {len(hashes)} is outside {MIN_TOTAL}..{MAX_TOTAL}, not publishing")
    if len(allow) > MAX_ALLOW:
        sys.exit("allow list too large, not publishing")

    old_block = read("block.bin")
    old_note = json.loads(read("feed.json")) if read("feed.json") else None
    old_hashes = unpack(old_block) if old_block else []
    if old_block and len(hashes) < len(old_hashes) * MAX_SHRINK:
        sys.exit(f"list shrank from {len(old_hashes)} to {len(hashes)}, not publishing")

    data = pack(hashes)
    allow_data = pack(sorted({fnv(h) for h in allow}))
    apps_data = open(os.path.join(HERE, "apps.json"), "rb").read()
    check_apps(apps_data)

    if (old_block == data and read("allow.bin") == allow_data and read("apps.out.json") == apps_data
            and old_note and "allow" in old_note):
        print("no change")
        return

    seq = max(int(time.time()), (old_note["seq"] + 1) if old_note else 0)
    note = {
        "v": 1,
        "seq": seq,
        "made": int(time.time()),
        "block": file_entry(data),
        "allow": file_entry(allow_data),
        "apps": file_entry(apps_data),
        "sources": counts,
    }
    delta = None
    if old_block and old_note:
        delta = make_delta(old_note["seq"], old_hashes, hashes)
        if apply_delta(old_hashes, delta) != hashes:
            sys.exit("delta does not rebuild the list, not publishing")
        note["delta"] = dict(file_entry(delta), **{"from": old_note["seq"]})
    note_bytes = json.dumps(note, separators=(",", ":")).encode()

    seed = base64.b64decode(os.environ["FEED_SIGNING_KEY"].strip())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(seed)
    sig = key.sign(note_bytes)
    key.public_key().verify(sig, note_bytes)  # fail loudly here rather than on phones

    open(os.path.join(HERE, "block.bin"), "wb").write(data)
    open(os.path.join(HERE, "allow.bin"), "wb").write(allow_data)
    open(os.path.join(HERE, "apps.out.json"), "wb").write(apps_data)
    if delta is not None:
        open(os.path.join(HERE, "delta.bin"), "wb").write(delta)
    elif os.path.exists(os.path.join(HERE, "delta.bin")):
        os.remove(os.path.join(HERE, "delta.bin"))
    open(os.path.join(HERE, "feed.json"), "wb").write(note_bytes)
    open(os.path.join(HERE, "feed.json.sig"), "wb").write(base64.b64encode(sig))
    print("published seq", seq, "delta", len(delta) if delta else 0, "bytes")


if __name__ == "__main__":
    main()
