#!/usr/bin/env python3
"""Builds and signs the PhoneGuard scam website list.

Output (all in this folder):
  block.bin       4-byte count, then sorted 64-bit FNV-1a fingerprints of website names (big-endian)
  feed.json       the note: version, sequence number, time made, SHA-256 and size of block.bin
  feed.json.sig   Ed25519 signature of feed.json (base64). The app checks it with its public key.

Sources:
  own-block.txt                     our own reviewed list
  Phishing.Database ACTIVE domains  MIT licence
  URLhaus host file (abuse.ch)      CC0
never-block.txt (the 10,000 most visited sites) is removed from every source, so a mistake in a
public feed can never make the app call a famous website a scam.

The signing key comes from the environment (FEED_SIGNING_KEY, base64 of the 32-byte seed).
It is a GitHub Actions secret and is never written to disk or printed.
"""
import base64, hashlib, json, os, struct, sys, time, urllib.request
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = [
    ("phishing-database", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", True),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", False),
]
MIN_TOTAL = 50_000      # fewer than this means a source broke: do not publish
MAX_TOTAL = 2_500_000   # keeps block.bin under the app's 24 MB limit
MAX_SHRINK = 0.5        # refuse a list less than half the size of the last one
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


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "phoneguard-feed"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", errors="ignore")


def main():
    never = {l.strip().lower() for l in open(os.path.join(HERE, "never-block.txt")) if l.strip()}
    block, counts = set(), {}

    def add_all(name, text):
        n = 0
        for h in lines_of(text):
            h = clean(h)
            if h and h not in never:
                block.add(h)
                n += 1
        counts[name] = n

    add_all("own", open(os.path.join(HERE, "own-block.txt")).read())
    for name, url, required in SOURCES:
        try:
            add_all(name, fetch(url))
        except Exception as e:  # one broken source must not stop the others
            print(f"source {name} failed: {e}")
            if required:
                sys.exit(f"required source {name} failed, not publishing")

    hashes = sorted({fnv(h) for h in block})
    print("counts", counts, "total", len(hashes))
    if not MIN_TOTAL <= len(hashes) <= MAX_TOTAL:
        sys.exit(f"list size {len(hashes)} is outside {MIN_TOTAL}..{MAX_TOTAL}, not publishing")

    old_path = os.path.join(HERE, "block.bin")
    if os.path.exists(old_path):
        old = struct.unpack(">i", open(old_path, "rb").read(4))[0]
        if len(hashes) < old * MAX_SHRINK:
            sys.exit(f"list shrank from {old} to {len(hashes)}, not publishing")

    data = struct.pack(">i", len(hashes)) + b"".join(struct.pack(">q", h) for h in hashes)
    if os.path.exists(old_path) and open(old_path, "rb").read() == data:
        print("no change")
        return

    note = json.dumps({
        "v": 1,
        "seq": int(time.time()),
        "made": int(time.time()),
        "block": {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)},
        "sources": counts,
    }, separators=(",", ":")).encode()

    seed = base64.b64decode(os.environ["FEED_SIGNING_KEY"].strip())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(seed)
    sig = key.sign(note)
    key.public_key().verify(sig, note)  # fail loudly here rather than on phones

    open(old_path, "wb").write(data)
    open(os.path.join(HERE, "feed.json"), "wb").write(note)
    open(os.path.join(HERE, "feed.json.sig"), "wb").write(base64.b64encode(sig))
    print("published seq", json.loads(note)["seq"])


if __name__ == "__main__":
    main()
