#!/usr/bin/env python3
"""Turns PhoneGuard user reports into a review pull request. Nothing reaches the signed list unreviewed.

Reads Firestore (project phoneguard-2489a) with a service account (secret FIREBASE_SA, JSON):
  flagged/{site}        "Report scam" on a website     -> own-block.txt  when votes >= MIN_SCAM
  wrongwarn/{site}      "Wrong warning" on a website   -> own-allow.txt  when votes >= MIN_WRONG
  scamnumbers/{number}  "Report scam" on a number      -> only counted here. This repository is public, and a
                        wrongly reported number may belong to a real person, so numbers stay in Firestore.
Only new names are added. Famous websites (never-block.txt) are never added to own-block.txt.
The workflow opens a pull request with the changes; merging it is the review. After the merge the
daily build signs the new list.
"""
import json, os, sys, urllib.request

PROJECT = os.environ.get("FIREBASE_PROJECT", "phoneguard-2489a")
MIN_SCAM, MIN_WRONG, MIN_NUMBER = 3, 2, 3
HERE = os.path.dirname(os.path.abspath(__file__))


def token():
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request
    info = json.loads(os.environ["FIREBASE_SA"])
    cred = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/datastore"])
    cred.refresh(Request())
    return cred.token


def docs(tok, collection):
    out, page = [], ""
    while True:
        url = (f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents/"
               f"{collection}?pageSize=300" + (f"&pageToken={page}" if page else ""))
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok})
        with urllib.request.urlopen(req, timeout=60) as r:
            o = json.load(r)
        for d in o.get("documents", []):
            f = d.get("fields", {})
            votes = int(f.get("votes", {}).get("integerValue", "0"))
            out.append((d["name"].rsplit("/", 1)[1], votes))
        page = o.get("nextPageToken", "")
        if not page:
            return out


def existing(name):
    p = os.path.join(HERE, name)
    if not os.path.exists(p):
        return set()
    return {l.strip().lower() for l in open(p) if l.strip() and not l.startswith("#")}


def append(name, items, note):
    if not items:
        return 0
    with open(os.path.join(HERE, name), "a") as f:
        f.write(f"# {note}\n")
        for i in sorted(items):
            f.write(i + "\n")
    return len(items)


def main():
    if not os.environ.get("FIREBASE_SA", "").strip():
        print("no FIREBASE_SA secret: skipped")
        return
    tok = token()
    never = existing("never-block.txt")
    block, allow = existing("own-block.txt"), existing("own-allow.txt")
    new_block = {s for s, v in docs(tok, "flagged") if v >= MIN_SCAM and s not in block and s not in never and s not in allow}
    new_allow = {s for s, v in docs(tok, "wrongwarn") if v >= MIN_WRONG and s not in allow}
    numbers = sum(1 for _, v in docs(tok, "scamnumbers") if v >= MIN_NUMBER)
    # A site that is both reported and called a wrong warning needs a human: it goes to neither list.
    both = new_block & new_allow
    new_block -= both
    new_allow -= both
    a = append("own-block.txt", new_block, "from user reports, check each one before merging")
    b = append("own-allow.txt", new_allow, "from wrong-warning reports, check each owner before merging")
    append("review/conflicts.txt", both, "reported as scam AND as wrong warning: decide by hand")
    print(f"added: block {a}, allow {b}, conflicts {len(both)}; scam numbers with {MIN_NUMBER}+ votes: {numbers}")


if __name__ == "__main__":
    main()
