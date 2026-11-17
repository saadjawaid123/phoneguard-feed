# phoneguard-feed

The signed list of known scam and malware websites that the PhoneGuard app downloads once a day.

- `block.bin` holds fingerprints (hashes) of website names. No user data, no messages, no phone details.
- `feed.json` describes the list. `feed.json.sig` is its Ed25519 signature. The app uses a list only
  when the signature matches the public key built into the app and the file matches the note.
- `build_feed.py` builds and signs it every day in GitHub Actions. The signing key is a repository
  secret. It is not in this repository.

Sources and licences: Phishing.Database (MIT), URLhaus by abuse.ch (CC0), and our own reviewed list
(`own-block.txt`). The 10,000 most visited websites (`never-block.txt`, from the Tranco list) are
always removed, so a mistake in a source cannot flag a famous website.

Other files:
- `delta.bin` is the change since the previous list, so phones download a few bytes instead of 3 MB.
- `allow.bin` is built from `own-allow.txt`: websites PhoneGuard never calls a scam.
- `apps.out.json` is the checked copy of `apps.json`: official apps and their signing keys for App
  Authenticity Check. Add a key only after reading it from a real install from Google Play.
- `import_reports.py` (weekly) turns user reports into a pull request. Merging it is the review.

Found a wrong entry? Open an issue with the website name.
