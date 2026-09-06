#!/usr/bin/env python3
"""test_secrets.py — self-contained integration test for the secrets pass.

Builds a synthetic rootfs with known planted credentials (and known
false-positive bait), runs the mithril binary with `-j`, and asserts the JSON
report finds exactly the planted secrets and none of the bait. No network, no
committed fixtures — the tree is generated fresh in a tempdir each run.

Usage: tests/test_secrets.py [path/to/mithril]   (default: build/mithril)
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def build_tree(d):
    """Plant a set of secrets; return the set of (relpath, type) expected."""
    os.makedirs(os.path.join(d, "etc"))
    os.makedirs(os.path.join(d, "app"))
    os.makedirs(os.path.join(d, "bin"))

    with open(os.path.join(d, "etc/app.conf"), "w") as f:
        f.write("db_password = S3cr3t_Pa55w0rd_9xQ7zLmNq\n")
        f.write("aws_key = AKIAJ2K3L4M5N6P7Q8R9\n")
        f.write("github_token = ghp_0123456789abcdefghijklmNOPQRSTUVwxyz\n")

    with open(os.path.join(d, "app/config.js"), "w") as f:
        # Split literal so secret scanners don't flag this synthetic fixture; runtime value is unchanged.
        f.write('const stripe = "sk_live_' + '0123456789abcdefABCDEF01";\n')
        f.write('const google = "AIzaabcdefghijklmnopqrstuvwxyz012345678";\n')
        # canonical AWS example key: must be filtered as a false positive.
        f.write('const demo = "AKIAIOSFODNN7EXAMPLE";\n')

    with open(os.path.join(d, "etc/id_rsa"), "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        f.write("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n")
        f.write("-----END OPENSSH PRIVATE KEY-----\n")

    # A base64 config blob hiding an AWS key (decode-then-scan path).
    blob = base64.b64encode(b"cred AKIAZZ9Y8X7W6V5U4T3S tail").decode()
    with open(os.path.join(d, "app/settings.b64"), "w") as f:
        f.write("payload = " + blob + "\n")

    # High-entropy binary: must be skipped by the text-ish gate (no findings).
    with open(os.path.join(d, "bin/busybox"), "wb") as f:
        f.write(os.urandom(8192))

    return {
        ("etc/app.conf", "generic-secret"),
        ("etc/app.conf", "aws-access-key-id"),
        ("etc/app.conf", "github-token"),
        ("app/config.js", "stripe-key"),
        ("app/config.js", "google-api-key"),
        ("etc/id_rsa", "private-key"),
        ("app/settings.b64", "aws-access-key-id"),
    }


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1

    with tempfile.TemporaryDirectory() as d:
        expected = build_tree(d)
        out = subprocess.check_output([binary, "-j", "--secrets", d])
        rep = json.loads(out)

        got = {(h["path"], h["type"]) for h in rep["secrets"]}
        fails = 0

        missing = expected - got
        if missing:
            print(f"FAIL: expected secrets not found: {sorted(missing)}")
            fails += 1

        # The canonical example key must never appear.
        for h in rep["secrets"]:
            if h["type"] == "aws-access-key-id" and "IOSF" in h.get("label", ""):
                print(f"FAIL: canonical AWS example key was not filtered: {h}")
                fails += 1

        # Every secret must be UNVERIFIED (offline pass makes no network calls).
        # Every secret must carry a confidence tier from the offline ladder.
        for h in rep["secrets"]:
            if h.get("confidence_tier") not in ("pattern", "structural", "validated"):
                print(f"FAIL: secret missing a valid confidence tier: {h}")
                fails += 1

        # The base64-hidden key must record its encoding basis.
        b64_hit = [h for h in rep["secrets"]
                   if h["path"] == "app/settings.b64" and h["type"] == "aws-access-key-id"]
        if not b64_hit or "base64" not in b64_hit[0]["evidence"]:
            print(f"FAIL: base64-encoded secret not attributed to base64: {b64_hit}")
            fails += 1

        # The private-key file must also be flagged as a notable file (M1 path rule).
        notable = {(h["path"], h["type"]) for h in rep.get("notable", [])}
        if ("etc/id_rsa", "ssh-private-key") not in notable:
            print(f"FAIL: id_rsa not flagged as a notable file: {sorted(notable)}")
            fails += 1

        if rep["file_count"] != 5:
            print(f"FAIL: expected 5 files scanned, got {rep['file_count']}")
            fails += 1

        if fails == 0:
            print(f"PASS: {len(got)} secrets across {rep['file_count']} files, "
                  f"canonical example filtered, id_rsa flagged notable")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
