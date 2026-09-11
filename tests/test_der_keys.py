#!/usr/bin/env python3
"""test_der_keys.py — integration test for the raw DER private-key scanner.

Generates real private keys with openssl in every DER encoding the scanner
targets (PKCS#8, PKCS#1, SEC1) across RSA / EC / Ed25519, embeds each in a
binary blob with non-text padding and NO PEM wrapper, runs the mithril binary
with `-j --secrets`, and asserts every key is reported as a `der-private-key`
at its exact offset with the right algorithm label — and that key-shaped bait
(class names, a lone anchor) produces no finding. Self-skips if openssl is
absent. No network, no committed fixtures.

Usage: tests/test_der_keys.py [path/to/mithril]   (default: build/mithril)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def gen_keys(d):
    """Generate DER keys with openssl. Returns [(filename, expected_label)]."""
    def sh(cmd):
        subprocess.run(cmd, cwd=d, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # PKCS#8 (genpkey default), plus traditional PKCS#1 / SEC1 via -traditional.
    sh(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
        "-outform", "DER", "-out", "rsa_pkcs8.der"])
    sh(["bash", "-c", "openssl genrsa 2048 2>/dev/null | "
        "openssl rsa -traditional -outform DER -out rsa_pkcs1.der 2>/dev/null"])
    sh(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-outform", "DER", "-out", "ec256_pkcs8.der"])
    sh(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-outform", "DER",
        "-out", "ec256_sec1.der"])
    sh(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1",
        "-outform", "DER", "-out", "ec384_pkcs8.der"])
    sh(["openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER", "-out", "ed25519.der"])
    return [
        ("rsa_pkcs8.der", "RSA-2048 private key"),
        ("rsa_pkcs1.der", "RSA-2048 private key"),
        ("ec256_pkcs8.der", "EC secp256r1 private key"),
        ("ec256_sec1.der", "EC secp256r1 private key"),
        ("ec384_pkcs8.der", "EC secp384r1 private key"),
        ("ed25519.der", "Ed25519 private key"),
    ]


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1
    if not shutil.which("openssl"):
        print("SKIP: openssl not installed (needed to generate DER key fixtures)")
        return 0

    with tempfile.TemporaryDirectory() as d:
        keys = gen_keys(d)

        # One binary "firmware image": each key wrapped in non-text padding, PEM-less.
        pad = bytes(range(256)) * 8
        blob = bytearray()
        expected = {}  # offset -> label
        for fn, label in keys:
            blob += pad
            off = len(blob)
            blob += open(os.path.join(d, fn), "rb").read()
            expected[off] = label
        blob += pad
        fw = os.path.join(d, "firmware.bin")
        open(fw, "wb").write(blob)

        # Bait that must NOT fire: key-ish class names + a lone anchor + random.
        neg = bytearray(pad)
        neg += b"com.example.crypto.RSAPrivateKeyImpl loadDerPrivateKey PRIVATE KEY\x00"
        neg += bytes([0x02, 0x01, 0x00, 0x30, 0xEE, 0xEE]) + bytes(range(256)) * 4
        open(os.path.join(d, "negative.bin"), "wb").write(neg)

        rep = json.loads(subprocess.check_output([binary, "-j", "--secrets", d]))
        der = [h for h in rep["secrets"] if h["type"] == "der-private-key"]
        fails = 0

        by_off = {h["offset"]: h for h in der if h["path"] == "firmware.bin"}
        for off, label in expected.items():
            h = by_off.get(off)
            if not h:
                print(f"FAIL: no der-private-key at offset {off} (expected {label})")
                fails += 1
            elif h["label"] != label:
                print(f"FAIL: offset {off}: label {h['label']!r} != expected {label!r}")
                fails += 1
            elif h.get("confidence_tier") != "structural":
                print(f"FAIL: offset {off}: tier {h.get('confidence_tier')} != structural")
                fails += 1

        # Each key counted exactly once (PKCS#8 wrapper not double-reported with its
        # nested PKCS#1) — one finding per embedded key.
        fw_hits = [h for h in der if h["path"] == "firmware.bin"]
        if len(fw_hits) != len(expected):
            print(f"FAIL: expected {len(expected)} keys in firmware.bin, got {len(fw_hits)}")
            fails += 1

        if any(h["path"] == "negative.bin" for h in der):
            print("FAIL: false positive in negative.bin (key-shaped bait matched)")
            fails += 1

        if fails == 0:
            print(f"PASS: {len(fw_hits)} DER keys detected across encodings "
                  f"(PKCS#8/PKCS#1/SEC1; RSA/EC/Ed25519), zero false positives")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
