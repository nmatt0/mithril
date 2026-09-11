#!/usr/bin/env python3
"""test_der_keys.py — integration test for the raw DER private-key scanner.

Generates real private keys with openssl in every DER encoding and algorithm
the scanner targets, embeds each PEM-less in a binary blob with non-text
padding, runs mithril with `-j --secrets`, and asserts every key is reported as
a `der-private-key` at its exact offset with the right label and tier.

Three parts:
  * COVERAGE  — RSA (PKCS#8 + traditional PKCS#1, 1024/2048/4096), EC (PKCS#8 +
    SEC1, secp256r1/384r1/521r1/secp256k1), and Ed25519/Ed448/X25519/X448
    (PKCS#8). Every combination the scanner claims, each detected exactly once.
  * FALSE POSITIVES — real non-key DER that the anchors will land inside of:
    X.509 certs (v3 + serial 0), SubjectPublicKeyInfo public keys, an encrypted
    PKCS#8 key, a DSA private key (unsupported algorithm), a multi-cert bundle,
    plus 32 KiB of random and the original class-name / lone-anchor bait. Any
    der-private-key finding on these is a bug.
  * CRASH SAFETY — every truncation of each key and a few hundred byte-flip
    mutations, dropped into the scan tree; the scan must complete (no crash,
    valid JSON) and report no key on the deliberately-broken truncations.

Self-skips if openssl is absent. No network, no committed fixtures.

Note on openssl: `genpkey -algorithm RSA -outform DER` emits *traditional
PKCS#1*, not PKCS#8. A genuine PKCS#8 RSA key (the code path that reads the
modulus size out of the inner OCTET STRING) requires wrapping with
`pkcs8 -topk8 -nocrypt`, which this test does.

Usage: tests/test_der_keys.py [path/to/mithril]   (default: build/mithril)
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAD = bytes(range(256)) * 8  # 2 KiB non-text, non-DER filler between samples

random.seed(20260910)


def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def gen_positives(d):
    """Generate keys the scanner must detect. Returns [(filename, label)]."""
    out = []

    # RSA: genuine PKCS#8 (wrapped) + traditional PKCS#1, three sizes.
    for bits in (1024, 2048, 4096):
        _run(["openssl", "genpkey", "-algorithm", "RSA",
              "-pkeyopt", f"rsa_keygen_bits:{bits}", "-out", f"rsa{bits}.pem"], d)
        _run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", f"rsa{bits}.pem",
              "-outform", "DER", "-out", f"rsa{bits}_pkcs8.der"], d)
        _run(["openssl", "rsa", "-in", f"rsa{bits}.pem", "-traditional",
              "-outform", "DER", "-out", f"rsa{bits}_pkcs1.der"], d)
        out.append((f"rsa{bits}_pkcs8.der", f"RSA-{bits} private key"))
        out.append((f"rsa{bits}_pkcs1.der", f"RSA-{bits} private key"))

    # EC: PKCS#8 + traditional SEC1, four curves.
    for curve, label in (("prime256v1", "secp256r1"), ("secp384r1", "secp384r1"),
                         ("secp521r1", "secp521r1"), ("secp256k1", "secp256k1")):
        _run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
              f"ec_paramgen_curve:{curve}", "-outform", "DER", "-out", f"ec_{curve}_pkcs8.der"], d)
        _run(["openssl", "ecparam", "-genkey", "-name", curve, "-outform", "DER",
              "-out", f"ec_{curve}_sec1.der"], d)
        out.append((f"ec_{curve}_pkcs8.der", f"EC {label} private key"))
        out.append((f"ec_{curve}_sec1.der", f"EC {label} private key"))

    # Modern EdDSA / X-family, all PKCS#8.
    for alg, label in (("ED25519", "Ed25519"), ("ED448", "Ed448"),
                       ("X25519", "X25519"), ("X448", "X448")):
        _run(["openssl", "genpkey", "-algorithm", alg, "-outform", "DER",
              "-out", f"{alg.lower()}.der"], d)
        out.append((f"{alg.lower()}.der", f"{label} private key"))

    return out


def gen_negatives(d):
    """Generate non-key DER that must NOT be flagged. Returns [(filename, note)]."""
    out = []
    _run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
          "ec_paramgen_curve:prime256v1", "-out", "seed_ec.pem"], d)
    _run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
          "rsa_keygen_bits:2048", "-out", "seed_rsa.pem"], d)

    for key, tag in (("seed_ec.pem", "ec"), ("seed_rsa.pem", "rsa")):
        _run(["openssl", "req", "-x509", "-key", key, "-days", "1",
              "-subj", f"/CN=probe-{tag}", "-outform", "DER", "-out", f"cert_{tag}_v3.der"], d)
        out.append((f"cert_{tag}_v3.der", f"X.509 v3 cert ({tag})"))
        _run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER",
              "-out", f"pub_{tag}.der"], d)
        out.append((f"pub_{tag}.der", f"public key SPKI ({tag})"))

    # Cert with serial 0 -> the byte run 02 01 00 30 (== the PKCS#8 anchor) sits
    # right where a v1 tbsCertificate would begin. Must still not parse as a key.
    _run(["openssl", "req", "-x509", "-key", "seed_rsa.pem", "-days", "1",
          "-set_serial", "0", "-subj", "/CN=serial0", "-outform", "DER",
          "-out", "cert_serial0.der"], d)
    out.append(("cert_serial0.der", "X.509 cert, serial 0"))

    # Encrypted PKCS#8 (EncryptedPrivateKeyInfo): first element is a SEQUENCE,
    # not INTEGER 0 -> classify() rejects it. Not a usable key regardless.
    _run(["openssl", "pkcs8", "-topk8", "-in", "seed_rsa.pem", "-passout", "pass:probe",
          "-outform", "DER", "-out", "enc_pkcs8.der"], d)
    out.append(("enc_pkcs8.der", "encrypted PKCS#8"))

    # DSA private key (unsupported algorithm). Traditional form is version 0 + 5
    # INTEGERs, so its p INTEGER trips the PKCS#1 anchor but must fail the
    # exactly-9-INTEGERs structural check.
    try:
        _run(["openssl", "genpkey", "-genparam", "-algorithm", "DSA",
              "-pkeyopt", "dsa_paramgen_bits:1024", "-out", "dsaparam.pem"], d)
        _run(["openssl", "genpkey", "-paramfile", "dsaparam.pem", "-out", "dsa.pem"], d)
        _run(["openssl", "dsa", "-in", "dsa.pem", "-outform", "DER", "-out", "dsa_trad.der"], d)
        out.append(("dsa_trad.der", "DSA private key, traditional (unsupported alg)"))
    except subprocess.CalledProcessError:
        pass  # some builds restrict DSA; skip rather than fail

    # A concatenated cert bundle (ca-certificates.crt style).
    with open(os.path.join(d, "bundle.der"), "wb") as f:
        for name in ("cert_ec_v3.der", "cert_rsa_v3.der", "cert_serial0.der"):
            f.write(open(os.path.join(d, name), "rb").read())
    out.append(("bundle.der", "3-cert DER bundle"))

    # 32 KiB random: the 4-6 byte anchors appear by chance; parse must reject all.
    with open(os.path.join(d, "random.bin"), "wb") as f:
        f.write(random.randbytes(32 * 1024))
    out.append(("random.bin", "32 KiB random"))

    return out


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1
    if not shutil.which("openssl"):
        print("SKIP: openssl not installed (needed to generate DER key fixtures)")
        return 0

    with tempfile.TemporaryDirectory() as d:
        pos = gen_positives(d)
        neg = gen_negatives(d)

        # firmware.bin: every positive key at a recorded offset, PEM-less.
        blob = bytearray()
        expected = {}  # offset -> label
        for fn, label in pos:
            blob += PAD
            off = len(blob)
            blob += open(os.path.join(d, fn), "rb").read()
            expected[off] = label
        blob += PAD
        open(os.path.join(d, "firmware.bin"), "wb").write(blob)

        # negatives.bin: real non-key DER back to back + the original bait.
        nblob = bytearray()
        for fn, _ in neg:
            nblob += PAD
            nblob += open(os.path.join(d, fn), "rb").read()
        nblob += PAD
        nblob += b"com.example.crypto.RSAPrivateKeyImpl loadDerPrivateKey PRIVATE KEY\x00"
        nblob += bytes([0x02, 0x01, 0x00, 0x30, 0xEE, 0xEE]) + bytes(range(256)) * 4
        open(os.path.join(d, "negatives.bin"), "wb").write(nblob)

        # crash-safety corpus: every truncation of a few keys + byte-flip
        # mutations, each its own file, all scanned in the one invocation below.
        fuzz = os.path.join(d, "fuzz")
        os.mkdir(fuzz)
        seeds = [open(os.path.join(d, f), "rb").read()
                 for f in ("ec_prime256v1_sec1.der", "ed25519.der", "rsa1024_pkcs1.der")]
        trunc_files = 0
        for si, s in enumerate(seeds):
            for L in range(1, len(s)):
                open(os.path.join(fuzz, f"t{si}_{L}.bin"), "wb").write(s[:L])
                trunc_files += 1
        for it in range(400):
            b = bytearray(random.choice(seeds))
            for _ in range(random.randint(1, 8)):
                b[random.randrange(len(b))] = random.randrange(256)
            open(os.path.join(fuzz, f"m{it}.bin"), "wb").write(bytes(b))

        # One invocation over the whole tree. If the scanner crashes on any file
        # (incl. the fuzz corpus) this raises and the test fails.
        rep = json.loads(subprocess.check_output([binary, "-j", "--secrets", d]))
        der = [h for h in rep["secrets"] if h["type"] == "der-private-key"]
        by_path = {}
        for h in der:
            by_path.setdefault(h["path"], []).append(h)

        fails = 0

        # --- coverage: each expected key found once, right label + tier ---
        fw = {h["offset"]: h for h in by_path.get("firmware.bin", [])}
        for off, label in expected.items():
            h = fw.get(off)
            if not h:
                print(f"FAIL: no der-private-key at offset {off} (expected {label})")
                fails += 1
            elif h["label"] != label:
                print(f"FAIL: offset {off}: label {h['label']!r} != expected {label!r}")
                fails += 1
            elif h.get("confidence_tier") != "structural":
                print(f"FAIL: offset {off}: tier {h.get('confidence_tier')} != structural")
                fails += 1
        # exact-once: no extra/duplicate hits (PKCS#8 wrapper vs nested PKCS#1)
        extra = [h for h in by_path.get("firmware.bin", []) if h["offset"] not in expected]
        for h in extra:
            print(f"FAIL: unexpected der-private-key in firmware.bin @ {h['offset']}: {h['label']!r}")
        fails += len(extra)
        if len(by_path.get("firmware.bin", [])) != len(expected):
            print(f"FAIL: expected {len(expected)} keys in firmware.bin, "
                  f"got {len(by_path.get('firmware.bin', []))}")
            fails += 1

        # --- false positives: nothing in negatives.bin or any negative fixture ---
        fp = by_path.get("negatives.bin", [])
        if fp:
            print(f"FAIL: {len(fp)} false positive(s) in negatives.bin: "
                  f"{[h['label'] for h in fp]}")
            fails += len(fp)

        # --- crash safety: no key reported on any truncated file (all broken) ---
        trunc_hits = [p for p in by_path if p.startswith("fuzz/t")]
        if trunc_hits:
            print(f"FAIL: der-private-key on truncated input(s): {trunc_hits}")
            fails += len(trunc_hits)

        if fails == 0:
            print(f"PASS: {len(expected)} DER keys across RSA/EC/Ed/X in "
                  f"PKCS#8/PKCS#1/SEC1 detected once each; {len(neg)} non-key DER "
                  f"structures + {trunc_files} truncations + 400 mutations, zero "
                  f"false positives, no crash")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
