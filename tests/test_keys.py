#!/usr/bin/env python3
"""test_keys.py — integration test for the Key Weakness pass (--keys).

Covers the three finding classes end to end, all offline (no network):

  * DISCLOSURE — the vendored leaked/default public keys (data/keycorpus/: rapid7
    ssh-badkeys host + authorized keys, the Vagrant insecure key) are dropped into
    a scan tree; each must be reported as `leaked-key` with the host-vs-authorized
    impact wording. These are the exact .pub files gen_keycorpus.py fingerprinted,
    so the compiled-in corpus must match them.
  * GENERATION (ROCA) — a modulus is built by CRT so that n mod p lands in the
    <65537> subgroup for every ROCA small prime (a faithful CVE-2017-15361
    fingerprint), DER-encoded as an RSA public key; must be flagged `roca-key`.
    Pure Python bignum, no key material committed.
  * STRUCTURAL — 512/1024-bit RSA keys (openssl) must be flagged
    rsa-tiny/rsa-weak-modulus; a healthy 2048-bit key and a normal cert must be
    silent (no ROCA, no weakness) — the false-positive guard.

Plus a crash-safety sweep: truncations and byte-flip mutations of the fixtures in
the tree; the scan must complete with valid JSON and no crash.

openssl-dependent parts self-skip if openssl is absent; the corpus-match and ROCA
parts are pure Python and always run.

Usage: tests/test_keys.py [path/to/mithril]   (default: build/mithril)
"""
import base64
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS = os.path.join(ROOT, "data", "keycorpus")
random.seed(20260913)

ROCA_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
               79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167]


def der_len(n):
    if n < 0x80:
        return bytes([n])
    x = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(x)]) + x


def der_int(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + der_len(len(b)) + b


def rsa_pub_pem(n, e=65537):
    body = der_int(n) + der_int(e)
    seq = b"\x30" + der_len(len(body)) + body
    b64 = base64.b64encode(seq).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN RSA PUBLIC KEY-----\n" + lines + "\n-----END RSA PUBLIC KEY-----\n"


def _is_prime(n, k=20):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


def _next_prime(n):
    n |= 1
    while not _is_prime(n):
        n += 2
    return n


# --- EC small-scalar fixtures (the Oct 2026 eMudhra failure class) -----------
# Minimal pure-Python EC over the four curves mithril carries, to synthesize a
# public key Q = d*G for a tiny private scalar d and wrap it in a DER SPKI. No key
# material is committed; the points are computed at test time.
EC_CURVES = {
    # name: (p, a, b, Gx, Gy, curve_oid_der_hex, field_bytes)
    "prime256v1": (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, None,
        0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, "06082a8648ce3d030107", 32),
    "secp384r1": (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff, None,
        0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f, "06052b81040022", 48),
    "secp521r1": ((1 << 521) - 1, None,
        0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
        0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
        0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650, "06052b81040023", 66),
    "secp256k1": (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, 0, 7,
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, "06052b8104000a", 32),
}


def ec_mul(name, k):
    p, a, b, gx, gy, _oid, _fb = EC_CURVES[name]
    if a is None:
        a = p - 3
    def inv(x):
        return pow(x, p - 2, p)
    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        lam = ((3 * x1 * x1 + a) * inv(2 * y1) if P == Q else (y2 - y1) * inv((x2 - x1) % p)) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)
    R = None
    P = (gx, gy)
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R


def ec_spki_der(name, d):
    """DER SubjectPublicKeyInfo for Q = d*G on `name`."""
    p, a, b, gx, gy, oid, fb = EC_CURVES[name]
    x, y = ec_mul(name, d)
    point = b"\x04" + x.to_bytes(fb, "big") + y.to_bytes(fb, "big")
    algid = b"\x30" + der_len(9 + len(bytes.fromhex(oid))) + \
        bytes.fromhex("06072a8648ce3d0201") + bytes.fromhex(oid)
    bitstr = b"\x03" + der_len(len(point) + 1) + b"\x00" + point
    body = algid + bitstr
    return b"\x30" + der_len(len(body)) + body


def make_roca_modulus():
    """N with n mod p inside <65537 mod p> for every ROCA prime, ~2048-bit."""
    from math import prod
    mods = ROCA_PRIMES
    res = [pow(65537, i * 7 + 3, p) for i, p in enumerate(mods)]  # nontrivial subgroup members
    M = prod(mods)
    x = 0
    for a, m in zip(res, mods):
        Mi = M // m
        x += a * Mi * pow(Mi, -1, m)
    x %= M
    return x + ((1 << (2048 - x.bit_length())) + 12345) * M


def run_json(binary, tree):
    out = subprocess.check_output([binary, "-j", "--keys", tree])
    return json.loads(out)


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1

    have_openssl = bool(shutil.which("openssl"))
    fails = 0

    with tempfile.TemporaryDirectory() as d:
        tree = os.path.join(d, "rootfs")
        os.makedirs(os.path.join(tree, "etc", "ssh"))
        os.makedirs(os.path.join(tree, "root", ".ssh"))
        os.makedirs(os.path.join(tree, "etc", "ssl", "private"))

        # --- DISCLOSURE fixtures: vendored corpus keys, host + authorized ---
        leaked_expected = []  # (label_substring, key_use)
        host_src = os.path.join(CORPUS, "ssh-badkeys", "host", "Actiontec_q2000_rsa.pub")
        auth_src = os.path.join(CORPUS, "ssh-badkeys", "authorized", "f5-bigip-cve-2012-1493.pub")
        vagrant_src = os.path.join(CORPUS, "vagrant", "vagrant.pub")
        shutil.copy(host_src, os.path.join(tree, "etc", "ssh", "ssh_host_rsa_key.pub"))
        leaked_expected.append(("Actiontec", "host"))
        # authorized_keys carries the F5 and the Vagrant key (two lines).
        akeys = open(auth_src).read().strip() + "\n" + open(vagrant_src).read().strip() + "\n"
        open(os.path.join(tree, "root", ".ssh", "authorized_keys"), "w").write(akeys)
        leaked_expected.append(("f5 bigip", "authorized"))
        leaked_expected.append(("Vagrant", "authorized"))

        # --- GENERATION (ROCA) ---
        roca_n = make_roca_modulus()
        open(os.path.join(tree, "etc", "ssl", "roca_pub.pem"), "w").write(rsa_pub_pem(roca_n))

        # --- GENERATION (Phase 2: recovers the private key outright) ---
        # Fermat: N = p*q with p,q adjacent -> factored in a few steps.
        fp = _gen_prime(512)
        fq = _next_prime(fp + random.randrange(2, 2000))
        open(os.path.join(tree, "etc", "ssl", "fermat_pub.pem"), "w").write(rsa_pub_pem(fp * fq))
        # Wiener: small private exponent d -> large public exponent e (the u64-
        # overflow regression: a large e must NOT read as rsa-broken-exponent).
        while True:
            wp, wq = _gen_prime(512), _gen_prime(512)
            if wp == wq:
                continue
            phi = (wp - 1) * (wq - 1)
            wd = _next_prime(1 << 100)
            if __import__("math").gcd(wd, phi) == 1:
                we = pow(wd, -1, phi)
                break
        open(os.path.join(tree, "etc", "ssl", "wiener_pub.pem"), "w").write(rsa_pub_pem(wp * wq, we))
        # Batch-GCD: two moduli sharing a prime (cross-file) -> both factorable.
        sp = _gen_prime(512)
        open(os.path.join(tree, "etc", "ssl", "gcd_a_pub.pem"), "w").write(
            rsa_pub_pem(sp * _gen_prime(512)))
        open(os.path.join(tree, "root", "gcd_b_pub.pem"), "w").write(
            rsa_pub_pem(sp * _gen_prime(512)))

        # --- GENERATION (EC small-scalar: the eMudhra Oct 2026 failure class) ---
        # Q = d*G for a tiny d on each carried curve; the search must recover d.
        os.makedirs(os.path.join(tree, "etc", "ssl", "ec"))
        ec_expected = {}  # filename -> (curve, d)
        for name in EC_CURVES:
            for dd in (1, 5, 255):
                fn = f"ec_{name}_d{dd}.der"
                open(os.path.join(tree, "etc", "ssl", "ec", fn), "wb").write(ec_spki_der(name, dd))
                ec_expected[fn] = (name, dd)

        # --- Real eMudhra intermediates (vendored, public): all 8 are weak P-384
        #     keys, each must be flagged ec-small-scalar AND named via the corpus.
        emudhra_dir = os.path.join(CORPUS, "emudhra")
        emudhra_scalars = {  # the published private scalars (verified by recovery)
            "EMOVTLSCAG3C": 4, "EMEVTLSCAG3C": 56, "EMOVCSCAG3B": 66, "EMEVTLSCAG3B": 115,
            "EMOVTLSCAG3B": 155, "EMDVTLSCAG3B": 156, "EMDVTLSCAG3C": 230, "EMOVCSCAG3C": 237,
        }
        have_emudhra = os.path.isdir(emudhra_dir)
        if have_emudhra:
            os.makedirs(os.path.join(tree, "etc", "ssl", "emudhra"))
            for cn in os.listdir(emudhra_dir):
                if cn.endswith(".crt"):
                    shutil.copy(os.path.join(emudhra_dir, cn),
                                os.path.join(tree, "etc", "ssl", "emudhra", cn))

        # --- STRUCTURAL + false-positive fixtures (openssl) ---
        if have_openssl:
            # Healthy EC keys (real random scalars) -> must be silent (FP guard).
            for cname in ("prime256v1", "secp384r1"):
                subprocess.run(["openssl", "ecparam", "-name", cname, "-genkey", "-noout",
                                "-out", "ec_priv.pem"], cwd=d,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["openssl", "ec", "-in", "ec_priv.pem", "-pubout",
                                "-out", os.path.join(tree, "etc", "ssl", "ec", f"healthy_{cname}.pem")],
                               cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            def genrsa(bits, path):
                p = subprocess.run(["openssl", "genrsa", str(bits)], cwd=d,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                priv = os.path.join(d, "tmp_priv.pem")
                open(priv, "wb").write(p.stdout)
                subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", path],
                               cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            genrsa(512, os.path.join(tree, "etc", "ssl", "private", "tiny512_pub.pem"))
            genrsa(1024, os.path.join(tree, "etc", "ssl", "private", "weak1024_pub.pem"))
            genrsa(2048, os.path.join(tree, "etc", "ssl", "private", "healthy2048_pub.pem"))
            # A traditional-format DSA private key (GH #44): the key-weakness pass
            # must report it as DSA (dsa-weak-parameters), never as an RSA key.
            dsa_ok = False
            dparams = os.path.join(d, "dsap.pem")
            if subprocess.run(["openssl", "dsaparam", "-out", dparams, "1024"], cwd=d,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                dpk8 = os.path.join(d, "dsa_pk8.pem")
                subprocess.run(["openssl", "gendsa", "-out", dpk8, dparams], cwd=d,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                dtrad = os.path.join(tree, "etc", "ssl", "private", "dsa1024_key.pem")
                # Newer openssl emits PKCS#8 by default; -traditional forces the
                # legacy "DSA PRIVATE KEY" form. Fall back if the flag is absent.
                subprocess.run(["openssl", "dsa", "-in", dpk8, "-out", dtrad, "-traditional"],
                               cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if not (os.path.exists(dtrad) and b"DSA PRIVATE KEY" in open(dtrad, "rb").read()):
                    subprocess.run(["openssl", "dsa", "-in", dpk8, "-out", dtrad],
                                   cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                dsa_ok = os.path.exists(dtrad) and b"DSA PRIVATE KEY" in open(dtrad, "rb").read()
            # A normal self-signed 2048 cert -> must be silent.
            priv = os.path.join(d, "cert_priv.pem")
            subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], cwd=d,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-x509", "-key", priv, "-days", "1",
                            "-subj", "/CN=probe", "-out",
                            os.path.join(tree, "etc", "ssl", "healthy_cert.pem")],
                           cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # A weak (512-bit) cert wrapped in a UEFI EFI_SIGNATURE_LIST (as an
            # extracted PK/db variable): --keys must unwrap the list, parse the
            # cert, and flag the weak key.
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:512", "-nodes",
                            "-keyout", "/dev/null", "-subj", "/CN=uefi-weak", "-outform", "DER",
                            "-days", "1", "-out", "weakcert.der"],
                           cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wc = open(os.path.join(d, "weakcert.der"), "rb").read()
            x509_guid = bytes([0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A,
                               0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72])
            import struct
            sigsize = 16 + len(wc)
            esl = x509_guid + struct.pack("<III", 28 + sigsize, 0, sigsize) + b"\x00" * 16 + wc
            open(os.path.join(tree, "etc", "ssl", "uefi_pk.esl"), "wb").write(esl)

        rep = run_json(binary, tree)
        kw = rep.get("key_weakness", [])
        by_type = {}
        for h in kw:
            by_type.setdefault(h["type"], []).append(h)

        # --- DISCLOSURE assertions ---
        leaked = by_type.get("leaked-key", [])
        for sub, use in leaked_expected:
            hit = next((h for h in leaked if sub.lower() in h["label"].lower()), None)
            if not hit:
                print(f"FAIL: no leaked-key finding for {sub!r}")
                fails += 1
                continue
            want = ("impersonate" if use == "host" else "log in")
            if want not in hit.get("description", ""):
                print(f"FAIL: {sub!r} leaked-key impact wording missing {want!r}: "
                      f"{hit.get('description')!r}")
                fails += 1
            if hit.get("confidence_tier") != "validated":
                print(f"FAIL: {sub!r} leaked-key tier {hit.get('confidence_tier')} != validated")
                fails += 1

        # --- ROCA assertion ---
        roca = by_type.get("roca-key", [])
        if not any(h["path"].endswith("roca_pub.pem") for h in roca):
            print(f"FAIL: ROCA modulus not flagged roca-key (got {[h['path'] for h in roca]})")
            fails += 1
        for h in roca:
            if h.get("confidence_tier") != "validated":
                print(f"FAIL: roca-key tier {h.get('confidence_tier')} != validated")
                fails += 1

        # --- GENERATION Phase 2: Fermat / Wiener / batch-GCD (recover the key) ---
        def on(path_end, typ):
            return [h for h in by_type.get(typ, []) if h["path"].endswith(path_end)]
        if not on("fermat_pub.pem", "fermat-factorable"):
            print("FAIL: close-prime modulus not flagged fermat-factorable")
            fails += 1
        if not on("wiener_pub.pem", "wiener-weak"):
            print("FAIL: small-d key not flagged wiener-weak")
            fails += 1
        # Regression: a large public exponent must NOT be read as a broken (0) one.
        if on("wiener_pub.pem", "rsa-broken-exponent"):
            print("FAIL: large exponent misreported as rsa-broken-exponent (u64 overflow)")
            fails += 1
        # Batch-GCD flags BOTH members of the shared-prime pair, across files.
        if not (on("gcd_a_pub.pem", "shared-prime") and on("gcd_b_pub.pem", "shared-prime")):
            print("FAIL: shared-prime pair not both flagged by batch-GCD")
            fails += 1
        for h in by_type.get("fermat-factorable", []) + by_type.get("wiener-weak", []):
            if h.get("confidence_tier") != "validated":
                print(f"FAIL: {h['type']} tier {h.get('confidence_tier')} != validated")
                fails += 1

        # --- STRUCTURAL + false positives ---
        if have_openssl:
            def flagged(path_end, typ):
                return any(h["path"].endswith(path_end) for h in by_type.get(typ, []))
            if not flagged("tiny512_pub.pem", "rsa-tiny-modulus"):
                print("FAIL: 512-bit RSA not flagged rsa-tiny-modulus")
                fails += 1
            if not flagged("weak1024_pub.pem", "rsa-weak-modulus"):
                print("FAIL: 1024-bit RSA not flagged rsa-weak-modulus")
                fails += 1
            # GH #44: a traditional DSA key must be flagged as DSA, never RSA.
            if dsa_ok:
                if not flagged("dsa1024_key.pem", "dsa-weak-parameters"):
                    print("FAIL: 1024-bit DSA key not flagged dsa-weak-parameters")
                    fails += 1
                rsa_mis = [h for h in kw if h["path"].endswith("dsa1024_key.pem")
                           and h["type"].startswith("rsa-")]
                if rsa_mis:
                    print(f"FAIL: DSA key misparsed as RSA: {[h['type'] for h in rsa_mis]}")
                    fails += 1
            # False positives: the healthy 2048 key/cert must produce no finding.
            for bad in ("healthy2048_pub.pem", "healthy_cert.pem"):
                hits = [h for h in kw if h["path"].endswith(bad)]
                if hits:
                    print(f"FAIL: false positive on {bad}: {[h['type'] for h in hits]}")
                    fails += len(hits)
            # ROCA must not fire on the healthy key.
            if any(h["path"].endswith("healthy2048_pub.pem") for h in roca):
                print("FAIL: ROCA false positive on a healthy 2048-bit key")
                fails += 1
            # UEFI EFI_SIGNATURE_LIST unwrap: the wrapped 512-bit cert is flagged.
            if not on("uefi_pk.esl", "rsa-tiny-modulus"):
                print("FAIL: weak key inside an EFI_SIGNATURE_LIST not flagged (unwrap failed)")
                fails += 1

        # --- EC small-scalar assertions ---
        import re as _re
        ess = by_type.get("ec-small-scalar", [])
        def recovered_d(h):
            m = _re.search(r"d=(\d+)", h.get("evidence", ""))
            return int(m.group(1)) if m else None
        # Synthetic Q = d*G on each curve: recovered d must match, tier validated.
        for fn, (cname, dd) in ec_expected.items():
            hit = next((h for h in ess if h["path"].endswith(fn)), None)
            if not hit:
                print(f"FAIL: {fn} ({cname} d={dd}) not flagged ec-small-scalar")
                fails += 1
            elif recovered_d(hit) != dd:
                print(f"FAIL: {fn} recovered d={recovered_d(hit)} != {dd}")
                fails += 1
            elif hit.get("confidence_tier") != "validated":
                print(f"FAIL: {fn} ec-small-scalar tier {hit.get('confidence_tier')} != validated")
                fails += 1
        # Healthy EC keys (openssl) must be silent — the false-positive guard.
        if have_openssl:
            for bad in ("healthy_prime256v1.pem", "healthy_secp384r1.pem"):
                hits = [h for h in kw if h["path"].endswith(bad)]
                if hits:
                    print(f"FAIL: EC false positive on {bad}: {[h['type'] for h in hits]}")
                    fails += len(hits)
        # Real eMudhra intermediates: every one flagged, with the right scalar, and
        # also named by the leaked-key corpus (identity + mechanism).
        if have_emudhra:
            leaked = by_type.get("leaked-key", [])
            for cn, scalar in emudhra_scalars.items():
                fn = cn + ".crt"
                hit = next((h for h in ess if h["path"].endswith(fn)), None)
                if not hit:
                    print(f"FAIL: eMudhra {cn} not flagged ec-small-scalar")
                    fails += 1
                elif recovered_d(hit) != scalar:
                    print(f"FAIL: eMudhra {cn} recovered d={recovered_d(hit)} != {scalar}")
                    fails += 1
                if not any(h["path"].endswith(fn) and "emudhra" in h["label"].lower()
                           for h in leaked):
                    print(f"FAIL: eMudhra {cn} not named by the leaked-key corpus")
                    fails += 1

        # --- crash safety: truncations + mutations in the tree, must not crash ---
        fuzz = os.path.join(tree, "fuzz")
        os.mkdir(fuzz)
        seed = rsa_pub_pem(roca_n).encode()
        for L in range(1, len(seed), 7):
            open(os.path.join(fuzz, f"t{L}.bin"), "wb").write(seed[:L])
        for it in range(200):
            b = bytearray(seed)
            for _ in range(random.randint(1, 8)):
                b[random.randrange(len(b))] = random.randrange(256)
            open(os.path.join(fuzz, f"m{it}.bin"), "wb").write(bytes(b))
        open(os.path.join(fuzz, "random.bin"), "wb").write(random.randbytes(64 * 1024))
        try:
            run_json(binary, tree)  # raises on crash / invalid JSON
        except Exception as ex:
            print(f"FAIL: crash/invalid JSON on fuzz sweep: {ex}")
            fails += 1

        if fails == 0:
            n_leaked = len(leaked_expected)
            extra = "" if have_openssl else " (openssl absent: structural/FP skipped)"
            em = ", 8 real eMudhra P-384 keys recovered" if have_emudhra else ""
            print(f"PASS: {n_leaked} leaked/default keys matched (host+authorized impact), "
                  f"ROCA + Fermat + Wiener + batch-GCD recoveries detected, EC small-scalar "
                  f"across 4 curves (synthetic{em}) + EC false-positive guard, structural bands + "
                  f"false-positive guard, crash-safe over truncations/mutations{extra}")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
