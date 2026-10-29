#!/usr/bin/env python3
"""test_sbom.py — integration test for the SBOM pass.

Builds a synthetic rootfs with a dpkg status DB (installed + not-installed
entries) and an apk installed DB, runs `mithril -j --sbom -C <out>`, and checks
the component set, the not-installed exclusion, and that the emitted CycloneDX
and SPDX files parse and carry the same components.

Usage: tests/test_sbom.py [path/to/mithril]   (default: build/mithril)
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

DPKG_STATUS = """\
Package: busybox
Status: install ok installed
Version: 1:1.30.1-6+deb10u1
Architecture: armhf
Description: tiny utils

Package: openssl
Status: install ok installed
Version: 1.1.1n-0+deb10u3
Architecture: armhf

Package: purged
Status: purge ok not-installed
Version: 9.9
"""

APK_INSTALLED = """\
C:Q1abc
P:musl
V:1.2.4-r2
A:x86_64
L:MIT

P:dropbear
V:2022.83-r0
A:x86_64
L:MIT
"""


def build_tree(d):
    os.makedirs(os.path.join(d, "etc"))
    with open(os.path.join(d, "etc/os-release"), "w") as f:
        f.write("ID=alpine\nVERSION_ID=3.20\n")
    os.makedirs(os.path.join(d, "var/lib/dpkg"))
    os.makedirs(os.path.join(d, "lib/apk/db"))
    with open(os.path.join(d, "var/lib/dpkg/status"), "w") as f:
        f.write(DPKG_STATUS)
    with open(os.path.join(d, "lib/apk/db/installed"), "w") as f:
        f.write(APK_INSTALLED)


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1

    with tempfile.TemporaryDirectory() as d:
        rootfs = os.path.join(d, "rootfs")
        outdir = os.path.join(d, "out")
        os.makedirs(rootfs)
        build_tree(rootfs)

        out = subprocess.check_output([binary, "-j", "--sbom", "-C", outdir, rootfs],
                                      stderr=subprocess.DEVNULL)
        rep = json.loads(out)
        names = {c["name"] for c in rep["components"]}
        by_name = {c["name"]: c for c in rep["components"]}
        fails = 0

        expected = {"busybox", "openssl", "musl", "dropbear"}
        if names != expected:
            print(f"FAIL: component set {names} != {expected}")
            fails += 1
        if "purged" in names:
            print("FAIL: not-installed dpkg package leaked into the SBOM")
            fails += 1

        # purl shape.
        if by_name.get("busybox", {}).get("purl") != "pkg:deb/busybox@1:1.30.1-6+deb10u1?arch=armhf":
            print(f"FAIL: busybox purl wrong: {by_name.get('busybox')}")
            fails += 1
        if by_name.get("musl", {}).get("purl") != "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64":
            print(f"FAIL: musl purl wrong: {by_name.get('musl')}")
            fails += 1

        # Emitted standard-format SBOMs parse and match.
        try:
            cdx = json.load(open(os.path.join(outdir, "sbom.cdx.json")))
            spdx = json.load(open(os.path.join(outdir, "sbom.spdx.json")))
        except Exception as e:
            print(f"FAIL: could not load emitted SBOM files: {e}")
            return 1

        if cdx.get("bomFormat") != "CycloneDX" or cdx.get("specVersion") != "1.5":
            print(f"FAIL: CycloneDX header wrong: {cdx.get('bomFormat')}/{cdx.get('specVersion')}")
            fails += 1
        if {c["name"] for c in cdx.get("components", [])} != expected:
            print("FAIL: CycloneDX components != report components")
            fails += 1
        if spdx.get("spdxVersion") != "SPDX-2.3":
            print(f"FAIL: SPDX version wrong: {spdx.get('spdxVersion')}")
            fails += 1
        if {p["name"] for p in spdx.get("packages", [])} != expected:
            print("FAIL: SPDX packages != report components")
            fails += 1

        # --- binary-version precision (issue #7) ---
        # A separate rootfs of synthetic ELFs: version strings must come from the
        # authoritative banner, not requirement text / dev placeholders / the
        # u-boot-tools userspace stamp.
        bv = os.path.join(d, "bv")
        elf = b"\x7fELF"
        def wfile(rel, body):
            p = os.path.join(bv, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(elf + b" pad " + body + b" end")
        # False: curl help text and a python module requirement string.
        wfile("usr/bin/curl", b"OpenSSL 1.1.1 or later. Use a different backend...")
        wfile("usr/lib/_hashlib.so", b"For OpenSSL 3.0.0 and newer it returns the provider")
        # False: fips dev-build placeholder date.
        wfile("usr/bin/fips_algvs", b"Big Number part of OpenSSL 1.1.0-fips-dev xx XXX xxxx")
        # False: the u-boot-tools userspace stamp (not the bootloader).
        wfile("usr/sbin/fw_printenv", b"Compiled with U-Boot 2023.04\nu-boot,env")
        # True: the authoritative openssl banner and a real u-boot bootloader banner.
        wfile("usr/bin/openssl", b"OpenSSL 3.0.13 30 Jan 2024")
        wfile("boot/u-boot.bin", b"U-Boot 2019.04-svn14626 (May 20 2024 - 17:23:07 +0800)")

        bvrep = json.loads(subprocess.check_output([binary, "-j", "--sbom", bv],
                                                   stderr=subprocess.DEVNULL))
        ossl = sorted(c["version"] for c in bvrep.get("components", []) if c["name"] == "openssl")
        ub = sorted(c["version"] for c in bvrep.get("components", []) if c["name"] == "u-boot")
        if ossl != ["3.0.13"]:
            print(f"FAIL: openssl precision: expected ['3.0.13'], got {ossl}")
            fails += 1
        if ub != ["2019.04"]:
            print(f"FAIL: u-boot precision: expected ['2019.04'], got {ub}")
            fails += 1

        # --- monolithic non-ELF firmware (binver raw-bytes scan) ---
        # A proprietary-OS / RTOS image is one statically-linked non-ELF blob with
        # no ELF member and no package DB. binver recovers its banners only when the
        # whole tree is monolithic (no ELF anywhere), so filesystem images are
        # untouched. Each case gets its own directory so the no-ELF condition holds.
        def mono_dir(name, body):
            p = os.path.join(d, name)
            os.makedirs(p, exist_ok=True)
            with open(os.path.join(p, "fw.bin"), "wb") as f:
                f.write(body)
            return p

        def ossl_bb(rep, tree):
            return (sorted(c["version"] for c in rep.get("components", []) if c["name"] == "openssl"),
                    sorted(c["version"] for c in rep.get("components", []) if c["name"] == "busybox"))

        # 1) Monolithic tree with clean banners -> recovered.
        mono = mono_dir("mono", b"rtos image \x01\x02 BusyBox v1.31.1 junk "
                                b"OpenSSL 0.9.7b 10 Apr 2003 \xaa\xbb end")
        r = json.loads(subprocess.check_output([binary, "-j", "--sbom", mono],
                                                stderr=subprocess.DEVNULL))
        if ossl_bb(r, mono) != (["0.9.7b"], ["1.31.1"]):
            print(f"FAIL: monolithic recovery: expected openssl 0.9.7b + busybox 1.31.1, "
                  f"got {ossl_bb(r, mono)}")
            fails += 1

        # 2) The SAME blob next to an ELF (a filesystem tree) is NOT raw-scanned:
        #    only the ELF's banner is reported, so filesystem images are unchanged.
        mixed = mono_dir("mixed", b"rtos image BusyBox v1.31.1 OpenSSL 0.9.7b 10 Apr 2003 end")
        with open(os.path.join(mixed, "prog"), "wb") as f:
            f.write(elf + b" realbox BusyBox v1.36.0 x")
        r = json.loads(subprocess.check_output([binary, "-j", "--sbom", mixed],
                                                stderr=subprocess.DEVNULL))
        if ossl_bb(r, mixed) != ([], ["1.36.0"]):
            print(f"FAIL: ELF-present tree must skip the raw blob: expected busybox 1.36.0 only, "
                  f"got {ossl_bb(r, mixed)}")
            fails += 1

        # 3) A corrupted build-date banner stays rejected (strict issue-#7 pattern).
        bad = mono_dir("mono_bad", b"blob OpenSSL 0.9.7b 10 Apr 200\x228 more")
        r = json.loads(subprocess.check_output([binary, "-j", "--sbom", bad],
                                                stderr=subprocess.DEVNULL))
        if any(c["name"] == "openssl" for c in r.get("components", [])):
            print("FAIL: malformed openssl date must not be emitted on the raw path")
            fails += 1

        # 4) zlib's ordinary-word anchors stay ELF-gated (raw_safe=False), so a
        #    monolithic blob does not get a zlib component from "inflate X.Y.Z".
        zl = mono_dir("mono_zlib", b"payload inflate 1.2.11 Copyright 1995 blah")
        r = json.loads(subprocess.check_output([binary, "-j", "--sbom", zl],
                                                stderr=subprocess.DEVNULL))
        if any(c["name"] == "zlib" for c in r.get("components", [])):
            print("FAIL: zlib must stay ELF-gated on the raw path")
            fails += 1

        if fails == 0:
            print(f"PASS: {len(names)} components (not-installed excluded), "
                  f"CycloneDX + SPDX emitted and consistent; binary-version precision "
                  f"(issue #7) rejects requirement/dev/tool strings, keeps real banners; "
                  f"monolithic non-ELF image recovered (busybox+openssl), filesystem trees "
                  f"and malformed/zlib banners unaffected")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
