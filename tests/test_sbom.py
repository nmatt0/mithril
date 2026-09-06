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

        if fails == 0:
            print(f"PASS: {len(names)} components (not-installed excluded), "
                  f"CycloneDX + SPDX emitted and consistent")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
