#!/usr/bin/env python3
"""test_kconfig.py — integration test for embedded kernel-config (IKCONFIG) extraction.

Builds a file with the IKCFG_ST ... gzip(.config) ... IKCFG_ED framing that a
CONFIG_IKCONFIG kernel uses, runs `mithril -j --sbom`, and asserts a
kernel-config notable finding with the right option count. Exercises the
hand-rolled DEFLATE end to end.

Usage: tests/test_kconfig.py [path/to/mithril]   (default: build/mithril)
"""
import gzip
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CONFIG = (b"#\n# Automatically generated file\n#\n"
          b"CONFIG_STACKPROTECTOR=y\n"
          b"CONFIG_FORTIFY_SOURCE=y\n"
          b"CONFIG_BPF_SYSCALL=y\n"
          b"CONFIG_USB_GADGET=m\n"
          b"# CONFIG_RANDOMIZE_BASE is not set\n")


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary}")
        return 1

    with tempfile.TemporaryDirectory() as d:
        blob = (os.urandom(256) + b"IKCFG_ST" + gzip.compress(CONFIG, 6) + b"IKCFG_ED" +
                os.urandom(256))
        with open(os.path.join(d, "vmlinux"), "wb") as f:
            f.write(blob)

        out = subprocess.check_output([binary, "-j", "--sbom", d], stderr=subprocess.DEVNULL)
        rep = json.loads(out)
        kc = [n for n in rep.get("notable", []) if n["type"] == "kernel-config"]
        fails = 0
        if not kc:
            print(f"FAIL: no kernel-config notable finding: {rep.get('notable')}")
            fails += 1
        else:
            f = kc[0]
            if "4 options" not in f.get("label", ""):
                print(f"FAIL: expected 4 enabled options, got: {f.get('label')}")
                fails += 1
            desc = f.get("description", "")
            if "stackprot+" not in desc or "kaslr-" not in desc:
                print(f"FAIL: hardening summary wrong: {desc}")
                fails += 1

        if fails == 0:
            print("PASS: IKCONFIG inflated, 4 options, hardening flags read (stackprot+ kaslr-)")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
