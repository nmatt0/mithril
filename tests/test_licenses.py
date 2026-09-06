#!/usr/bin/env python3
"""test_licenses.py — integration test for the license pass.

Builds a tree with a COPYING file (GPL-2.0 text), a NOTICE (Apache-2.0), and a
source file carrying an SPDX tag, runs `mithril -j --licenses`, and asserts the
licenses are identified with the right basis.

Usage: tests/test_licenses.py [path/to/mithril]   (default: build/mithril)
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1

    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "COPYING"), "w") as f:
            f.write("GNU GENERAL PUBLIC LICENSE\n  Version 2, June 1991\n ...body...\n")
        with open(os.path.join(d, "NOTICE"), "w") as f:
            f.write("Apache License\n Version 2.0, January 2004\n http://www.apache.org/\n")
        with open(os.path.join(d, "src", "main.c"), "w") as f:
            f.write("// SPDX-License-Identifier: MIT\nint main(void){return 0;}\n")

        out = subprocess.check_output([binary, "-j", "--licenses", d], stderr=subprocess.DEVNULL)
        rep = json.loads(out)
        lic = {x["license"]: x for x in rep.get("licenses", [])}
        fails = 0

        for want in ("GPL-2.0", "Apache-2.0", "MIT"):
            if want not in lic:
                print(f"FAIL: license {want} not identified; got {sorted(lic)}")
                fails += 1
        # The SPDX tag is a declared (validated) match; the license files are structural.
        if lic.get("MIT", {}).get("confidence_tier") != "validated":
            print(f"FAIL: MIT (SPDX tag) should be validated: {lic.get('MIT')}")
            fails += 1
        if lic.get("GPL-2.0", {}).get("confidence_tier") != "structural":
            print(f"FAIL: GPL-2.0 (license file) should be structural: {lic.get('GPL-2.0')}")
            fails += 1

        if fails == 0:
            print("PASS: GPL-2.0 + Apache-2.0 (license files, structural) and MIT (SPDX tag, "
                  "validated) identified")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
