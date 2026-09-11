#!/usr/bin/env python3
"""test_licenses.py — integration test for the license pass.

Builds a tree with a COPYING file (GPL-2.0 text), a NOTICE (Apache-2.0), and two
source files carrying the same SPDX tag, runs `mithril -j --licenses`, and
asserts the licenses are identified with the right basis. Also checks the
`paths` array (every file location per license) in JSON and the human-mode
`--license-paths` expansion vs the default count summary (issue #3).

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
        # Same SPDX tag in two files -> the license must aggregate to count 2
        # with both paths.
        with open(os.path.join(d, "src", "main.c"), "w") as f:
            f.write("// SPDX-License-Identifier: MIT\nint main(void){return 0;}\n")
        with open(os.path.join(d, "src", "util.c"), "w") as f:
            f.write("// SPDX-License-Identifier: MIT\nint util(void){return 1;}\n")

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

        # JSON carries every file location (issue #3): `paths` array, count-consistent,
        # and the old `example_path` field is gone.
        mit = lic.get("MIT", {})
        if "example_path" in mit:
            print(f"FAIL: example_path should be removed from JSON: {mit}")
            fails += 1
        mit_paths = mit.get("paths")
        if not isinstance(mit_paths, list) or mit.get("count") != len(mit_paths):
            print(f"FAIL: MIT paths array missing or count-inconsistent: {mit}")
            fails += 1
        elif sorted(mit_paths) != ["src/main.c", "src/util.c"]:
            print(f"FAIL: MIT paths {mit_paths} != both source files")
            fails += 1

        # Human default: counts + the hint, no file paths printed.
        human = subprocess.check_output([binary, "--licenses", d],
                                        stderr=subprocess.DEVNULL).decode()
        if "src/main.c" in human or "src/util.c" in human:
            print("FAIL: default human output should not print file paths")
            fails += 1
        if "--license-paths" not in human:
            print("FAIL: default human output should hint at --license-paths")
            fails += 1

        # Human --license-paths: the actual locations appear, hint gone.
        paths_out = subprocess.check_output([binary, "--license-paths", d],
                                            stderr=subprocess.DEVNULL).decode()
        for p in ("src/main.c", "src/util.c"):
            if p not in paths_out:
                print(f"FAIL: --license-paths output missing {p}")
                fails += 1
        # MIT id should appear on two rows (once per file) in the detail view.
        if paths_out.count("MIT") < 2:
            print("FAIL: --license-paths should show MIT once per file")
            fails += 1

        if fails == 0:
            print("PASS: GPL-2.0 + Apache-2.0 (files, structural) and MIT x2 (SPDX tag, "
                  "validated) identified; JSON paths array, --license-paths locations")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
