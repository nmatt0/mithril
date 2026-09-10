#!/usr/bin/env python3
"""test_kernelfeed.py — integration test for --kernel-cves-all (the full
kernel.org CVE feed) and its merge with the curated checklist.

Seeds a small kernel-cve-index.json fixture (the on-disk feed format) into a
throwaway MITHRIL_DB, builds a tiny tree carrying a kernel banner, and asserts:
  1. --kernel-cves-all surfaces the in-range feed CVEs (source "kernel.org"),
     branch-aware: a bug fixed in 6.6.17 hits 6.6.10 but NOT 6.6.110, even though
     the mainline window spans both.
  2. the JSON kernel_cve_scan flips to method "curated+kernel.org", exhaustive
     true, with a feed_in_range count.
  3. without the feed asset, --kernel-cves-all fails loud (a scan-level error
     naming --fetch-db --with-kernel-feed), not silently.

Usage: tests/test_kernelfeed.py [path/to/mithril]
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def banner(ver):
    return (f"Linux version {ver} (builder@host) (gcc version 13.0.0) "
            f"#0 SMP Thu Jan 1 00:00:00 UTC 2026\n").encode()


# A minimal feed index in the on-disk format written by write_kernel_feed_index.
FEED = {
    "schema": "mithril-kernel-cve-1",
    "source": "test",
    "generated": 1,
    "cves": [
        # branch-precise: 6.6 affected until 6.6.17; 6.1 until 6.1.78
        {"id": "CVE-2024-90001", "ranges": [["6.6", "6.6.17"], ["6.1.43", "6.1.78"]],
         "mainline": ["6.5", "6.8"], "sev": "HIGH", "score": 7.8, "sum": "branch-precise bug"},
        # a different branch only (should NOT hit 6.6.x)
        {"id": "CVE-2024-90002", "ranges": [["5.15.10", "5.15.60"]], "sev": "MEDIUM",
         "sum": "5.15-only bug"},
        # coarse/custom single range -> broad-range (verify backport)
        {"id": "CVE-2024-90003", "broad": [["3.15", "6.8"]], "sev": "LOW",
         "sum": "coarse range bug"},
    ],
}


def run_json(binary, root, env, extra=()):
    # The scan exits nonzero when the component mirror (OSV/NVD) is absent, which it
    # is in this fixture DB (we seed only the kernel feed). The JSON report is still
    # written to stdout, and that is all this test cares about — so parse stdout
    # regardless of the exit code.
    r = subprocess.run([binary, "-j", "--cve", *extra, root],
                       capture_output=True, env=env)
    return json.loads(r.stdout)


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary}")
        return 1
    fails = 0

    with tempfile.TemporaryDirectory() as db, tempfile.TemporaryDirectory() as tree:
        env = {**os.environ, "MITHRIL_DB": db, "NO_COLOR": "1"}
        with open(os.path.join(db, "kernel-cve-index.json"), "w") as f:
            json.dump(FEED, f)

        # --- Case 1: 6.6.10 -> branch-precise bug + coarse bug apply, 5.15 one not ---
        with open(os.path.join(tree, "vmlinuz"), "wb") as f:
            f.write(banner("6.6.10") + os.urandom(4096))
        rep = run_json(binary, tree, env, extra=["--kernel-cves-all"])
        feed = {k["cve"]: k for k in rep.get("kernel_cves", []) if k.get("source") == "kernel.org"}
        if "CVE-2024-90001" not in feed:
            print(f"FAIL(1): branch-precise CVE not matched for 6.6.10: {sorted(feed)}")
            fails += 1
        if "CVE-2024-90003" not in feed:
            print(f"FAIL(1): coarse-range CVE not matched for 6.6.10: {sorted(feed)}")
            fails += 1
        if "CVE-2024-90002" in feed:
            print("FAIL(1): 5.15-only CVE wrongly matched for 6.6.10")
            fails += 1
        scan = rep.get("kernel_cve_scan", {})
        if scan.get("method") != "curated+kernel.org" or scan.get("exhaustive") is not True:
            print(f"FAIL(1): kernel_cve_scan not full/exhaustive: {scan}")
            fails += 1
        if scan.get("feed_in_range", 0) < 2:
            print(f"FAIL(1): feed_in_range wrong: {scan}")
            fails += 1
        # reason records the basis
        if "verify backport" not in feed.get("CVE-2024-90003", {}).get("reason", ""):
            print(f"FAIL(1): coarse CVE not marked verify-backport: {feed.get('CVE-2024-90003')}")
            fails += 1

        # --- Case 2: 6.6.110 -> the 6.6-branch bug is fixed (6.6.17); NOT reported ---
        with open(os.path.join(tree, "vmlinuz"), "wb") as f:
            f.write(banner("6.6.110") + os.urandom(4096))
        rep2 = run_json(binary, tree, env, extra=["--kernel-cves-all"])
        feed2 = {k["cve"]: k for k in rep2.get("kernel_cves", []) if k.get("source") == "kernel.org"}
        if "CVE-2024-90001" in feed2:
            print("FAIL(2): 6.6.110 wrongly flagged for a bug fixed in 6.6.17 (cross-branch FP)")
            fails += 1
        if "CVE-2024-90003" not in feed2:  # coarse range still spans it
            print("FAIL(2): coarse-range CVE should still match 6.6.110")
            fails += 1

        # --- Case 3: default run (no --kernel-cves-all) does not consult the feed ---
        rep3 = run_json(binary, tree, env)
        if any(k.get("source") == "kernel.org" for k in rep3.get("kernel_cves", [])):
            print("FAIL(3): feed CVEs leaked into a default scan (no --kernel-cves-all)")
            fails += 1
        if rep3.get("kernel_cve_scan", {}).get("exhaustive") is not False:
            print("FAIL(3): default scan should be non-exhaustive")
            fails += 1

    # --- Case 4: --kernel-cves-all with no feed asset -> loud, actionable error ---
    with tempfile.TemporaryDirectory() as db2, tempfile.TemporaryDirectory() as tree2:
        env2 = {**os.environ, "MITHRIL_DB": db2, "NO_COLOR": "1"}
        with open(os.path.join(tree2, "vmlinuz"), "wb") as f:
            f.write(banner("6.6.10") + os.urandom(4096))
        r = subprocess.run([binary, "--cve", "--kernel-cves-all", tree2],
                           capture_output=True, env=env2)
        msg = (r.stdout + r.stderr).decode()
        if "no kernel CVE feed" not in msg or "--with-kernel-feed" not in msg:
            print(f"FAIL(4): missing-feed error not surfaced: {msg[:200]}")
            fails += 1

    if fails == 0:
        print("PASS: --kernel-cves-all merges the branch-aware kernel.org feed, "
              "excludes fixed branches, and fails loud without the asset")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
