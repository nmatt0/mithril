#!/usr/bin/env python3
"""test_cve.py — integration test for the CVE join (offline, fixture DB).

Points MITHRIL_DB at a temp dir holding a hand-built normalized OSV index, builds
a rootfs with a dpkg status DB that lists a vulnerable busybox, runs
`mithril -j --cve`, and asserts the CVE is reported for the affected version and
not for a patched one. No network — the fixture stands in for `--update-db`.

Usage: tests/test_cve.py [path/to/mithril]   (default: build/mithril)
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

INDEX = {
    "schema": 1, "source": "test-fixture", "generated": "2026-09-05T00:00:00Z",
    "vulns": [
        {"id": "CVE-2021-28831", "eco": "Debian", "pkg": "busybox",
         "ev": [["i", "0"], ["f", "1:1.30.1-6"]],
         "sev": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
         "sum": "busybox decompress_gunzip out-of-bounds read"},
    ],
}

NVD_INDEX = {
    "schema": 1, "source": "test-nvd",
    "vulns": [
        {"id": "CVE-2022-0778", "vendor": "openssl", "product": "openssl",
         "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", "ee": "1.1.1n"},
    ],
}


def dpkg_status(busybox_version):
    return (f"Package: busybox\nStatus: install ok installed\n"
            f"Version: {busybox_version}\nArchitecture: armhf\n")


def run(binary, rootfs, dbdir):
    env = dict(os.environ, MITHRIL_DB=dbdir)
    out = subprocess.check_output([binary, "-j", "--cve", rootfs], env=env,
                                  stderr=subprocess.DEVNULL)
    return json.loads(out)


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1

    # The OSV index is the compact binary format; build the fixture .mdb with the
    # mkosvindex helper (next to the binary) from the normalized JSON.
    mkosvindex = os.path.join(os.path.dirname(os.path.abspath(binary)), "mkosvindex")
    if not os.path.exists(mkosvindex):
        print(f"FAIL: mkosvindex helper not found: {mkosvindex} (build first)")
        return 1

    with tempfile.TemporaryDirectory() as d:
        dbdir = os.path.join(d, "db")
        os.makedirs(dbdir)
        jtmp = os.path.join(dbdir, "osv.json")
        with open(jtmp, "w") as f:
            json.dump(INDEX, f)
        subprocess.check_call([mkosvindex, jtmp, os.path.join(dbdir, "osv-index.mdb")])
        os.remove(jtmp)
        with open(os.path.join(dbdir, "nvd-index.json"), "w") as f:
            json.dump(NVD_INDEX, f)

        fails = 0

        # Vulnerable busybox (1:1.30.1-5 < fixed 1:1.30.1-6).
        vuln = os.path.join(d, "vuln", "var", "lib", "dpkg")
        os.makedirs(vuln)
        with open(os.path.join(vuln, "status"), "w") as f:
            f.write(dpkg_status("1:1.30.1-5"))
        rep = run(binary, os.path.join(d, "vuln"), dbdir)
        cves = {(c["cve"], c["component"]) for c in rep.get("cves", [])}
        if ("CVE-2021-28831", "busybox@1:1.30.1-5") not in cves:
            print(f"FAIL: expected CVE not reported for vulnerable busybox: {cves}")
            fails += 1
        # Severity + basis carried through.
        hit = next((c for c in rep["cves"] if c["cve"] == "CVE-2021-28831"), None)
        if not hit or "CVSS" not in hit.get("severity", "") or "Debian" not in hit.get("basis", ""):
            print(f"FAIL: CVE match missing severity/basis: {hit}")
            fails += 1

        # Patched busybox (== fixed version) -> no CVE.
        patched = os.path.join(d, "patched", "var", "lib", "dpkg")
        os.makedirs(patched)
        with open(os.path.join(patched, "status"), "w") as f:
            f.write(dpkg_status("1:1.30.1-6"))
        rep2 = run(binary, os.path.join(d, "patched"), dbdir)
        if rep2.get("cves"):
            print(f"FAIL: patched busybox should have no CVEs: {rep2['cves']}")
            fails += 1

        # NVD augment: a binary-version openssl (from an ELF banner) -> CPE join.
        elfdir = os.path.join(d, "bv", "usr", "lib")
        os.makedirs(elfdir)
        with open(os.path.join(elfdir, "libssl.so"), "wb") as f:
            f.write(b"\x7fELF padding OpenSSL 1.1.1m end")  # < 1.1.1n -> vulnerable
        rep3 = run(binary, os.path.join(d, "bv"), dbdir)
        nvd = {(c["cve"], c["component"]) for c in rep3.get("cves", [])
               if "nvd-cpe" in c.get("basis", "")}
        if ("CVE-2022-0778", "openssl@1.1.1m") not in nvd:
            print(f"FAIL: NVD/CPE join did not flag openssl 1.1.1m: {rep3.get('cves')}")
            fails += 1

        if fails == 0:
            print("PASS: vulnerable busybox flagged CVE-2021-28831 (severity+basis), "
                  "patched clean, NVD/CPE join flagged openssl 1.1.1m")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
