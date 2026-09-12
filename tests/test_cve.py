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
        # Availability-only DoS (7.5). Gets a high EPSS below, but the human gate
        # must still hide it: a crash is not a foothold.
        {"id": "CVE-2021-28831", "eco": "Debian", "pkg": "busybox",
         "ev": [["i", "0"], ["f", "1:1.30.1-6"]],
         "sev": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
         "sum": "busybox decompress_gunzip out-of-bounds read"},
        # Real integrity impact at low complexity (8.8), sub-Critical. Qualifies
        # only via the EPSS arm and must be SHOWN (a foothold candidate).
        {"id": "CVE-2099-0002", "eco": "Debian", "pkg": "busybox",
         "ev": [["i", "0"], ["f", "1:1.30.1-6"]],
         "sev": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
         "sum": "busybox synthetic memory-corruption fixture"},
    ],
}

# EPSS scores (annotation): both over the 0.10 bar so both take the EPSS arm; the
# DoS one is still filtered by impact, the integrity one is kept.
EPSS = "CVE-2021-28831,0.50\nCVE-2099-0002,0.15\n"

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


def run_human(binary, rootfs, dbdir, extra=None):
    env = dict(os.environ, MITHRIL_DB=dbdir, NO_COLOR="1")
    cmd = [binary, "--cve", rootfs] + (extra or [])
    return subprocess.check_output(cmd, env=env, stderr=subprocess.DEVNULL).decode()


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
        with open(os.path.join(dbdir, "epss.txt"), "w") as f:
            f.write(EPSS)

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

        # Human-view gating. The vuln rootfs has two sub-Critical CVEs, both High
        # (>= 7.0) with EPSS >= 0.10: a remote availability-only DoS (7.5, EPSS
        # 0.50) and a real integrity bug (8.8, EPSS 0.15). The DoS is below the
        # 0.70 remote-DoS bar so it is hidden; the integrity bug is shown. Default
        # view shows 1 of 2; JSON stays complete + records the outcome.
        scan = rep.get("component_cve_scan")
        if not scan or (scan.get("total"), scan.get("high_signal"), scan.get("hidden")) != (2, 1, 1):
            print(f"FAIL: component_cve_scan gate metadata wrong (want 2/1/1): {scan}")
            fails += 1
        if hit and hit.get("cvss_score") != 7.5:
            print(f"FAIL: cvss_score not recomputed from vector (want 7.5): {hit}")
            fails += 1
        h = run_human(binary, os.path.join(d, "vuln"), dbdir)
        # DoS hidden, integrity bug shown, despite BOTH having high EPSS.
        if "1 high-signal shown, 1 hidden" not in h:
            print(f"FAIL: default human view count line wrong:\n{h}")
            fails += 1
        if "CVE-2021-28831" in h:
            print(f"FAIL: availability-only DoS should be hidden despite EPSS 0.50:\n{h}")
            fails += 1
        if "CVE-2099-0002" not in h:
            print(f"FAIL: real-impact CVE should survive the EPSS arm:\n{h}")
            fails += 1
        if "--component-cves-all" not in h:
            print(f"FAIL: gated human view should point to --component-cves-all:\n{h}")
            fails += 1
        # --component-cves-all lists every CVE, with no gate banner or footer.
        hall = run_human(binary, os.path.join(d, "vuln"), dbdir, ["--component-cves-all"])
        if "CVE-2021-28831" not in hall or "CVE-2099-0002" not in hall or "hidden" in hall:
            print(f"FAIL: --component-cves-all should list every CVE:\n{hall}")
            fails += 1

        if fails == 0:
            print("PASS: vulnerable busybox flagged CVE-2021-28831 (severity+basis), "
                  "patched clean, NVD/CPE join flagged openssl 1.1.1m, "
                  "human view gates to foothold-worthy (hard High/Critical floor; remote DoS "
                  "kept only when trending; --component-cves-all opts out)")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
