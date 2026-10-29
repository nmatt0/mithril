#!/usr/bin/env python3
"""Offline APK identity and distro-advisory regression checks."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path("build/mithril").resolve()


class ApkDistroTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory()
        cls.db = Path(cls.storage.name) / "db"
        cls.db.mkdir()
        rows = []
        for cve, release in [("CVE-2099-0001", ""), ("CVE-2099-0319", "3.19"), ("CVE-2099-0320", "3.20")]:
            rows.append({"id": cve, "eco": "Alpine", "pkg": "busybox", "rel": release,
                         "ev": [["i", "0"], ["f", "1.38.0-r0"]], "sev": "", "sum": "fixture"})
        source = cls.db / "osv.json"
        source.write_text(json.dumps({"schema": 1, "vulns": rows}))
        subprocess.run([str(BINARY.with_name("mkosvindex")), str(source), str(cls.db / "osv-index.mdb")],
                       check=True, capture_output=True)
        (cls.db / "nvd-index.json").write_text('{"schema":1,"vulns":[]}')
        (cls.db / "epss.txt").write_text("")

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def setUp(self):
        self.storage = tempfile.TemporaryDirectory()
        self.addCleanup(self.storage.cleanup)
        self.root = Path(self.storage.name)

    def tree(self, name, distro=None, release="3.20", os_path="etc/os-release"):
        root = self.root / name
        db = root / "lib/apk/db/installed"
        db.parent.mkdir(parents=True)
        db.write_text("P:busybox\nV:1.37.0-r6\nA:x86_64\n\n")
        if distro is not None:
            identity = root / os_path
            identity.parent.mkdir(parents=True, exist_ok=True)
            identity.write_text(f'ID={distro}\nVERSION_ID="{release}"\n')
        return root

    def scan(self, root, mode="--cve"):
        env = dict(os.environ, MITHRIL_DB=str(self.db), MITHRIL_NO_FETCH="1")
        result = subprocess.run([str(BINARY), "-j", mode, str(root)], capture_output=True,
                                text=True, env=env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_openwrt_does_not_borrow_alpine_advisories(self):
        report = self.scan(self.tree("openwrt", "openwrt", "25.12.6"))
        self.assertEqual(report["components"][0]["purl"], "pkg:apk/openwrt/busybox@1.37.0-r6?arch=x86_64")
        self.assertEqual(report["cves"], [])

    def test_alpine_keeps_its_advisory_matches(self):
        report = self.scan(self.tree("alpine", "alpine"))
        self.assertEqual({c["cve"] for c in report["cves"]}, {"CVE-2099-0001", "CVE-2099-0319", "CVE-2099-0320"})
        self.assertEqual(report["components"][0]["purl"], "pkg:apk/alpine/busybox@1.37.0-r6?arch=x86_64")

    def test_unknown_identity_does_not_assume_alpine(self):
        report = self.scan(self.tree("unknown"))
        self.assertEqual(report["components"][0]["purl"], "pkg:apk/busybox@1.37.0-r6?arch=x86_64")
        self.assertEqual(report["cves"], [])

    def test_mixed_roots_do_not_borrow_the_first_distro_or_collapse(self):
        for alpine_name, openwrt_name in [("a", "z"), ("z", "a")]:
            with self.subTest(alpine=alpine_name):
                group = alpine_name + openwrt_name
                self.tree(group + "/" + alpine_name, "alpine")
                self.tree(group + "/" + openwrt_name, "openwrt", "25.12.6")
                self.tree(group + "/unknown")
                report = self.scan(self.root / group)
                self.assertEqual(len(report["components"]), 3)
                self.assertEqual({c["cve"] for c in report["cves"]}, {"CVE-2099-0001", "CVE-2099-0319", "CVE-2099-0320"})
                self.assertTrue(all(c["purl"].startswith("pkg:apk/alpine/") for c in report["cves"]))

    def test_unrelated_debian_release_does_not_filter_alpine_advisories(self):
        self.tree("z-alpine", "alpine")
        identity = self.root / "a-debian/etc/os-release"
        identity.parent.mkdir(parents=True)
        identity.write_text("ID=debian\nVERSION_ID=12\n")
        report = self.scan(self.root)
        self.assertEqual({c["cve"] for c in report["cves"]},
                         {"CVE-2099-0001", "CVE-2099-0319", "CVE-2099-0320"})

    def test_etc_identity_overrides_usr_lib(self):
        root = self.tree("override", "alpine", os_path="usr/lib/os-release")
        (root / "etc").mkdir()
        (root / "etc/os-release").write_text("ID=openwrt\nVERSION_ID=25.12.6\n")
        self.assertEqual(self.scan(root)["cves"], [])

    def test_usr_lib_identity_is_used_when_etc_is_absent(self):
        report = self.scan(self.tree("fallback", "alpine", os_path="usr/lib/os-release"))
        self.assertEqual({c["cve"] for c in report["cves"]}, {"CVE-2099-0001", "CVE-2099-0319", "CVE-2099-0320"})

    def test_custom_etc_symlink_does_not_assume_usr_lib_identity(self):
        root = self.tree("custom-link", "alpine", os_path="usr/lib/os-release")
        (root / "etc").mkdir()
        (root / "etc/openwrt-os-release").write_text("ID=openwrt\n")
        (root / "etc/os-release").symlink_to("openwrt-os-release")
        report = self.scan(root)
        self.assertEqual(report["cves"], [])
        self.assertEqual(report["components"][0]["purl"], "pkg:apk/busybox@1.37.0-r6?arch=x86_64")

    def test_dangling_etc_symlink_keeps_identity_unknown(self):
        root = self.tree("dangling-link", "alpine", os_path="usr/lib/os-release")
        (root / "etc").mkdir()
        (root / "etc/os-release").symlink_to("missing-os-release")
        self.assertEqual(self.scan(root)["cves"], [])

    def test_canonical_etc_symlinks_keep_own_root_identity(self):
        for name, target in [("relative", "../usr/lib/os-release"), ("absolute", "/usr/lib/os-release")]:
            with self.subTest(target=target):
                root = self.tree(name, "alpine", os_path="usr/lib/os-release")
                (root / "etc").mkdir()
                (root / "etc/os-release").symlink_to(target)
                report = self.scan(root)
                self.assertEqual({c["cve"] for c in report["cves"]},
                                 {"CVE-2099-0001", "CVE-2099-0319", "CVE-2099-0320"})

    def test_foreign_root_etc_symlink_does_not_borrow_identity(self):
        root = self.tree("foreign-link", "alpine", os_path="usr/lib/os-release")
        self.tree("other", "openwrt")
        (root / "etc").mkdir()
        (root / "etc/os-release").symlink_to("../../other/etc/os-release")
        self.assertEqual(self.scan(root)["cves"], [])

    def test_symlinked_etc_directory_keeps_identity_unknown(self):
        root = self.tree("directory-link", "alpine", os_path="usr/lib/os-release")
        (root / "openwrt-etc").mkdir()
        (root / "openwrt-etc/os-release").write_text("ID=openwrt\n")
        (root / "etc").symlink_to("openwrt-etc", target_is_directory=True)
        self.assertEqual(self.scan(root)["cves"], [])

    def test_nested_root_does_not_borrow_parent_identity(self):
        root = self.tree("outer", "alpine")
        self.tree("outer/nested")
        report = self.scan(root)
        self.assertEqual(len(report["components"]), 2)
        nested = next(c for c in report["components"] if c["origin_path"].startswith("nested/"))
        self.assertEqual(nested["purl"], "pkg:apk/busybox@1.37.0-r6?arch=x86_64")

    def test_invalid_distro_id_does_not_become_a_namespace(self):
        report = self.scan(self.tree("invalid", "alpine/other"))
        self.assertEqual(report["components"][0]["purl"], "pkg:apk/busybox@1.37.0-r6?arch=x86_64")
        self.assertEqual(report["cves"], [])

    def test_sbom_only_keeps_the_same_package_identity(self):
        report = self.scan(self.tree("sbom", "openwrt", "25.12.6"), "--sbom")
        self.assertEqual(report["components"][0]["purl"], "pkg:apk/openwrt/busybox@1.37.0-r6?arch=x86_64")


if __name__ == "__main__":
    unittest.main()
