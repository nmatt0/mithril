#!/usr/bin/env python3
"""test_kconfig_recovery.py — integration test for kernel-config recovery beyond
IKCONFIG and the tri-state kernel-CVE gating that rides on it.

Builds small synthetic trees and runs `mithril -j --cve`, asserting the
kernel_cves verdicts:
  1. an on-disk .config (no IKCONFIG) is recovered and gates authoritatively:
     a CONFIG_PACKET CVE stays applicable, a CONFIG_NF_TABLES CVE is ruled out.
  2. a loadable .ko under /lib/modules rules its subsystem IN (evidence ko-file),
     while unrelated modular subsystems stay undetermined (honest tri-state).

Does not exercise the kallsyms binary decoder (covered by the unit tests); this
checks the walker wiring, source precedence, and JSON shape end to end.

Usage: tests/test_kconfig_recovery.py [path/to/mithril]
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

BANNER = (b"Linux version 5.4.0 (builder@host) (gcc version 8.3.0) "
          b"#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2020\n")

# A realistic-enough .config: the generated-file header makes it authoritative.
def make_config():
    lines = [b"#", b"# Automatically generated file; DO NOT EDIT.",
             b"# Linux/arm 5.4.0 Kernel Configuration", b"#",
             b"CONFIG_PACKET=y", b"CONFIG_UNIX=y", b"CONFIG_KEYS=y",
             b"CONFIG_STACKPROTECTOR_STRONG=y",          # hardening: enabled
             b"# CONFIG_HARDENED_USERCOPY is not set",   # hardening: disabled (a finding)
             b"# CONFIG_NF_TABLES is not set", b"# CONFIG_IO_URING is not set",
             b"# CONFIG_TIPC is not set"]
    for i in range(60):
        lines.append(b"CONFIG_STUB%d=y" % i)
    for i in range(20):
        lines.append(b"# CONFIG_OFFSTUB%d is not set" % i)
    return b"\n".join(lines) + b"\n"


def kernel_cves(binary, root):
    out = subprocess.check_output([binary, "-j", "--cve", root], stderr=subprocess.DEVNULL)
    return {k["cve"]: k for k in json.loads(out).get("kernel_cves", [])}


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary}")
        return 1
    fails = 0

    # --- Case 1: on-disk .config recovered, authoritative gating ---
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "boot"))
        os.makedirs(os.path.join(d, "etc"))
        with open(os.path.join(d, "boot", "vmlinuz"), "wb") as f:
            f.write(BANNER + os.urandom(4096))
        with open(os.path.join(d, "etc", "kernel.config"), "wb") as f:
            f.write(make_config())
        out = subprocess.check_output([binary, "-j", "--cve", d], stderr=subprocess.DEVNULL)
        rep = json.loads(out)
        kc = {k["cve"]: k for k in rep.get("kernel_cves", [])}
        # af_packet double-free needs CONFIG_PACKET (=y) -> applicable
        pk = kc.get("CVE-2021-22600")
        if not pk or pk["state"] != "applicable":
            print(f"FAIL(1): CVE-2021-22600 expected applicable, got {pk}")
            fails += 1
        # nf_tables double-free needs CONFIG_NF_TABLES (not set) -> ruled_out
        nf = kc.get("CVE-2024-1086")
        if not nf or nf["state"] != "ruled_out" or "kconfig" not in nf.get("reason", ""):
            print(f"FAIL(1): CVE-2024-1086 expected ruled_out via kconfig, got {nf}")
            fails += 1
        # kernel_config block: recovered, authoritative, per-option evidence present
        kcfg = rep.get("kernel_config", {})
        if not kcfg.get("recovered") or kcfg.get("source") not in ("on-disk .config", "ikconfig"):
            print(f"FAIL(1): kernel_config not recovered/authoritative: {kcfg}")
            fails += 1
        by = {o["name"]: o for o in kcfg.get("options", [])}
        if by.get("CONFIG_PACKET", {}).get("state") != "on" or \
           by.get("CONFIG_NF_TABLES", {}).get("state") != "off":
            print(f"FAIL(1): per-option states wrong: PACKET/NF_TABLES = "
                  f"{by.get('CONFIG_PACKET')}, {by.get('CONFIG_NF_TABLES')}")
            fails += 1
        # hardening tri-state: enabled (=y), disabled (not set), not_available (absent)
        hb = {h["name"]: h["state"] for h in kcfg.get("hardening", [])}
        if hb.get("stack protector") != "enabled" or \
           hb.get("hardened usercopy") != "disabled" or \
           hb.get("kaslr") != "not_available":
            print(f"FAIL(1): hardening tri-state wrong: {hb}")
            fails += 1
        # --dump-kconfig prints the verbatim config; a config-less tree exits nonzero
        dumped = subprocess.run([binary, "--dump-kconfig", d], capture_output=True)
        if dumped.returncode != 0 or b"CONFIG_PACKET=y" not in dumped.stdout:
            print(f"FAIL(1): --dump-kconfig did not emit the recovered config (rc={dumped.returncode})")
            fails += 1

    # --- Case 2: a .ko module rules its subsystem in; others undetermined ---
    with tempfile.TemporaryDirectory() as d:
        moddir = os.path.join(d, "lib", "modules", "5.4.0", "kernel", "net", "mac80211")
        os.makedirs(moddir)
        with open(os.path.join(d, "vmlinuz"), "wb") as f:
            f.write(BANNER + os.urandom(4096))
        with open(os.path.join(moddir, "mac80211.ko"), "wb") as f:
            f.write(b"\x7fELF" + os.urandom(2048))  # content irrelevant; path is the signal
        kc = kernel_cves(binary, d)
        # mac80211 MBSSID UAF needs CONFIG_MAC80211 (5.1..6.1) -> applicable via the .ko
        mb = kc.get("CVE-2022-42719")
        if not mb or mb["state"] != "applicable":
            print(f"FAIL(2): CVE-2022-42719 expected applicable via ko-file, got {mb}")
            fails += 1
        # A modular subsystem with no evidence stays undetermined, not ruled out.
        tp = kc.get("CVE-2022-0435")  # needs CONFIG_TIPC (fixed 5.17)
        if not tp or tp["state"] != "undetermined":
            print(f"FAIL(2): CVE-2022-0435 expected undetermined, got {tp}")
            fails += 1
        # No verbatim .config here -> --dump-kconfig must exit nonzero.
        dumped = subprocess.run([binary, "--dump-kconfig", d], capture_output=True)
        if dumped.returncode == 0:
            print("FAIL(2): --dump-kconfig should fail when no .config was recovered")
            fails += 1

    if fails == 0:
        print("PASS: .config recovered + authoritative gating; .ko rules subsystem in; "
              "modular-unknown stays undetermined")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
