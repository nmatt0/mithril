#!/usr/bin/env python3
"""test_config_cred.py — integration test for the config-credential pass (JSON).

Builds a synthetic tree of config files with known credential fields and known
bait, runs `mithril -j --secrets`, and asserts the config-credential pass flags
exactly the real credential fields (category "config-credential") and none of
the placeholders, enums, non-credential keys, or non-JSON files. Also asserts a
high-entropy value under a generic-anchor key is reported once (by the existing
flat-stream engine), not duplicated by this pass.

Usage: tests/test_config_cred.py [path/to/mithril]   (default: build/mithril)
"""
import base64
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def b64(s):
    return base64.b64encode(s.encode()).decode()


def build_tree(d):
    os.makedirs(os.path.join(d, "etc"))
    os.makedirs(os.path.join(d, "cfg"))

    # POSITIVE 1: short disarm-style codes as base64 passwd fields nested in an
    # array of user objects. Short + low-entropy + encoded: the flat-stream
    # engine floors all of these out.
    with open(os.path.join(d, "user.json"), "w") as f:
        json.dump({"users": [
            {"name": "svc", "passwd": b64("1379")},
            {"name": "op", "passwd": b64("5082")},
            {"name": "tech", "passwd": b64("9513")},
        ]}, f)

    # POSITIVE 2: a wifi PSK — key the flat-stream engine has no anchor for, so
    # this pass is the only chance to catch it. Long value, Pattern tier (no decode).
    with open(os.path.join(d, "cfg/wifi.json"), "w") as f:
        json.dump({"wlan0": {"ssid": "HomeNet", "psk": "correcthorsebatterystaple7"}}, f)

    # POSITIVE 3: a short numeric PIN as a JSON number (not a string).
    with open(os.path.join(d, "cfg/lock.json"), "w") as f:
        json.dump({"door": {"pin": 2468}}, f)

    # POSITIVE 4: scalar elements in an array inherit the array's key.
    with open(os.path.join(d, "cfg/keys.json"), "w") as f:
        json.dump({"wpakey": [b64("Zone1Secret!")]}, f)

    # DEFER: a high-entropy value under a generic-anchor key ("password") must be
    # caught once by the flat-stream generic-secret rule, NOT also by this pass.
    with open(os.path.join(d, "cfg/app.json"), "w") as f:
        json.dump({"db": {"password": "S3cr3t_Pa55w0rd_9xQ7zLmNqVt"}}, f)

    # NEGATIVES — every one of these must produce zero config-credential findings.
    with open(os.path.join(d, "cfg/noise.json"), "w") as f:
        json.dump({
            "password": "",                 # empty
            "passwd": "changeme",           # placeholder
            "secret": "default",            # placeholder enum
            "apikey": "<YOUR_API_KEY>",     # placeholder
            "pin": "0000",                   # all-same-char
            "token": 1003,                   # token-like + numeric -> log/enum code
            "rebootDelay_sec": 30,          # non-credential key
            "DefaultLanguage": "English",   # non-credential key
            "enabled": True,                 # bool
            "entry_time": [0, 30000, 30000],  # array of non-cred numbers
        }, f)

    # NEGATIVE: not valid JSON (a JS object literal) -> the parse gate rejects it
    # before any key is examined, even though it starts with '{' and says passwd.
    with open(os.path.join(d, "cfg/bundle.json"), "w") as f:
        f.write("{ var passwd = function(){ return 'x'; }; }\n" + ("/*pad*/" * 2000))

    # NEGATIVE: a plain non-config text file naming passwd (not JSON at all).
    with open(os.path.join(d, "etc/readme.txt"), "w") as f:
        f.write("Set your passwd to something strong. password = see the manual.\n")

    expected_cfgcred = {
        ("user.json", "config-password"),
        ("cfg/wifi.json", "config-wifi-key"),
        ("cfg/lock.json", "config-password"),
        ("cfg/keys.json", "config-wifi-key"),
    }
    return expected_cfgcred


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "mithril")
    if not os.path.exists(binary):
        print(f"FAIL: binary not found: {binary} (build first)")
        return 1

    with tempfile.TemporaryDirectory() as d:
        expected = build_tree(d)
        out = subprocess.check_output([binary, "-j", "--secrets", d])
        rep = json.loads(out)
        secrets = rep["secrets"]
        fails = 0

        cfg = [h for h in secrets if h.get("category") == "config-credential"]
        got_paths = {(h["path"], h["type"]) for h in cfg}

        # 1. every expected real credential field is flagged, with the right path+type.
        missing = expected - got_paths
        if missing:
            print(f"FAIL: expected config-credentials not found: {sorted(missing)}")
            fails += 1

        # 2. user.json yields exactly the three disarm codes, base64-decoded (structural).
        upw = [h for h in cfg if h["path"] == "user.json"]
        if len(upw) != 3:
            print(f"FAIL: expected 3 passwd fields in user.json, got {len(upw)}: {upw}")
            fails += 1
        for h in upw:
            if h.get("confidence_tier") != "structural" or "base64" not in h.get("label", ""):
                print(f"FAIL: user.json passwd not reported as base64/structural: {h}")
                fails += 1

        # 3. NO config-credential finding comes from any negative file.
        bad = [h for h in cfg if h["path"] in
               ("cfg/noise.json", "cfg/bundle.json", "etc/readme.txt", "cfg/app.json")]
        if bad:
            print(f"FAIL: config-credential false positives: {bad}")
            fails += 1

        # 4. the deferred high-entropy password is reported once, by the flat-stream
        #    engine (generic-secret), and not duplicated as a config-credential.
        app_hits = [h for h in secrets if h["path"] == "cfg/app.json"]
        app_cfg = [h for h in app_hits if h.get("category") == "config-credential"]
        app_gen = [h for h in app_hits if h["type"] == "generic-secret"]
        if app_cfg:
            print(f"FAIL: app.json password double-reported as config-credential: {app_cfg}")
            fails += 1
        if not app_gen:
            print(f"FAIL: app.json password not caught by the generic-secret engine: {app_hits}")
            fails += 1

        # 5. values are redacted (the raw PIN/base64 is never emitted verbatim).
        for h in cfg:
            if "5082" in json.dumps(h) or "correcthorsebatterystaple7" in json.dumps(h):
                print(f"FAIL: config-credential leaked a raw value: {h}")
                fails += 1

        if fails == 0:
            print(f"PASS: {len(cfg)} config-credentials flagged across "
                  f"{rep['file_count']} files, placeholders/enums/non-JSON silent, "
                  f"high-entropy value not double-reported, values redacted")
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
