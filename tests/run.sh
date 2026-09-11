#!/usr/bin/env bash
# run.sh — build mithril + run the whole test suite (unit + integration).
# Mirrors moria/tests/run.sh. Usage: tests/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=${BUILD:-build}

echo "== configure + build =="
# EXTRA_CMAKE lets CI run the whole suite under sanitizers (EXTRA_CMAKE=-DMT_SANITIZE=ON)
# without duplicating the test list here.
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release ${EXTRA_CMAKE:-} >/dev/null
cmake --build "$BUILD" -j >/dev/null

echo "== unit tests =="
"./$BUILD/mithril_unit"

echo "== integration: secrets =="
python3 tests/test_secrets.py "./$BUILD/mithril"

echo "== integration: der private keys =="
python3 tests/test_der_keys.py "./$BUILD/mithril"

echo "== integration: sbom =="
python3 tests/test_sbom.py "./$BUILD/mithril"

echo "== integration: cve (fixture db) =="
python3 tests/test_cve.py "./$BUILD/mithril"

echo "== integration: licenses =="
python3 tests/test_licenses.py "./$BUILD/mithril"

echo "== integration: kconfig (hand-rolled DEFLATE) =="
python3 tests/test_kconfig.py "./$BUILD/mithril"

echo "== integration: kconfig recovery + tri-state kernel-CVE gating =="
python3 tests/test_kconfig_recovery.py "./$BUILD/mithril"

echo "== integration: kernel.org feed (--kernel-cves-all) =="
python3 tests/test_kernelfeed.py "./$BUILD/mithril"

echo "== all tests passed =="
