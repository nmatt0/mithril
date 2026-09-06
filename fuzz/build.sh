#!/usr/bin/env bash
# build.sh — compile the secrets fuzz target with libFuzzer + ASan/UBSan.
# Usage: fuzz/build.sh && ./fuzz/fuzz_secrets -max_total_time=60
set -euo pipefail
cd "$(dirname "$0")/.."

CXX=${CXX:-clang++}
"$CXX" -std=c++20 -O1 -g \
    -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
    -I src \
    src/ahocorasick.cpp src/validators.cpp src/rules_builtin.cpp src/engine.cpp \
    src/credstore.cpp src/binver.cpp src/filever.cpp src/inflate.cpp src/kconfig.cpp src/kernelcve.cpp src/version.cpp src/langmanifest.cpp src/rpm.cpp src/license.cpp src/sbom.cpp fuzz/fuzz_secrets.cpp \
    -o fuzz/fuzz_secrets

echo "built fuzz/fuzz_secrets — run: ./fuzz/fuzz_secrets -max_total_time=60"
