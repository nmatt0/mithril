#!/usr/bin/env bash
# build.sh — compile the secrets fuzz target with libFuzzer + ASan/UBSan.
# Usage: fuzz/build.sh && ./fuzz/fuzz_secrets -max_total_time=60
set -euo pipefail
cd "$(dirname "$0")/.."

CXX=${CXX:-clang++}
# Compile the whole src tree except main.cpp (libFuzzer supplies its own main),
# so the fuzz build never drifts out of sync when a new module is added (a
# hardcoded list previously dropped kconfig_infer.cpp and failed to link).
mapfile -t SRCS < <(find src -name '*.cpp' ! -name 'main.cpp' | sort)
"$CXX" -std=c++20 -O1 -g \
    -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
    -I src \
    "${SRCS[@]}" fuzz/fuzz_secrets.cpp \
    -o fuzz/fuzz_secrets

echo "built fuzz/fuzz_secrets — run: ./fuzz/fuzz_secrets -max_total_time=60"
