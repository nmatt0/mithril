#!/usr/bin/env bash
# Build mithril. Needs cmake + a C++20 compiler (g++ 13+ / clang 16+). No runtime deps.
#   skills/mithril/scripts/bootstrap.sh
set -euo pipefail
cd "$(dirname "$0")/.."
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
echo "built ./build/mithril (and ./build/mithril_unit)"
