#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
# Run inside the devcontainer after configuring and building Coverage.
set -euo pipefail
build=${1:?usage: run_mbt_coverage.sh BUILD_DIR OUTPUT_DIR DIFF [libfabric spdk]}
out=${2:?}
diff=${3:?}
mkdir -p "$out"
# A nonempty suite is insufficient: catch accidentally disabled model families.
ctest --test-dir "$build" -L '^mbt$' --show-only=json-v1 > "$out/tests.json"
shift 3
required=("$@")
python3 scripts/ci_mbt_matrix.py tests "$out/tests.json" --require "${required[@]}"
rm -rf "${build:?}/coverage"
mkdir -p "$build/coverage/profraw"
# Each replay may drive a host, wire peer and several reactor threads.
# Bound concurrency; callers can override it on a dedicated larger runner.
LLVM_PROFILE_FILE="$build/coverage/profraw/%m-%p.profraw" \
    ctest --test-dir "$build" -L '^mbt$' --output-on-failure \
    --no-tests=error --timeout 600 --output-junit "$out/results.xml" -j "${CTEST_PARALLEL_LEVEL:-2}"
python3 scripts/ci_patch_coverage.py --sources "$diff" > "$out/sources.txt"
COVERAGE_JSON="$out/coverage-export.json" COVERAGE_LCOV="$out/patch-coverage.lcov" \
    COVERAGE_LCOV_SOURCES="$out/sources.txt" bash etc/coverage-report.sh "$build"
python3 scripts/ci_mbt_matrix.py execution "$out/coverage-export.json" --root "$PWD" \
    --require "${required[@]}"
python3 scripts/ci_coverage_report.py "$out/coverage-export.json" "$PWD" "${RUN_URL:-}" > "$out/coverage-report.md"
python3 scripts/ci_patch_coverage.py "$diff" "$out/patch-coverage.lcov" "$PWD" \
    "${GH_REPO:-}" "${SOURCE_SHA:-}" >> "$out/coverage-report.md"
