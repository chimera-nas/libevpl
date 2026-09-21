#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
# Run inside the devcontainer after configuring and building Coverage.
set -euo pipefail
build=${1:?usage: run_mbt_coverage.sh BUILD_DIR OUTPUT_DIR DIFF}
out=${2:?}
diff=${3:?}
mkdir -p "$out"
# A nonempty suite is insufficient: catch accidentally disabled model families.
ctest --test-dir "$build" -L '^mbt$' --show-only=json-v1 > "$out/tests.json"
python3 - "$out/tests.json" <<'PY'
import json, re, sys
names = [t['name'] for t in json.load(open(sys.argv[1]))['tests']]
for prefix in ('libevpl/core/core_conformance_', 'libevpl/http/conformance$',
               'libevpl/http/conformance_client', 'libevpl/rpc2/conformance_STREAM_',
               'libevpl/rpc2/conformance_client_'):
    if not any(re.match(prefix, n) for n in names):
        raise SystemExit('Missing MBT replay family: ' + prefix)
PY
rm -rf "${build:?}/coverage"
mkdir -p "$build/coverage/profraw"
LLVM_PROFILE_FILE="$build/coverage/profraw/%m-%p.profraw" \
    ctest --test-dir "$build" -L '^mbt$' --output-on-failure \
    --no-tests=error --timeout 600 --output-junit "$out/results.xml" -j "$(nproc)"
python3 scripts/ci_patch_coverage.py --sources "$diff" > "$out/sources.txt"
COVERAGE_JSON="$out/coverage-export.json" COVERAGE_LCOV="$out/patch-coverage.lcov" \
    COVERAGE_LCOV_SOURCES="$out/sources.txt" bash etc/coverage-report.sh "$build"
python3 scripts/ci_coverage_report.py "$out/coverage-export.json" "$PWD" "${RUN_URL:-}" > "$out/coverage-report.md"
python3 scripts/ci_patch_coverage.py "$diff" "$out/patch-coverage.lcov" "$PWD" \
    "${GH_REPO:-}" "${SOURCE_SHA:-}" >> "$out/coverage-report.md"
