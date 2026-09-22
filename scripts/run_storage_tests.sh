#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
# The same behavioral traces run on each storage adapter. Device selection
# belongs here, never in the Quint model.
set -euo pipefail
out=/workspace/coverage-output
ctest --test-dir /build -L '^mbt_storage$' --show-only=json-v1 > "$out/storage-tests.json"
python3 scripts/ci_mbt_matrix.py storage-tests "$out/storage-tests.json"
status=0
for backend in libaio io_uring vfio; do
    mkdir -p "/build/coverage/profraw/$backend"
    uri=("EVPL_TEST_BLOCK_URI=$(cat "$out/kernel-nvme-device")")
    if [[ "$backend" == vfio ]]; then uri=(EVPL_TEST_BLOCK_URI=00:04.0); fi
    env "${uri[@]}" LLVM_PROFILE_FILE="/build/coverage/profraw/$backend/%m-%p.profraw" \
        ctest --test-dir /build -R "^libevpl/core/(core|listener)_conformance_${backend}_" \
        --output-on-failure --no-tests=error --timeout 300 -j 1 \
        --output-junit "$out/$backend-model-results.xml" || status=$?
    COVERAGE_PROFILE_DIR="/build/coverage/profraw/$backend" \
        COVERAGE_JSON="$out/$backend-coverage-export.json" bash etc/coverage-report.sh /build
    python3 scripts/ci_mbt_matrix.py execution "$out/$backend-coverage-export.json" \
        --root /workspace --require "$backend" || status=$?
done
exit "$status"
