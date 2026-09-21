#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
set -euo pipefail
out=/workspace/coverage-output
regression_status=0
# Ordinary integration tests must not contribute to the model-only report.
LLVM_PROFILE_FILE=/tmp/rdma-regression-%m-%p.profraw \
    ctest --test-dir /build -L '^rdma$' --output-on-failure --no-tests=error \
    --timeout 120 --output-junit "$out/rdma-regressions.xml" -j 1 || regression_status=$?

mkdir -p /build/coverage/profraw/rdma
ctest --test-dir /build -L '^mbt_rdma$' --show-only=json-v1 > "$out/rdma-tests.json"
python3 scripts/ci_mbt_matrix.py rdma-tests "$out/rdma-tests.json"
LLVM_PROFILE_FILE=/build/coverage/profraw/rdma/%m-%p.profraw \
    ctest --test-dir /build -L '^mbt_rdma$' --output-on-failure --no-tests=error \
    --timeout 300 --output-junit "$out/rdma-model-results.xml" -j 1
# Verify the guest batch independently: native device enumeration alone must
# not satisfy the combined report's RDMA execution check.
COVERAGE_PROFILE_DIR=/build/coverage/profraw/rdma \
    COVERAGE_JSON="$out/rdma-coverage-export.json" bash etc/coverage-report.sh /build
python3 scripts/ci_mbt_matrix.py execution "$out/rdma-coverage-export.json" \
    --root /workspace --require rdma
exit "$regression_status"
