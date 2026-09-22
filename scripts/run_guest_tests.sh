#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
set -uo pipefail
status=0
bash scripts/run_rdma_tests.sh || status=$?
bash scripts/run_storage_tests.sh || status=$?
exit "$status"
