#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# check_models.sh - run the Quint models' own scenario tests and invariants
#
# Usage: check_models.sh QUINT SRC_DIR
#
# Registered as a ctest so that a broken specification surfaces as a failing
# test rather than as a failing build or, worse, as a quietly wrong case table.
# This is the model checking the model; the conformance test that consumes its
# output is what checks the implementation.

set -euo pipefail

QUINT="${1:?usage: check_models.sh QUINT SRC_DIR}"
SRC_DIR="${2:?}"

"${QUINT}" test "${SRC_DIR}/values.qnt"
"${QUINT}" test "${SRC_DIR}/defects.qnt"

# Random simulation against the invariants: the value model must only ever
# emit legal input, and every defect must carry a specified outcome.
"${QUINT}" run "${SRC_DIR}/values.qnt" \
    --invariant=wellFormed --max-samples=500 --max-steps=50
"${QUINT}" run "${SRC_DIR}/defects.qnt" \
    --invariant=safety --max-samples=500 --max-steps=50
