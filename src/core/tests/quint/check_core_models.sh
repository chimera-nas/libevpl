#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# check_core_models.sh - run the core Quint model's own tests and invariants
#
# Usage: check_core_models.sh QUINT SRC_DIR
#
# Registered as a ctest so that a broken specification surfaces as a failing
# test rather than as a failing build or, worse, as a quietly wrong program
# table.  This is the model checking the model; core_conformance is what
# checks the implementation.

set -euo pipefail

QUINT="${1:?usage: check_core_models.sh QUINT SRC_DIR}"
SRC_DIR="${2:?}"

"${QUINT}" test "${SRC_DIR}/core.qnt"

# Random simulation against the invariants: every op must be one the driver
# knows, and every obligation must be attached to the quiesce that checks it.
"${QUINT}" run "${SRC_DIR}/core.qnt" \
    --invariant=safety --max-samples=500 --max-steps=60
