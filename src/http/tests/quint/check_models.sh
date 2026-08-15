#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# check_models.sh - run the HTTP/1.x model's scenario tests and invariants
#
# Usage: check_models.sh QUINT SRC_DIR
#
# Registered as a ctest so that a broken specification surfaces as a failing
# test rather than as a failing build or, worse, as a quietly wrong case table.
# This is the model checking the model; the conformance test that consumes its
# output is what checks the implementation.
#
# http1x.qnt holds four modules, so every invocation names the one it means:
# without --main quint looks for a module matching the file name, which is the
# shared vocabulary and has no tests of its own.

set -euo pipefail

QUINT="${1:?usage: check_models.sh QUINT SRC_DIR}"
SRC_DIR="${2:?}"

MODEL="${SRC_DIR}/http1x.qnt"

"${QUINT}" test "${MODEL}" --main=http1x_requests
"${QUINT}" test "${MODEL}" --main=http1x_defects
"${QUINT}" test "${MODEL}" --main=http1x_client

# Random simulation against the invariants: the positive matrix must only ever
# emit requests the RFCs require a server to serve -- at the version each shape
# belongs to -- every defect must carry an outcome that is both specified and
# consistent with the rule that a complete request is always answered, and
# every response defect must resolve to a completion the caller can observe.
"${QUINT}" run "${MODEL}" --main=http1x_requests \
    --invariant=wellFormed --max-samples=500 --max-steps=50
"${QUINT}" run "${MODEL}" --main=http1x_defects \
    --invariant=safety --max-samples=500 --max-steps=50
"${QUINT}" run "${MODEL}" --main=http1x_client \
    --invariant=safety --max-samples=500 --max-steps=50
