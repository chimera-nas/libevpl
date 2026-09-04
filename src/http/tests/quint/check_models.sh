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
NODE="${3:-node}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODEL="${SRC_DIR}/http1x.qnt"

# One elaboration for all six checks.  Each `quint test` / `quint run` is a
# separate process that re-parses and re-typechecks http1x.qnt, and that costs
# 3.53s against roughly 4s of actual checking -- so five of the six
# elaborations here were pure waste.  scripts/quint_batch.js drives quint's
# staged API instead: load/parse/typecheck once, then every check against the
# same typechecked model.  These ran sequentially before, so nothing is
# serialised that was not already.
#
# The random simulations below check that the positive matrix only ever emits
# requests the RFCs require a server to serve -- at the version each shape
# belongs to -- that every defect carries an outcome both specified and
# consistent with the rule that a complete request is always answered, and that
# every response defect resolves to a completion the caller can observe.
"${NODE}" "${SCRIPT_DIR}/../../../../scripts/quint_batch.js" "${QUINT}" <<SPEC
{
  "model": "${MODEL}",
  "backend": "rust",
  "tests": [
    { "main": "http1x_requests" },
    { "main": "http1x_defects" },
    { "main": "http1x_client" }
  ],
  "runs": [
    { "main": "http1x_requests", "invariant": "wellFormed", "maxSamples": 500, "maxSteps": 50 },
    { "main": "http1x_defects",  "invariant": "safety",     "maxSamples": 500, "maxSteps": 50 },
    { "main": "http1x_client",   "invariant": "safety",     "maxSamples": 500, "maxSteps": 50 }
  ]
}
SPEC
