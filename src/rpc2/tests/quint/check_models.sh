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
NODE="${3:-node}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


# One elaboration for every check below.  Each `quint test` / `quint run` is a
# separate process that re-parses and re-typechecks the model, and that
# dominates: elaborating values.qnt and defects.qnt costs 0.63s and 1.02s against a few seconds of actual
# checking.  scripts/quint_batch.js drives quint's staged API instead --
# load/parse/typecheck once, then every check against the same typechecked
# model.  These already ran sequentially, so no parallelism is lost.
#
# --backend=rust, quint's default and the fast one.  TypeScript would let
# ubuntu 22.04 and rocky 9 run these too -- it needs no Rust evaluator -- but it
# is 2.4x slower on these models and generates a different corpus from the same
# seed, so those two images would compile a different case table from every
# other platform.  They keep skipping these suites instead.

# Two models, so two elaborations rather than one; each still serves both of
# its own checks instead of one apiece.
# No "main": each of these files holds exactly one module, whose name does not
# match the filename (evpl_core, xdr_values, rpc2_defects), so quint resolves it
# as the file's default module -- which is what the CLI invocations relied on by
# passing no --main.  Naming one explicitly would have to name it correctly.
for m in values:wellFormed defects:safety; do
    "${NODE}" "${SCRIPT_DIR}/../../../../scripts/quint_batch.js" "${QUINT}" <<SPEC
{
  "model": "${SRC_DIR}/${m%%:*}.qnt",
  "backend": "rust",
  "tests": [ {} ],
  "runs": [
    { "invariant": "${m##*:}", "maxSamples": 500, "maxSteps": 50 }
  ]
}
SPEC
done
