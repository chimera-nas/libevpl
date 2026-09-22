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
NODE="${3:-node}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


# One elaboration for every check below.  Each `quint test` / `quint run` is a
# separate process that re-parses and re-typechecks the model, and that
# dominates: elaborating core.qnt costs 3.35s against a few seconds of actual
# checking.  scripts/quint_batch.js drives quint's staged API instead --
# load/parse/typecheck once, then every check against the same typechecked
# model.  These already ran sequentially, so no parallelism is lost.
#
# --backend=typescript, everywhere.  Rust is quint's default and is 2.4x faster
# on these models, but its evaluator is published only against glibc 2.39 and
# will not run on ubuntu 22.04 or rocky 9, so those two images used to skip
# these suites entirely.  That was affordable while chimera replayed a prebuilt
# trace bundle; it stopped being affordable once every consumer generates its
# own corpus at build time, because "no working backend" became "no model-based
# tests at all on the merge queue's oldest glibc".
#
# The objection to TypeScript was never that it is wrong -- it is that a
# platform using it would compile a DIFFERENT case table from the same seed, so
# a mixed fleet would not be comparing like with like.  Pinning every platform
# to it removes that objection: the case table is different from the one the
# rust backend produced, and identical across the fleet, which is the property
# that actually matters.

# No "main": each of these files holds exactly one module, whose name does not
# match the filename (evpl_core, xdr_values, rpc2_defects), so quint resolves it
# as the file's default module -- which is what the CLI invocations relied on by
# passing no --main.  Naming one explicitly would have to name it correctly.
"${NODE}" "${SCRIPT_DIR}/../../../../scripts/quint_batch.js" "${QUINT}" <<SPEC
{
  "model": "${SRC_DIR}/core_generation.qnt",
  "backend": "typescript",
  "tests": [ {} ],
  "runs": [
    { "init": "initStream", "step": "stepMixed", "invariant": "safety", "maxSamples": 200, "maxSteps": 65 },
    { "init": "initSmallDatagram", "step": "stepTransport", "invariant": "safety", "maxSamples": 100, "maxSteps": 65 },
    { "init": "initStream", "step": "stepBlock", "invariant": "safety", "maxSamples": 100, "maxSteps": 65 }
  ]
}
SPEC

for model in fd lifecycle block_lifecycle listener ownership block_retry; do
    "$QUINT" test --backend=typescript "$SRC_DIR/$model.qnt"
    "$QUINT" run --backend=typescript "$SRC_DIR/$model.qnt" --invariant=inv \
        --seed=991 --max-steps=128 --max-samples=32 --verbosity=0
done
