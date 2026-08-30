#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# generate_cases.sh - turn the Quint models into the C case table
#
# Usage: generate_cases.sh QUINT PYTHON SRC_DIR WORK_DIR OUT_HEADER
#
# Driven by CMake as a build step, so everything it produces -- the ITF traces
# as well as the header -- is a build artifact under WORK_DIR rather than
# something checked in.  Run it by hand the same way if you want to inspect the
# traces.
#
# Generation is deliberately lean: it does not re-check the models, because the
# quint_model test does that and a build is the wrong place to discover a
# broken specification.
#
# The seeds are fixed, so a given quint version always yields the same cases.
# Different quint versions may sample differently; that is the tradeoff for
# generating rather than checking in, and is why the devcontainer pins one.

set -euo pipefail

QUINT="${1:?usage: generate_cases.sh QUINT PYTHON SRC_DIR WORK_DIR OUT_HEADER}"
PYTHON="${2:?}"
SRC_DIR="${3:?}"
WORK_DIR="${4:?}"
OUT_HEADER="${5:?}"

mkdir -p "${WORK_DIR}"

# The value matrix is a wide cross-product, so it is sampled: several traces,
# long ones, de-duplicated by the converter.  The defect taxonomy is small and
# enumerable, so its traces only need to be long enough to reach every
# (defect, target) pair -- the case count printed at the end is the check on
# that.
#
# One quint invocation per model rather than one per trace: nearly all of a
# quint run is parsing and typechecking, so the cost is per PROCESS and
# --n-traces pays it once for the group.  The two models are independent and
# run concurrently.
VALUE_TRACES=10
DEFECT_TRACES=4

VALUE_SEED=0xa1
DEFECT_SEED=0xb1

"${QUINT}" run "${SRC_DIR}/values.qnt" --max-steps=200 \
    --max-samples="${VALUE_TRACES}" --n-traces="${VALUE_TRACES}" \
    --seed="${VALUE_SEED}" \
    --out-itf="${WORK_DIR}/values-{seq}.itf.json" > /dev/null &
values_pid=$!

"${QUINT}" run "${SRC_DIR}/defects.qnt" --max-steps=400 \
    --max-samples="${DEFECT_TRACES}" --n-traces="${DEFECT_TRACES}" \
    --seed="${DEFECT_SEED}" \
    --out-itf="${WORK_DIR}/defects-{seq}.itf.json" > /dev/null &
defects_pid=$!

wait "${values_pid}" || { echo "quint run failed (values)" >&2; exit 1; }
wait "${defects_pid}" || { echo "quint run failed (defects)" >&2; exit 1; }

"${PYTHON}" "${SRC_DIR}/itf_to_cases.py" "${OUT_HEADER}" \
    --values "${WORK_DIR}"/values-*.itf.json \
    --defects "${WORK_DIR}"/defects-*.itf.json
