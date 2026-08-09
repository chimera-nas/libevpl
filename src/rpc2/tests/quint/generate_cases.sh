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

# The value matrix is a wide cross-product, so it is sampled: several seeds,
# long traces, de-duplicated by the converter.  The defect taxonomy is small
# and enumerable, so its traces only need to be long enough to reach every
# (defect, target) pair -- the case count printed at the end is the check on
# that.
VALUE_SEEDS=(0xa1 0xa2 0xa3 0xa4 0xa5 0xa6 0xa7 0xa8)
DEFECT_SEEDS=(0xb1 0xb2 0xb3 0xb4)

VALUE_TRACES=()
for s in "${VALUE_SEEDS[@]}"; do
    f="${WORK_DIR}/values-${s}.itf.json"
    "${QUINT}" run "${SRC_DIR}/values.qnt" \
        --seed="$s" --max-steps=200 --out-itf="$f" > /dev/null
    VALUE_TRACES+=("$f")
done

DEFECT_TRACES=()
for s in "${DEFECT_SEEDS[@]}"; do
    f="${WORK_DIR}/defects-${s}.itf.json"
    "${QUINT}" run "${SRC_DIR}/defects.qnt" \
        --seed="$s" --max-steps=400 --out-itf="$f" > /dev/null
    DEFECT_TRACES+=("$f")
done

"${PYTHON}" "${SRC_DIR}/itf_to_cases.py" "${OUT_HEADER}" \
    --values "${VALUE_TRACES[@]}" \
    --defects "${DEFECT_TRACES[@]}"
