#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# generate_cases.sh - turn http10.qnt into the C case table
#
# Usage: generate_cases.sh QUINT PYTHON SRC_DIR WORK_DIR OUT_HEADER
#
# Driven by CMake as a build step, so everything it produces -- the ITF traces
# as well as the header -- is a build artifact under WORK_DIR rather than
# something checked in.  Run it by hand the same way if you want to inspect the
# traces.
#
# Generation is deliberately lean: it does not re-check the model, because the
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

# The positive matrix is a cross product of six dimensions, so it is sampled
# rather than enumerated: enough traces to cover the pairs that matter without
# opening several thousand TCP connections per run.  The defect taxonomy is
# small and enumerable, so its traces only need to be long enough to reach
# every (defect, delivery) pair -- the case count printed at the end is the
# check on that, and must equal the size of that cross product.
REQUEST_SEEDS=(0x21 0x22 0x23 0x24)
DEFECT_SEEDS=(0x41 0x42 0x43 0x44 0x45 0x46)

REQUEST_TRACES=()
for s in "${REQUEST_SEEDS[@]}"; do
    f="${WORK_DIR}/requests-${s}.itf.json"
    "${QUINT}" run "${SRC_DIR}/http10.qnt" --main=http10_requests \
        --seed="$s" --max-steps=150 --out-itf="$f" > /dev/null
    REQUEST_TRACES+=("$f")
done

DEFECT_TRACES=()
for s in "${DEFECT_SEEDS[@]}"; do
    f="${WORK_DIR}/defects-${s}.itf.json"
    "${QUINT}" run "${SRC_DIR}/http10.qnt" --main=http10_defects \
        --seed="$s" --max-steps=300 --out-itf="$f" > /dev/null
    DEFECT_TRACES+=("$f")
done

"${PYTHON}" "${SRC_DIR}/itf_to_cases.py" "${OUT_HEADER}" \
    "${REQUEST_TRACES[@]}" -- "${DEFECT_TRACES[@]}"
