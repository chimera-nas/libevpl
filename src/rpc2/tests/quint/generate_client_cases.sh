#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# generate_client_cases.sh - turn client.qnt into the C case table
#
# Usage: generate_client_cases.sh QUINT PYTHON SRC_DIR WORK_DIR OUT_HEADER
#
# The client-side twin of generate_cases.sh.  Driven by CMake as a build step,
# so everything it produces -- the ITF traces as well as the header -- is a
# build artifact under WORK_DIR rather than something checked in.  Run it by
# hand the same way if you want to inspect the traces.
#
# Generation is deliberately lean: it does not re-check the model, because the
# quint_client_model test does that and a build is the wrong place to discover
# a broken specification.
#
# The seeds are fixed, so a given quint version always yields the same cases.
# Different quint versions may sample differently; that is the tradeoff for
# generating rather than checking in, and is why the devcontainer pins one.

set -euo pipefail

QUINT="${1:?usage: generate_client_cases.sh QUINT PYTHON SRC_DIR WORK_DIR OUT_HEADER}"
PYTHON="${2:?}"
SRC_DIR="${3:?}"
WORK_DIR="${4:?}"
OUT_HEADER="${5:?}"

mkdir -p "${WORK_DIR}"

# The taxonomy is small and enumerable, so the traces only need to be long
# enough to reach every (defect, delivery) pair.  The case count printed at the
# end is the check on that: it must equal the size of the cross product the
# model declares, minus the pairs the converter collapses.
SEEDS=(0xc1 0xc2 0xc3 0xc4 0xc5 0xc6)

TRACES=()
for s in "${SEEDS[@]}"; do
    f="${WORK_DIR}/client-${s}.itf.json"
    "${QUINT}" run "${SRC_DIR}/client.qnt" \
        --seed="$s" --max-steps=400 --out-itf="$f" > /dev/null
    TRACES+=("$f")
done

"${PYTHON}" "${SRC_DIR}/itf_to_client_cases.py" "${OUT_HEADER}" "${TRACES[@]}"
