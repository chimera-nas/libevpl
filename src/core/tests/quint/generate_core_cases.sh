#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# generate_core_cases.sh - turn core.qnt into the C program table
#
# Usage: generate_core_cases.sh QUINT PYTHON SRC_DIR WORK_DIR OUT_HEADER
#
# Driven by CMake as a build step, so everything it produces -- the ITF traces
# as well as the header -- is a build artifact under WORK_DIR rather than
# something checked in.  Run it by hand the same way if you want to inspect
# the traces.
#
# Generation is deliberately lean: it does not re-check the model, because the
# quint_core_model test does that and a build is the wrong place to discover a
# broken specification.
#
# The seeds are fixed, so a given quint version always yields the same
# programs.  Different quint versions may sample differently; that is the
# tradeoff for generating rather than checking in, and is why the devcontainer
# pins one.

set -euo pipefail

QUINT="${1:?usage: generate_core_cases.sh QUINT PYTHON SRC_DIR WORK_DIR OUT_HEADER}"
PYTHON="${2:?}"
SRC_DIR="${3:?}"
WORK_DIR="${4:?}"
OUT_HEADER="${5:?}"

mkdir -p "${WORK_DIR}"

# Unlike the RPC2 models, these traces are not a bag of independent cases that
# de-duplicate down to a taxonomy: each program is distinct, so breadth comes
# from generating more of them rather than from longer traces.
#
# Generous, because a program costs almost nothing to run.  Its windows are
# advances of libevpl's virtual clock rather than sleeps, so a 100ms window is
# a few hundred non-blocking passes of the event loop and the whole suite runs
# in well under a second.  On a real clock this many programs would be minutes.
SEEDS=(0xe1 0xe2 0xe3 0xe4 0xe5 0xe6 0xe7 0xe8 0xe9 0xea)
STEPS=260

# The seeds are independent, so they run concurrently -- serially this is the
# slowest step of the build by an order of magnitude, and it is pure waiting on
# a simulator that uses about one and a half cores.
TRACES=()
PIDS=()

for s in "${SEEDS[@]}"; do
    f="${WORK_DIR}/core-${s}.itf.json"
    "${QUINT}" run "${SRC_DIR}/core.qnt" \
        --seed="$s" --max-steps="${STEPS}" --out-itf="$f" > /dev/null &
    PIDS+=($!)
    TRACES+=("$f")
done

for pid in "${PIDS[@]}"; do
    wait "$pid" || { echo "quint run failed" >&2; exit 1; }
done

"${PYTHON}" "${SRC_DIR}/itf_to_core_cases.py" "${OUT_HEADER}" "${TRACES[@]}"
