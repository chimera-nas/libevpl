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
#
# Split across a few seeds, several traces each, rather than one trace per
# seed.  Two costs are in play: quint parses and typechecks the model once per
# PROCESS, and simulates once per TRACE.  This model is big enough that the
# simulation is not lost in the noise, so neither extreme is right -- one
# process per trace pays the parse ten times, and one process for all ten
# serialises the simulation.  A handful of processes, each producing a
# handful of traces, pays the parse once per core and still runs them at once.
SEEDS=(0xe1 0xe2 0xe3 0xe4 0xe5)
TRACES_PER_SEED=2
STEPS=260

TRACES=()
PIDS=()

for s in "${SEEDS[@]}"; do
    "${QUINT}" run "${SRC_DIR}/core.qnt" \
        --seed="$s" --max-steps="${STEPS}" \
        --max-samples="${TRACES_PER_SEED}" --n-traces="${TRACES_PER_SEED}" \
        --out-itf="${WORK_DIR}/core-${s}-{seq}.itf.json" > /dev/null &
    PIDS+=($!)

    for i in $(seq 0 $((TRACES_PER_SEED - 1))); do
        TRACES+=("${WORK_DIR}/core-${s}-${i}.itf.json")
    done
done

for pid in "${PIDS[@]}"; do
    wait "$pid" || { echo "quint run failed" >&2; exit 1; }
done

"${PYTHON}" "${SRC_DIR}/itf_to_core_cases.py" "${OUT_HEADER}" "${TRACES[@]}"
