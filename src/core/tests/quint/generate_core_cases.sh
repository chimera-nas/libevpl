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

# Each profile walks legal transitions with a different focus. No profile
# prescribes operation positions. Limits describe inputs, not providers.
profiles=(Stream Message Datagram SmallDatagram Block Events Mixed Poll Pressure)
inits=(initStream initMessage initDatagram initSmallDatagram initStream initStream initStream initPoll initStream)
steps=(stepTransport stepTransport stepTransport stepTransport stepBlock stepEvents stepMixed stepPoll stepPressure)
traces=()
pids=()
for i in "${!profiles[@]}"; do
    prefix="$WORK_DIR/core-${profiles[$i]}"
    "$QUINT" run --backend=typescript "$SRC_DIR/core_generation.qnt" \
        --init="${inits[$i]}" --step="${steps[$i]}" --seed="$((225 + i))" \
        --max-steps=520 --max-samples=2 --n-traces=2 \
        --out-itf="$prefix-{seq}.itf.json" > /dev/null &
    pids+=($!)
    traces+=("$prefix-0.itf.json" "$prefix-1.itf.json")
done
for pid in "${pids[@]}"; do
    wait "$pid" || { echo "quint generation failed" >&2; exit 1; }
done
"$PYTHON" "$SRC_DIR/itf_to_core_cases.py" "$OUT_HEADER" "${traces[@]}"
