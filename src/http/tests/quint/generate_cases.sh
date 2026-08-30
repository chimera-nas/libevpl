#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# generate_cases.sh - turn http1x.qnt into the C case table
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

# The positive matrix is a cross product of eight dimensions, so it is sampled
# rather than enumerated: enough traces to cover the pairs that matter without
# opening several thousand TCP connections per run.  The defect taxonomy is
# small and enumerable, so its traces only need to be long enough to reach
# every (defect, version, delivery) triple -- the case count printed at the end
# is the check on that, and must equal the size of that cross product.
#
# One quint invocation per group rather than one per trace.  Nearly all of a
# quint run is parsing and typechecking the model -- for this one, 2.1s of a
# 2.2s invocation -- so the cost is per PROCESS, not per trace, and --n-traces
# pays it once for the whole group instead of once each.  The three groups then
# run concurrently because they are independent.
REQUEST_TRACES=6
DEFECT_TRACES=12
CLIENT_TRACES=12

REQUEST_SEED=0x21
DEFECT_SEED=0x41
CLIENT_SEED=0x61

# gen MAIN STEPS NTRACES SEED PREFIX
gen() {
    "${QUINT}" run "${SRC_DIR}/http1x.qnt" --main="$1" \
        --max-steps="$2" --max-samples="$3" --n-traces="$3" --seed="$4" \
        --out-itf="${WORK_DIR}/$5-{seq}.itf.json" > /dev/null
}

gen http1x_requests 200 "${REQUEST_TRACES}" "${REQUEST_SEED}" requests &
pids="$!"
gen http1x_defects  300 "${DEFECT_TRACES}"  "${DEFECT_SEED}"  defects  &
pids="${pids} $!"
gen http1x_client   300 "${CLIENT_TRACES}"  "${CLIENT_SEED}"  client   &
pids="${pids} $!"

for pid in ${pids}; do
    wait "${pid}" || { echo "quint run failed" >&2; exit 1; }
done

"${PYTHON}" "${SRC_DIR}/itf_to_cases.py" "${OUT_HEADER}" \
    "${WORK_DIR}"/requests-*.itf.json -- \
    "${WORK_DIR}"/defects-*.itf.json -- \
    "${WORK_DIR}"/client-*.itf.json
