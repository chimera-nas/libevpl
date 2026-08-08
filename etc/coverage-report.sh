#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# coverage-report.sh - Merge clang source-based coverage data and print a report
#
# Usage: coverage-report.sh BUILD_DIR
#
# Expects the test suite to have already run with the binaries instrumented by a
# Coverage build (-fprofile-instr-generate -fcoverage-mapping) and with
# LLVM_PROFILE_FILE pointing into BUILD_DIR/coverage/profraw (see the Makefile's
# test_coverage target). This merges every *.profraw into a single profdata file
# and prints a per-file llvm-cov report covering the libevpl source tree.
#
# Set COVERAGE_HTML=1 to additionally emit a browsable HTML report under
# BUILD_DIR/coverage/html.

set -euo pipefail

BUILD_DIR="${1:?usage: coverage-report.sh BUILD_DIR}"
COV_DIR="${BUILD_DIR}/coverage"
PROFRAW_DIR="${COV_DIR}/profraw"
PROFDATA="${COV_DIR}/coverage.profdata"

PROFDATA_TOOL="${LLVM_PROFDATA:-llvm-profdata}"
COV_TOOL="${LLVM_COV:-llvm-cov}"

# Drop everything that isn't first-party libevpl source from the report.  The
# submodules (xdrzcc, prometheus-c, oteltracing-c) live under ext/ and the
# vendored headers under 3rdparty/, so libevpl's own code is what remains.
#
# These are anchored to libevpl's own source root rather than written as bare
# /ext/ and /3rdparty/: libevpl is itself commonly checked out *inside* another
# project's ext/ directory (chimera keeps it at ext/libevpl), and an unanchored
# pattern would then match every path in this tree and empty the whole report.
SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
esc_src=$(printf '%s' "${SRC_DIR}" | sed 's/[.[\*^$()+?{|/]/\\&/g')
IGNORE_REGEX="(${esc_src}/ext/|${esc_src}/3rdparty/|/usr/|/CMakeFiles/)"

# By default, also exclude generated code so it doesn't distort the totals.
# Generated sources (the xdrzcc XDR marshallers for rpc2, etc.) are emitted into
# the build tree, whereas hand-written sources live under the source tree -- so
# "compiled from under BUILD_DIR" is a reliable, generator-agnostic way to spot
# generated code. Set COVERAGE_INCLUDE_GENERATED=1 to fold it back into the
# report, which is what you want when the question is how well the generated
# marshallers themselves are exercised.
INCLUDE_GENERATED="${COVERAGE_INCLUDE_GENERATED:-0}"
if [[ "${INCLUDE_GENERATED}" == "1" ]]; then
    echo "coverage: including generated code (COVERAGE_INCLUDE_GENERATED=1)"
else
    abs_build=$(readlink -f "${BUILD_DIR}")
    # Escape regex metacharacters so the path is matched literally.
    esc_build=$(printf '%s' "${abs_build}" | sed 's/[.[\*^$()+?{|/]/\\&/g')
    IGNORE_REGEX="(${esc_build}/|${esc_src}/ext/|${esc_src}/3rdparty/|/usr/|/CMakeFiles/)"
    echo "coverage: excluding generated code under ${abs_build} (set COVERAGE_INCLUDE_GENERATED=1 to include)"
fi

# A full suite run produces one .profraw per test process (and per daemon a test
# spawns), which can overflow ARG_MAX if globbed onto the command line. Build a
# newline-separated list file and hand it to llvm-profdata via --input-files
# instead.
raw_list="${COV_DIR}/profraw.list"
find "${PROFRAW_DIR}" -type f -name '*.profraw' > "${raw_list}"
raw_count=$(wc -l < "${raw_list}")
if [[ "${raw_count}" -eq 0 ]]; then
    echo "coverage: no .profraw files found under ${PROFRAW_DIR}" >&2
    echo "coverage: did the tests run against a Coverage build with LLVM_PROFILE_FILE set?" >&2
    exit 1
fi

echo "coverage: merging ${raw_count} raw profile(s) ..."
"${PROFDATA_TOOL}" merge -sparse --input-files="${raw_list}" -o "${PROFDATA}"

# Collect the instrumented binaries: any executable or shared object in the
# build tree that carries an __llvm_covmap section. llvm-cov fails outright if
# handed an object with no coverage mapping, so we must filter rather than glob.
# NB: the section list is captured into a variable rather than piped into
# grep.  Under `set -o pipefail`, `readelf ... | grep -q` reports failure
# whenever grep finds its match early, exits, and leaves readelf to die of
# SIGPIPE -- so a matching binary is racily reported as NOT instrumented and
# silently dropped from the report.
objs=()
while IFS= read -r f; do
    sections=$(readelf -SW "$f" 2>/dev/null || true)
    if [[ "${sections}" == *__llvm_covmap* ]]; then
        objs+=("$f")
    fi
done < <(find "${BUILD_DIR}" -type f \
            \( -perm -u+x -o -name '*.so' -o -name '*.so.*' \) \
            ! -path '*/CMakeFiles/*')

if [[ ${#objs[@]} -eq 0 ]]; then
    echo "coverage: no instrumented binaries found under ${BUILD_DIR}" >&2
    exit 1
fi

# llvm-cov takes the first object positionally and the rest via -object.
object_args=()
for o in "${objs[@]:1}"; do
    object_args+=(-object "$o")
done

echo "coverage: reporting over ${#objs[@]} instrumented binaries"
echo
"${COV_TOOL}" report "${objs[0]}" "${object_args[@]}" \
    -instr-profile="${PROFDATA}" \
    -ignore-filename-regex="${IGNORE_REGEX}" \
    -show-region-summary=false

if [[ "${COVERAGE_HTML:-0}" == "1" ]]; then
    HTML_DIR="${COV_DIR}/html"
    echo
    echo "coverage: writing HTML report to ${HTML_DIR} ..."
    "${COV_TOOL}" show "${objs[0]}" "${object_args[@]}" \
        -instr-profile="${PROFDATA}" \
        -ignore-filename-regex="${IGNORE_REGEX}" \
        -format=html -output-dir="${HTML_DIR}" \
        -show-line-counts-or-regions
    echo "coverage: open ${HTML_DIR}/index.html"
fi
