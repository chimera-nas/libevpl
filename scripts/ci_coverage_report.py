#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: Unlicense
"""Render llvm-cov export -summary-only as an MBT coverage comment.

Usage: ci_coverage_report.py export.json repo_root [run_url]
Adapted from Chimera's coverage report. Counts first-party library code only.
"""
import json
import os
import sys

MARKER = "<!-- mbt-coverage-report -->"

# The selection this report measures, as something to paste.  The make target
# builds Coverage, runs the label with LLVM_PROFILE_FILE set, and then runs
# etc/coverage-report.sh over the result -- exactly what CI does.
REPRO = 'make coverage CTEST_ARGS_COVERAGE="-L mbt --output-on-failure --no-tests=error"'

METRICS = ("functions", "lines", "branches")

BAR_WIDTH = 10


def component(rel):
    """Separate core backends from the common core, HTTP and RPC2."""
    parts = rel.split("/")
    if len(parts) >= 4 and parts[:2] == ["src", "core"]:
        return "/".join(parts[:3])
    return "/".join(parts[:2])


def measurable(rel):
    return (rel.startswith(("src/", "include/"))
            and rel.endswith((".c", ".h"))
            and "/tests/" not in rel)


def relative(path, roots):
    """Path relative to whichever root contains it, or None if none does.

    Longest root wins, so an in-tree build directory (build/ inside the
    checkout) attributes its generated sources to the build tree rather than
    to a "build/..." component of the source tree.
    """
    for root in sorted((r for r in roots if r), key=len, reverse=True):
        rel = os.path.relpath(path, root)
        if rel != ".." and not rel.startswith("../"):
            return rel
    return None


def cell(covered, count):
    """One metric as a bar, a percentage and the raw pair.

    Two lines rather than one: three of these per row on a single line forces a
    horizontal scrollbar onto the comment, which is where a wide table stops
    being read at all.
    """
    if not count:
        return "—"
    percent = 100.0 * covered / count
    filled = int(round(percent / 100.0 * BAR_WIDTH))
    bar = "█" * filled + "░" * (BAR_WIDTH - filled)
    return f"`{bar}` {percent:.0f}%<br>{covered:,}/{count:,}"


def main():
    export_path, root = sys.argv[1], os.path.realpath(sys.argv[2])
    run_url = sys.argv[3] if len(sys.argv) > 3 else ""
    build_root = os.path.realpath(sys.argv[4]) if len(sys.argv) > 4 else ""

    with open(export_path) as f:
        data = json.load(f)

    comps = {}
    for entry in data.get("data", [{}])[0].get("files", []):
        rel = relative(os.path.realpath(entry["filename"]), (root, build_root))
        # Only library sources owned by this checkout enter the denominator.
        if rel is None or not measurable(rel):
            continue
        summary = entry.get("summary", {})
        if summary.get("lines", {}).get("count", 0) == 0:
            continue
        totals = comps.setdefault(component(rel),
                                  {m: [0, 0] for m in METRICS})
        for metric in METRICS:
            got = summary.get(metric, {})
            totals[metric][0] += got.get("count", 0)
            totals[metric][1] += got.get("covered", 0)

    title = "Quint model-based test coverage"
    out = [MARKER, "",
           f"## [{title}]({run_url})" if run_url else f"## {title}", ""]

    if not comps:
        raise SystemExit("No instrumented libevpl source in coverage export")

    out += ["C code exercised by the Core, HTTP and RPC2 model trace replays "
            "(`ctest -L mbt`). Linux devcontainer build; other platforms and "
            "unbuilt code are not measured. This is code coverage, not model "
            "state/transition coverage.", ""]

    if os.environ.get('MBT_STORAGE_COVERAGE') == '1':
        out += ["Includes libaio, io_uring and direct io_uring_nvme replays on a disposable NVMe "
                "namespace, and VFIO replays on a second NVMe controller behind "
                "the guest IOMMU. Their model profiles enter the same union.", ""]

    if os.environ.get('MBT_RDMA_COVERAGE') == '1':
        out += ["Includes native RDMA model replays in a Soft-RoCE KVM guest "
                "running the same container and instrumented binaries. Native "
                "and guest LLVM profiles are merged before counting coverage; "
                "ordinary RDMA integration tests are excluded.", ""]

    out += ["| Component | Functions | Lines | Branches |",
            "|---|---|---|---|"]

    grand = {m: [0, 0] for m in METRICS}
    for name, totals in sorted(comps.items(),
                               key=lambda kv: -kv[1]["lines"][0]):
        cells = []
        for metric in METRICS:
            count, covered = totals[metric]
            grand[metric][0] += count
            grand[metric][1] += covered
            cells.append(cell(covered, count))
        out.append(f"| `{name}` | " + " | ".join(cells) + " |")

    out.append("| **Total** | "
               + " | ".join(cell(grand[m][1], grand[m][0]) for m in METRICS)
               + " |")

    out += ["", "```sh", REPRO, "```"]
    print("\n".join(out))


if __name__ == "__main__":
    main()
