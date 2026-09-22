#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only
"""Retain source-level function coverage, merging inline instantiations."""
import csv
import json
import os
import sys
from ci_coverage_report import measurable, relative


def functions(data, root):
    result = {}
    for unit in data.get('data', []):
        for fn in unit.get('functions', []):
            region = fn['regions'][0]
            filename = fn['filenames'][region[5]]
            path = relative(os.path.realpath(filename), (os.path.realpath(root),))
            if path is None or not measurable(path):
                continue
            name = fn['name'].rsplit(':', 1)[-1]
            key = path, region[0], name
            result[key] = result.get(key, 0) + fn['count']
    return [dict(file=p, line=line, function=name, count=count)
            for (p, line, name), count in sorted(result.items())]


if __name__ == '__main__':
    rows = functions(json.load(sys.stdin), sys.argv[1])
    if not rows:
        raise SystemExit('No library functions in coverage export')
    writer = csv.DictWriter(sys.stdout, fieldnames=('file', 'line', 'function', 'count'))
    writer.writeheader()
    writer.writerows(rows)
