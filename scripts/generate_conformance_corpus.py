#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
"""Generate the same C case tables for every native CI architecture."""
import concurrent.futures
import pathlib
import shutil
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
output = pathlib.Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
quint = shutil.which("quint")
if not quint:
    raise SystemExit("quint must be on PATH")

jobs = [
    ("core", "generate_core_cases.sh", "core_cases.h"),
    ("http", "generate_cases.sh", "http_cases.h"),
    ("rpc2", "generate_cases.sh", "conformance_cases.h"),
    ("rpc2", "generate_client_cases.sh", "client_cases.h"),
]


def generate(job):
    component, script, header = job
    source = root / "src" / component / "tests" / "quint"
    work = output / header.removesuffix(".h")
    subprocess.run(["bash", str(source / script), quint, sys.executable,
                    str(source), str(work), str(output / header)], check=True)


with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    list(pool.map(generate, jobs))

source = root / "src/core/tests/quint"
subprocess.run([sys.executable, str(source / "generate_sdk_cases.py"), quint, str(source), str(output)], check=True)
