#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
"""Generate HTTP/2 integration traces, retaining mandatory lifecycle witnesses."""
import json
from pathlib import Path
import subprocess
import sys

OPS = 'Reset Connect Open Upload Interim Respond Partial Finish Cancel Release Close Goaway'.split()
FIELDS = 'phase shape streaming trailers interim'.split()


def emit(traces, output):
    rows, seen, roles, outcomes = [], set(), set(), set()
    for trace in traces:
        states = json.loads(trace.read_text())['states']
        for state in states:
            op, s = state['op'], state['s']
            if op not in OPS:
                raise ValueError('Unknown HTTP/2 operation: ' + op)
            seen.add(op)
            roles.add(s['client'])
            if op in ('Partial', 'Finish', 'Cancel'):
                outcomes.add((s['client'], op))
            streams = s['streams']
            def integer(value):
                return int(value['#bigint']) if isinstance(value, dict) else int(value)
            fields = [integer(state['slot'])] + [integer(s[key]) for key in
                                                ('connected', 'client', 'blocked', 'fragmented')]
            values = []
            for stream in streams:
                if set(stream) != set(FIELDS):
                    raise ValueError('Unexpected HTTP/2 stream schema')
                values.append('{' + ', '.join(str(integer(stream[key])) for key in FIELDS) + '}')
            rows.append('  {h2_' + op + ', ' + ', '.join(map(str, fields)) + ', {' + ', '.join(values) + '}},')
    required = {(client, op) for client in (False, True) for op in ('Partial', 'Finish', 'Cancel')}
    if seen != set(OPS) or roles != {False, True} or not required <= outcomes:
        raise ValueError(f'HTTP/2 corpus lost lifecycle witnesses: {set(OPS) - seen}, {required - outcomes}')
    output.write_text('/* Generated from Quint; do not edit. */\n#pragma once\n'
                      + 'enum { ' + ', '.join('h2_' + op for op in OPS) + ' };\n'
                      + 'struct h2_stream_state { int ' + ', '.join(FIELDS) + '; };\n'
                      + 'struct h2_step { int op, slot, connected, client, blocked, fragmented; struct h2_stream_state streams[3]; };\n'
                      + 'static const struct h2_step h2_steps[] = {\n' + '\n'.join(rows) + '\n};\n')
    print(f'HTTP/2: {len(traces)} traces, {len(rows)} steps, all required lifecycle witnesses present')


def main():
    quint, source, work, output = sys.argv[1:]
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    for old in work.glob('http2-*.itf.json'):
        old.unlink()
    model = str(Path(source) / 'http2.qnt')
    subprocess.run([quint, 'test', '--backend=typescript', model, '--verbosity=0', '--seed=827',
                    '--out-itf=' + str(work / 'http2-test-{test}-{seq}.itf.json')], check=True)
    subprocess.run([quint, 'run', '--backend=typescript', model, '--verbosity=0', '--seed=827',
                    '--max-steps=96', '--max-samples=8', '--n-traces=8', '--invariant=inv',
                    '--out-itf=' + str(work / 'http2-random-{seq}.itf.json')], check=True)
    emit(sorted(work.glob('http2-*.itf.json')), Path(output))


if __name__ == '__main__':
    main()
