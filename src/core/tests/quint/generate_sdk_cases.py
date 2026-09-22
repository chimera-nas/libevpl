#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only
"""Generate small SDK state-machine replays; reject missing transitions."""
import json
from pathlib import Path
import subprocess
import sys

quint, source, work = sys.argv[1:]
work = Path(work)
work.mkdir(parents=True, exist_ok=True)
models = {
    'ownership': ('Reset Allocate Clone Move Slice ReleaseA ReleaseB ReleaseC Request Take TakeEmpty Destroy Inspect',
                  'a b c request r offset length refs'),
    'block_retry': ('Reset Open Read Write Close Remove RetryAgain Retry Inspect',
                    'opened online closing waiting kind value completions errors closes retries'),
    'listener': ('Reset Start Attach Detach Connect Stop Quiesce',
                 'listening attached pending accepts disconnects'),
    'block_lifecycle': ('Reset Open Close Resize Remove Read ReadRemoved Inspect',
                        'opened online blocks resizes removes'),
    'fd': ('Reset Attach Remove Interest Pause WriteInterest WritePause Put Force Retire Quiesce',
           'attached interest writeInterest pending forced retire bytes reads writes'),
    'lifecycle': ('Reset Thread ThreadAsync EmptyPool Pool Stop StopAsync Quiesce',
                  'live kind stopping created ready stopped completions pending'),
}
for name, (ops, fields) in models.items():
    ops, fields = ops.split(), fields.split()
    prefix = work / name
    # Listener traces create kernel rings and worker threads at each restart.
    # Keep four independent walks and all transition/handoff witnesses.
    steps = 128 if name in ('listener', 'block_retry') else 1024
    subprocess.run([quint, 'run', '--backend=typescript', str(Path(source) / (name + '.qnt')),
                    '--verbosity=0', '--seed=827', f'--max-steps={steps}', '--max-samples=4', '--n-traces=4',
                    '--invariant=inv', '--out-itf=' + str(prefix) + '-{seq}.itf.json'], check=True)
    rows, seen = [], set()
    self_removals = 0
    discarded = 0
    retained = 0
    close_waiting = remove_waiting = 0
    read_written = 0
    for i in range(4):
        states = json.loads(Path(str(prefix) + f'-{i}.itf.json').read_text())['states']
        previous = None
        for state in states:
            op, s = state['op'], state['s']
            if name == 'fd' and op == 'Quiesce' and previous and previous['attached'] and not s['attached']:
                self_removals += 1
            if name == 'listener' and op == 'Quiesce' and previous and previous['pending'] and not previous['attached']:
                discarded += 1
            if name == 'ownership' and op == 'Destroy' and s['a']:
                retained += 1
            if name == 'block_retry' and op == 'Close' and s['waiting']:
                close_waiting += 1
            if name == 'block_retry' and op == 'Remove' and s['waiting']:
                remove_waiting += 1
            if name == 'block_retry' and op == 'Retry' and s['online'] and s['kind']['#bigint'] == '0' and s['value']['#bigint'] == '1':
                read_written += 1
            previous = s
            if op not in ops or set(s) != set(fields):
                raise ValueError(f'unknown schema: {op} {s}')
            seen.add(op)
            values = [int(s[k]['#bigint']) if isinstance(s[k], dict) else int(s[k]) for k in fields]
            rows.append('  {' + f'{name}_{op}, ' + ', '.join(map(str, values)) + '},')
    if seen != set(ops):
        raise ValueError(f'{name}: missing operations {set(ops) - seen}')
    if name == 'listener' and not discarded:
        raise ValueError('listener corpus never discards a pending accept')
    if name == 'fd' and not self_removals:
        raise ValueError('fd corpus never retires an event inside its callback')
    if name == 'ownership' and not retained:
        raise ValueError('ownership corpus never retains a transferred buffer after holder destruction')
    if name == 'block_retry' and (not close_waiting or not remove_waiting or not read_written):
        raise ValueError('retry corpus must close/remove while waiting and read previously written data')
    header = ('/* Generated from Quint; do not edit. */\n#pragma once\n'
              + 'enum { ' + ', '.join(name + '_' + op for op in ops) + ' };\n'
              + f'struct {name}_step {{ int op, ' + ', '.join(fields) + '; };\n'
              + f'static const struct {name}_step {name}_steps[] = {{\n'
              + '\n'.join(rows) + '\n};\n')
    (work / (name + '_cases.h')).write_text(header)
