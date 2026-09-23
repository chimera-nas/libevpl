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
    'registration': ('Reset Register Unregister Reuse Validate Churn', 'a b slot offset length valid issued'),
    'rdma': ('Reset Connect Queue Drain Close PeerClose PartialClose Inspect',
             'connected pending count kind access take value memory completions errors prefix'),
    'unix_path': ('Reset Stale Live File Listen Stop Crash Remove Inspect', 'path success'),
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
    steps = 128 if name in ('listener', 'block_retry', 'rdma', 'unix_path', 'registration') else 1024
    subprocess.run([quint, 'run', '--backend=typescript', str(Path(source) / (name + '.qnt')),
                    '--verbosity=0', '--seed=827', f'--max-steps={steps}', '--max-samples=4', '--n-traces=4',
                    '--invariant=inv', '--out-itf=' + str(prefix) + '-{seq}.itf.json'], check=True)
    traces = [Path(str(prefix) + f'-{i}.itf.json') for i in range(4)]
    if name in ('rdma', 'unix_path', 'registration'):
        # Replay model scenarios as well as random walks: boundary witnesses
        # must survive changes to the random action distribution.
        for old in work.glob(name + '-test-*.itf.json'):
            old.unlink()
        subprocess.run([quint, 'test', '--backend=typescript', str(Path(source) / (name + '.qnt')),
                        '--seed=827', '--verbosity=0',
                        '--out-itf=' + str(prefix) + '-test-{test}-{seq}.itf.json'], check=True)
        traces.extend(sorted(work.glob(name + '-test-*.itf.json')))
    rows, seen = [], set()
    self_removals = 0
    discarded = 0
    retained = 0
    close_waiting = remove_waiting = 0
    read_written = 0
    rdma_outcomes = set()
    partial_outcomes = set()
    partial_boundaries = set()
    unix_outcomes = set()
    for trace in traces:
        states = json.loads(trace.read_text())['states']
        previous = None
        for state in states:
            op, s = state['op'], state['s']
            if name == 'rdma' and op == 'PartialClose':
                count, prefix_length = (int(s[k]['#bigint']) for k in ('count', 'prefix'))
                if not 0 < prefix_length < count:
                    raise ValueError('partial cancellation must have completed and pending operations')
                partial_outcomes.add((int(s['kind']['#bigint']), s['take'], int(s['access']['#bigint']) != 0))
                partial_boundaries.add((count, prefix_length))
            if name == 'rdma' and previous and previous['pending']['#bigint'] != '0' and op in ('Drain', 'Close', 'PeerClose'):
                rdma_outcomes.add((op, int(previous['kind']['#bigint']), int(previous['access']['#bigint'])))
            if name == 'unix_path' and previous and op == 'Listen':
                unix_outcomes.add(int(previous['path']['#bigint']))
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
    if name == 'rdma':
        required = {('Drain', kind, access) for kind in (0, 1) for access in range(5)}
        required.update((op, kind, 0) for op in ('Close', 'PeerClose') for kind in (0, 1))
        if not required <= rdma_outcomes:
            raise ValueError(f'RDMA corpus missing outcomes: {required - rdma_outcomes}')
        partial_required = {(kind, take, error) for kind, take in ((0, False), (1, False), (1, True))
                            for error in (False, True)}
        if not partial_required <= partial_outcomes or not {(15, 14), (17, 1), (33, 16), (33, 32)} <= partial_boundaries:
            raise ValueError('RDMA corpus missing partial cancellation outcomes or boundary witnesses')
    if name == 'unix_path' and unix_outcomes != {0, 1, 2, 3}:
        raise ValueError(f'UNIX corpus missing listen outcomes: {unix_outcomes}')
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
