#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
"""Fail closed if a required MBT family/backend or its execution disappears."""
import argparse
import json
import os
import re

from ci_coverage_report import relative


def check_rdma_tests(data):
    names = {test['name'] for test in data['tests']}
    for mech in ('epoll', 'select'):
        required = [f'core/core_conformance_rdma_{mech}']
        required.extend(f'rpc2/conformance_{proto}_{mech}' for proto in
                        ('STREAM_RDMACM_RC', 'DATAGRAM_RDMACM_RC'))
        for name in required:
            if 'libevpl/' + name not in names:
                raise ValueError('Missing RDMA MBT replay: ' + name)


def check_storage_tests(data):
    names = {test['name'] for test in data['tests']}
    for backend in ('libaio', 'io_uring', 'vfio'):
        for mech in ('epoll', 'select'):
            name = f'libevpl/core/core_conformance_{backend}_{mech}'
            if name not in names:
                raise ValueError('Missing storage MBT replay: ' + name)


def check_tests(data, backends):
    names = [test['name'] for test in data['tests']]
    required = [r'libevpl/core/core_conformance_', r'libevpl/http/conformance$',
                r'libevpl/http/conformance_client', r'libevpl/rpc2/conformance_STREAM_',
                r'libevpl/rpc2/conformance_client_']
    if 'tls' in backends:
        for mech in ('epoll', 'select'):
            for mode in ('software', 'auto'):
                required.append(f'libevpl/core/core_conformance_tls_{mode}_{mech}$')
            required.append(f'libevpl/rpc2/conformance_STREAM_SOCKET_TLS_{mech}$')
        if 'spdk' in backends:
            required.append(r'libevpl/core/core_conformance_tls_software_spdk$')
            for mode in ('polling', 'interrupt'):
                required.append(f'libevpl/rpc2/conformance_STREAM_SOCKET_TLS_spdk_{mode}$')
    if 'libfabric' in backends:
        required.append(r'libevpl/core/core_conformance_libfabric_(?:epoll|select)$')
        required.append(r'libevpl/core/core_conformance_libfabric_rdm_(?:epoll|select)$')
        for proto in ('STREAM_LIBFABRIC_MSG', 'DATAGRAM_LIBFABRIC_MSG'):
            required.append(f'libevpl/rpc2/conformance_{proto}_(?!spdk)')
    if 'spdk' in backends:
        required.append(r'libevpl/core/core_conformance_spdk$')
        if 'libfabric' in backends:
            required.append(r'libevpl/core/core_conformance_libfabric_spdk$')
            required.append(r'libevpl/core/core_conformance_libfabric_rdm_spdk$')
        for mode in ('polling', 'interrupt'):
            for family in ('http', 'rpc2'):
                for suite in ('conformance', 'conformance_client'):
                    for proto in ('STREAM_SOCKET_TCP', 'STREAM_SPDK_TCP'):
                        required.append(f'libevpl/{family}/{suite}_{proto}_spdk_{mode}$')
            if 'libfabric' in backends:
                for proto in ('STREAM_LIBFABRIC_MSG', 'DATAGRAM_LIBFABRIC_MSG'):
                    required.append(f'libevpl/rpc2/conformance_{proto}_spdk_{mode}$')
    for pattern in required:
        if not any(re.match(pattern, name) for name in names):
            raise ValueError('Missing MBT replay: ' + pattern)


def check_execution(data, root, backends):
    required = []
    if 'tls' in backends:
        required.append('src/core/tls/openssl.c')
    if 'rdma' in backends:
        required.append('src/core/rdmacm/rdmacm.c')
    if 'libfabric' in backends:
        required.append('src/core/libfabric/libfabric.c')
    if 'spdk' in backends:
        required.extend('src/core/spdk/' + name for name in
                        ('spdk_core.c', 'spdk_block.c', 'tcp.c'))
    for backend, source in (('libaio', 'libaio_block.c'),
                            ('io_uring', 'io_uring_block.c'), ('vfio', 'vfio.c')):
        if backend in backends:
            required.append(f'src/core/{backend}/{source}')
    hits = {}
    for unit in data.get('data', []):
        for entry in unit.get('files', []):
            path = relative(os.path.realpath(entry['filename']), (os.path.realpath(root),))
            hits[path] = hits.get(path, 0) + entry.get('summary', {}).get('lines', {}).get('covered', 0)
    if 'tls' in backends and not any(hits.get('src/core/tls/' + source, 0) > 0
                                     for source in ('tls.c', 'stream_tls.c')):
        raise ValueError('Required TLS transport has no executed lines')
    for path in required:
        if hits.get(path, 0) <= 0:
            raise ValueError('Required MBT backend has no executed lines: ' + path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('tests', 'rdma-tests', 'storage-tests', 'execution'))
    parser.add_argument('input')
    parser.add_argument('--root', default='.')
    parser.add_argument('--require', nargs='*', choices=('libfabric', 'spdk', 'rdma', 'libaio', 'io_uring', 'vfio', 'tls'), default=[])
    args = parser.parse_args()
    with open(args.input) as stream:
        data = json.load(stream)
    try:
        if args.mode == 'tests':
            check_tests(data, args.require)
        elif args.mode == 'storage-tests':
            check_storage_tests(data)
        elif args.mode == 'rdma-tests':
            check_rdma_tests(data)
        else:
            check_execution(data, args.root, args.require)
    except ValueError as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
