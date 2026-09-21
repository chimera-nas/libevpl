# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ci_mbt_matrix import check_execution, check_tests, check_rdma_tests


class MatrixTests(unittest.TestCase):
    def test_rdma_requires_all_transports_and_mechanisms(self):
        names = []
        for mech in ('epoll', 'select'):
            names.append(f'core/core_conformance_rdma_{mech}')
            names.extend(f'rpc2/conformance_{proto}_{mech}' for proto in
                         ('STREAM_RDMACM_RC', 'DATAGRAM_RDMACM_RC'))
        data = {'tests': [{'name': 'libevpl/' + name} for name in names]}
        check_rdma_tests(data)
        for index in range(len(names)):
            with self.assertRaisesRegex(ValueError, 'Missing RDMA'):
                check_rdma_tests({'tests': data['tests'][:index] + data['tests'][index + 1:]})

    def test_rdma_execution_is_required(self):
        with self.assertRaisesRegex(ValueError, 'rdmacm.c'):
            check_execution({'data': []}, '/repo', ['rdma'])
        data = {'data': [{'files': [{'filename': '/repo/src/core/rdmacm/rdmacm.c',
                                    'summary': {'lines': {'covered': 100}}}]}]}
        check_execution(data, '/repo', ['rdma'])

    def setUp(self):
        names = ['core/core_conformance_epoll', 'http/conformance',
                 'http/conformance_client', 'rpc2/conformance_STREAM_SOCKET_TCP_epoll',
                 'rpc2/conformance_client_STREAM_SOCKET_TCP_epoll',
                 'core/core_conformance_libfabric_epoll', 'core/core_conformance_spdk',
                 'core/core_conformance_libfabric_spdk']
        for proto in ('STREAM_LIBFABRIC_MSG', 'DATAGRAM_LIBFABRIC_MSG'):
            names.append(f'rpc2/conformance_{proto}_epoll')
        for mode in ('polling', 'interrupt'):
            for family in ('http', 'rpc2'):
                for suite in ('conformance', 'conformance_client'):
                    for proto in ('STREAM_SOCKET_TCP', 'STREAM_SPDK_TCP'):
                        names.append(f'{family}/{suite}_{proto}_spdk_{mode}')
            for proto in ('STREAM_LIBFABRIC_MSG', 'DATAGRAM_LIBFABRIC_MSG'):
                names.append(f'rpc2/conformance_{proto}_spdk_{mode}')
        self.data = {'tests': [{'name': 'libevpl/' + n} for n in names]}

    def test_complete_matrix_and_missing_combination(self):
        check_tests(self.data, ['libfabric', 'spdk'])
        self.data['tests'].pop()
        with self.assertRaisesRegex(ValueError, 'DATAGRAM_LIBFABRIC_MSG_spdk_interrupt'):
            check_tests(self.data, ['libfabric', 'spdk'])

    def test_native_only_still_supported_but_ci_requires_backends(self):
        self.data['tests'] = self.data['tests'][:5]
        check_tests(self.data, [])
        with self.assertRaisesRegex(ValueError, 'libfabric'):
            check_tests(self.data, ['libfabric', 'spdk'])

    def test_every_backend_path_must_execute(self):
        files = [{'filename': '/repo/src/core/' + p,
                  'summary': {'lines': {'covered': 1}}} for p in
                 ('libfabric/libfabric.c', 'spdk/spdk_core.c', 'spdk/spdk_block.c', 'spdk/tcp.c')]
        data = {'data': [{'files': files}]}
        check_execution(data, '/repo', ['libfabric', 'spdk'])
        files[-1]['summary']['lines']['covered'] = 0
        with self.assertRaisesRegex(ValueError, 'spdk/tcp.c'):
            check_execution(data, '/repo', ['libfabric', 'spdk'])

    def test_foreign_or_test_code_cannot_satisfy_execution_guard(self):
        files = [{'filename': p, 'summary': {'lines': {'covered': 1000}}} for p in
                 ('/other/src/core/libfabric/libfabric.c',
                  '/repo/src/core/libfabric/tests/libfabric.c')]
        with self.assertRaisesRegex(ValueError, 'libfabric.c'):
            check_execution({'data': [{'files': files}]}, '/repo', ['libfabric'])


if __name__ == '__main__':
    unittest.main()
