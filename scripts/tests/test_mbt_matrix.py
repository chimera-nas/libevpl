# SPDX-FileCopyrightText: 2026 Ben Jarvis
# SPDX-License-Identifier: LGPL-2.1-only
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ci_mbt_matrix import check_execution, check_tests, check_rdma_tests, check_storage_tests
from mbt_configurations import configurations


class MatrixTests(unittest.TestCase):
    def test_every_configuration_replay_is_required(self):
        for mech in ('epoll', 'select'):
            for i in range(len(configurations()[0])):
                name = f'libevpl/core/core_conformance_config_pair{i:02d}_{mech}'
                tests = [t for t in self.data['tests'] if t['name'] != name]
                with self.assertRaisesRegex(ValueError, 'Missing MBT replay'):
                    check_tests({'tests': tests}, ['libfabric', 'spdk'])

    def test_tls_matrix_requires_both_modes_and_spdk(self):
        names = []
        for mech in ('epoll', 'select'):
            names.append(f'core/core_conformance_alpn_{mech}')
            names.append(f'core/listener_conformance_TLS_{mech}')
            names.extend(f'core/core_conformance_tls_{mode}_{mech}'
                         for mode in ('software', 'auto'))
            names.append(f'rpc2/conformance_STREAM_SOCKET_TLS_{mech}')
        names.append('core/core_conformance_tls_software_spdk')
        names.extend(f'rpc2/conformance_STREAM_SOCKET_TLS_spdk_{mode}'
                     for mode in ('polling', 'interrupt'))
        base = self.data['tests']
        tests = base + [{'name': 'libevpl/' + n} for n in names]
        check_tests({'tests': tests}, ['tls', 'spdk'])
        for name in names:
            with self.assertRaisesRegex(ValueError, 'Missing MBT replay'):
                check_tests({'tests': [t for t in tests if t['name'] != 'libevpl/' + name]},
                            ['tls', 'spdk'])

    def test_tls_requires_openssl_and_transport_execution(self):
        for transport in ('tls.c', 'stream_tls.c'):
            files = [{'filename': '/repo/src/core/tls/' + name,
                      'summary': {'lines': {'covered': 1}}}
                     for name in ('openssl.c', transport)]
            check_execution({'data': [{'files': files}]}, '/repo', ['tls'])
            for missing in range(2):
                with self.assertRaisesRegex(ValueError, 'no executed lines'):
                    check_execution({'data': [{'files': files[:missing] + files[missing + 1:]}]},
                                    '/repo', ['tls'])

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

    def test_storage_requires_every_backend_and_mechanism(self):
        tests = [{'name': f'libevpl/core/core_conformance_{b}_{m}'}
                 for b in ('libaio', 'io_uring', 'io_uring_tcp', 'vfio', 'vfio_prp', 'vfio_interrupt') for m in ('epoll', 'select')]
        tests.extend({'name': f'libevpl/core/listener_conformance_io_uring_{m}'} for m in ('epoll', 'select'))
        check_storage_tests({'tests': tests})
        for i in range(len(tests)):
            with self.assertRaisesRegex(ValueError, 'Missing storage'):
                check_storage_tests({'tests': tests[:i] + tests[i + 1:]})

    def test_storage_execution_cannot_be_satisfied_by_another_backend(self):
        for backend, source in (('libaio', 'libaio_block.c'),
                                ('io_uring', 'io_uring_block.c'), ('vfio', 'vfio.c')):
            data = {'data': [{'files': [{'filename': f'/repo/src/core/{backend}/{source}',
                                        'summary': {'lines': {'covered': 10}}}]}]}
            check_execution(data, '/repo', [backend])
            for other in {'libaio', 'io_uring', 'vfio'} - {backend}:
                with self.assertRaisesRegex(ValueError, 'no executed lines'):
                    check_execution(data, '/repo', [other])

    def setUp(self):
        names = ['core/listener_conformance_STREAM_INPROC_epoll', 'core/listener_conformance_DATAGRAM_TCP_RDMA_epoll',
                 'core/listener_conformance_epoll', 'core/fd_conformance_epoll', 'core/lifecycle_conformance_epoll',
                 'core/core_conformance_capacity_epoll', 'core/core_conformance_tcp_rdma_epoll',
                 'core/lifecycle_conformance_spdk', 'core/block_lifecycle_conformance_spdk',
                 'core/core_conformance_epoll', 'http/conformance',
                 'http/conformance_client', 'rpc2/conformance_STREAM_SOCKET_TCP_epoll',
                 'rpc2/conformance_client_STREAM_SOCKET_TCP_epoll',
                 'core/core_conformance_libfabric_epoll', 'core/core_conformance_spdk',
                 'core/core_conformance_libfabric_spdk',
                 'core/core_conformance_libfabric_rdm_epoll',
                 'core/core_conformance_libfabric_rdm_spdk']
        names.append('core/block_retry_conformance_spdk')
        for mech in ('epoll', 'select'):
            names.extend((f'core/ownership_conformance_{mech}', f'core/ownership_conformance_shared_{mech}'))
            names.extend(f'core/{family}_conformance_{mech}' for family in ('rdma', 'unix_path', 'registration'))
            names.extend(f'core/core_conformance_config_pair{i:02d}_{mech}'
                         for i in range(len(configurations()[0])))
            for proto in ('STREAM_LIBFABRIC_MSG', 'DATAGRAM_LIBFABRIC_MSG'):
                for mode in ('fd', 'pollfd', 'none'):
                    names.append(f'rpc2/conformance_libfabric_external_{proto}_{mode}_{mech}')
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

    def test_rdm_replay_is_required_alongside_msg(self):
        for name in ('core/core_conformance_libfabric_rdm_epoll',
                     'core/core_conformance_libfabric_rdm_spdk'):
            tests = [t for t in self.data['tests'] if t['name'] != 'libevpl/' + name]
            with self.assertRaisesRegex(ValueError, 'libfabric_rdm'):
                check_tests({'tests': tests}, ['libfabric', 'spdk'])

    def test_ownership_retry_and_external_modes_cannot_disappear(self):
        targets = [t['name'] for t in self.data['tests']
                   if any(s in t['name'] for s in ('ownership_conformance', 'block_retry', 'libfabric_external',
                                                  'rdma_conformance', 'unix_path_conformance', 'registration_conformance'))]
        for name in targets:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Missing MBT replay'):
                check_tests({'tests': [t for t in self.data['tests'] if t['name'] != name]},
                            ['libfabric', 'spdk'])

    def test_native_only_still_supported_but_ci_requires_backends(self):
        self.data['tests'] = [t for t in self.data['tests'] if not any(b in t['name'] for b in ('libfabric', 'spdk'))]
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
