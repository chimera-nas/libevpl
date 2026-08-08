# SPDX-FileCopyrightText: 2024 - 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# Each of these runs once per event-loop mechanism compiled into the build
# (epoll/kqueue/select), giving every mechanism the same socket I/O coverage.

unit_test_bin_all_mechs(socket hello_world_msg_udp hello_world_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin_all_mechs(socket hello_world_stream_tcp hello_world_stream -r STREAM_SOCKET_TCP)
unit_test_bin_all_mechs(socket hello_world_connected_msg_tcp hello_world_connected_msg -r STREAM_SOCKET_TCP)

unit_test_bin_all_mechs(socket ping_pong_msg_udp ping_pong_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin_all_mechs(socket ping_pong_stream_tcp ping_pong_stream -r STREAM_SOCKET_TCP)
unit_test_bin_all_mechs(socket ping_pong_msg_tcp ping_pong_connected_msg -r STREAM_SOCKET_TCP)

unit_test_bin_all_mechs(socket bulk_msg_udp bulk_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin_all_mechs(socket bulk_msg_tcp bulk_connected_msg -r STREAM_SOCKET_TCP)
unit_test_bin_all_mechs(socket bulk_stream_tcp bulk_stream -r STREAM_SOCKET_TCP)

unit_test_bin_all_mechs(socket rand_full_duplex_msg_udp rand_full_duplex_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin_all_mechs(socket rand_full_duplex_stream_tcp rand_full_duplex_stream -r STREAM_SOCKET_TCP)

# TCP_RDMA tests
unit_test_bin_all_mechs(socket rdma_ops_tcp_rdma rdma_ops -r DATAGRAM_TCP_RDMA)

# AF_UNIX stream tests.  The same stream bodies the TCP battery runs; the
# datagram tests are omitted because STREAM_SOCKET_UNIX has no .bind op, and
# rdma_ops needs one-sided RDMA.
#
# Each test derives its own socket path from its binary name and pid (see
# test_address() in src/tests/test_common.h), so they stay collision-free
# under `ctest -j` without a per-test -a argument.
unit_test_bin_all_mechs(unix hello_world_stream_unix hello_world_stream -r STREAM_SOCKET_UNIX)
unit_test_bin_all_mechs(unix hello_world_connected_msg_unix hello_world_connected_msg -r STREAM_SOCKET_UNIX)

unit_test_bin_all_mechs(unix ping_pong_stream_unix ping_pong_stream -r STREAM_SOCKET_UNIX)
unit_test_bin_all_mechs(unix ping_pong_msg_unix ping_pong_connected_msg -r STREAM_SOCKET_UNIX)

unit_test_bin_all_mechs(unix bulk_msg_unix bulk_connected_msg -r STREAM_SOCKET_UNIX)
unit_test_bin_all_mechs(unix bulk_stream_unix bulk_stream -r STREAM_SOCKET_UNIX)

unit_test_bin_all_mechs(unix rand_full_duplex_stream_unix rand_full_duplex_stream -r STREAM_SOCKET_UNIX)

# Abstract namespace: no filesystem object, so nothing to unlink and nothing a
# crash can leave stale.
unit_test_bin_all_mechs(unix hello_world_stream_unix_abstract hello_world_stream -r STREAM_SOCKET_UNIX -a @evpl-test-hws)
unit_test_bin_all_mechs(unix ping_pong_stream_unix_abstract ping_pong_stream -r STREAM_SOCKET_UNIX -a @evpl-test-pps)
