# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

unit_test_bin(evpl hello_world_datagram_udp hello_world_datagram -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl hello_world_stream_tcp hello_world_stream -r STREAM_SOCKET_TCP)
unit_test_bin(evpl ping_pong_datagram_udp ping_pong_datagram -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl ping_pong_stream_tcp ping_pong_stream -r STREAM_SOCKET_TCP)
unit_test_bin(evpl bulk_datagram_udp bulk_datagram -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl bulk_stream_tcp bulk_stream -r STREAM_SOCKET_TCP)
unit_test_bin(evpl rand_full_duplex_datagram_udp rand_full_duplex_datagram -r DATAGRAM_SOCKET_UDP)
