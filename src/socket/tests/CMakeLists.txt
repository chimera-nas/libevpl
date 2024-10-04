# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

unit_test_bin(evpl hello_world_msg_udp hello_world_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl hello_world_stream_tcp hello_world_stream -r STREAM_SOCKET_TCP)
unit_test_bin(evpl hello_world_connected_msg_tcp hello_world_connected_msg -r STREAM_SOCKET_TCP)

unit_test_bin(evpl ping_pong_msg_udp ping_pong_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl ping_pong_stream_tcp ping_pong_stream -r STREAM_SOCKET_TCP)
unit_test_bin(evpl ping_pong_msg_tcp ping_pong_connected_msg -r STREAM_SOCKET_TCP)

unit_test_bin(evpl bulk_msg_udp bulk_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl bulk_msg_tcp bulk_connected_msg -r STREAM_SOCKET_TCP)
unit_test_bin(evpl bulk_stream_tcp bulk_stream -r STREAM_SOCKET_TCP)

unit_test_bin(evpl rand_full_duplex_msg_udp rand_full_duplex_msg -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl rand_full_duplex_stream_tcp rand_full_duplex_stream -r STREAM_SOCKET_TCP)
