# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

unit_test_bin(evpl hello_world_datagram_udp hello_world_datagram -r DATAGRAM_SOCKET_UDP)
unit_test_bin(evpl hello_world_stream_tcp hello_world_stream -r STREAM_SOCKET_TCP)
unit_test(evpl pingpong_tcp pingpong_tcp.c)
