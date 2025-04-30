# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

unit_test(io_uring basic basic.c)


unit_test_bin(io_uring hello_world_stream_tcp hello_world_stream -r STREAM_IO_URING_TCP)
unit_test_bin(io_uring hello_world_connected_msg_tcp hello_world_connected_msg -r STREAM_IO_URING_TCP)

unit_test_bin(io_uring ping_pong_stream_tcp ping_pong_stream -r STREAM_IO_URING_TCP)
unit_test_bin(io_uring ping_pong_msg_tcp ping_pong_connected_msg -r STREAM_IO_URING_TCP)

unit_test_bin(io_uring bulk_msg_tcp bulk_connected_msg -r STREAM_IO_URING_TCP)
unit_test_bin(io_uring bulk_stream_tcp bulk_stream -r STREAM_IO_URING_TCP)

unit_test_bin(io_uring rand_full_duplex_stream_tcp rand_full_duplex_stream -r STREAM_IO_URING_TCP)
