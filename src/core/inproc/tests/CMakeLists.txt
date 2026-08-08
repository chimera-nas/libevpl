# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# In-process transport tests.
#
# Registered with unit_test_bin_local: these touch no kernel transport at all,
# so they need neither a network namespace nor the shared port lock.  The
# registry behind an inproc name is private to the process, which makes these
# the only transport tests with no shared namespace of any kind -- two of them
# could use identical names and still not collide.
#
# The shared test bodies already run their client and server on separate evpl
# threads, which is exactly what this transport connects, so they need no
# change beyond the address normalization in test_address().

# STREAM_INPROC: the byte-stream battery, including segment-callback framing.
unit_test_bin_local(inproc hello_world_stream_inproc hello_world_stream -r STREAM_INPROC)
unit_test_bin_local(inproc hello_world_connected_msg_inproc hello_world_connected_msg -r STREAM_INPROC)

unit_test_bin_local(inproc ping_pong_stream_inproc ping_pong_stream -r STREAM_INPROC)
unit_test_bin_local(inproc ping_pong_msg_inproc ping_pong_connected_msg -r STREAM_INPROC)

unit_test_bin_local(inproc bulk_stream_inproc bulk_stream -r STREAM_INPROC)
unit_test_bin_local(inproc bulk_msg_inproc bulk_connected_msg -r STREAM_INPROC)

unit_test_bin_local(inproc rand_full_duplex_stream_inproc rand_full_duplex_stream -r STREAM_INPROC)

# DATAGRAM_INPROC: message framing, and one-sided RDMA with no hardware and no
# request/reply emulation behind it.
unit_test_bin_local(inproc hello_world_msg_inproc hello_world_connected_msg -r DATAGRAM_INPROC)
unit_test_bin_local(inproc ping_pong_dgram_inproc ping_pong_connected_msg -r DATAGRAM_INPROC)
unit_test_bin_local(inproc bulk_dgram_inproc bulk_connected_msg -r DATAGRAM_INPROC)
unit_test_bin_local(inproc rdma_ops_inproc rdma_ops -r DATAGRAM_INPROC)
