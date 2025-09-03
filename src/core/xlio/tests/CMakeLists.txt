# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

if (DEFINED ENV{EVPL_RDMACM_IP})
    SET(ADDR $ENV{EVPL_RDMACM_IP})
else()
    set(ADDR 127.0.0.1)
endif()

unit_test_bin(xlio hello_world_stream_xlio_tcp hello_world_stream -r STREAM_XLIO_TCP -a ${ADDR})
