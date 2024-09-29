# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

if (DEFINED ENV{EVPL_RDMACM_IP}) 
    unit_test_bin(evpl hello_world_datagram_rdmacm_cm hello_world_connected_datagram -r DATAGRAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(evpl hello_world_stream_rdmacm_cm hello_world_stream -r STREAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})

    unit_test_bin(evpl ping_pong_datagram_rdmacm_rc ping_pong_connected_datagram -r DATAGRAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(evpl ping_pong_stream_rdmacm_rc ping_pong_stream -r STREAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})

    unit_test_bin(evpl bulk_datagram_rdmacm_rc bulk_connected_datagram -r DATAGRAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})
else()
    message(STATUS "EVPL_RDMACM_IP is not set to a valid RDMACM IP address, so RDMACM tests will be disabled")
endif()
