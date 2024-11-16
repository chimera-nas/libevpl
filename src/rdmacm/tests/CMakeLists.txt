# SPDX-FileCopyrightText: 2024 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

if (DEFINED ENV{EVPL_RDMACM_IP}) 
    unit_test_bin(rdmacm hello_world_msg_rdmacm_ud hello_world_msg -r DATAGRAM_RDMACM_UD -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(rdmacm hello_world_msg_rdmacm_rc hello_world_connected_msg -r DATAGRAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(rdmacm hello_world_stream_rdmacm_rc hello_world_stream -r STREAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})

    unit_test_bin(rdmacm ping_pong_msg_rdmacm_ud ping_pong_msg -r DATAGRAM_RDMACM_UD -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(rdmacm ping_pong_msg_rdmacm_rc ping_pong_connected_msg -r DATAGRAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(rdmacm ping_pong_stream_rdmacm_rc ping_pong_stream -r STREAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})


    unit_test_bin(rdmacm bulk_msg_rdmacm_rc bulk_connected_msg -r DATAGRAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(rdmacm bulk_msg_rdmacm_ud bulk_msg -r DATAGRAM_RDMACM_UD -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(rdmacm bulk_stream_rdmacm_rc bulk_stream -r STREAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})

    unit_test_bin(rdmacm rand_full_duplex_stream_rdmacm_rc rand_full_duplex_stream -r STREAM_RDMACM_RC -a $ENV{EVPL_RDMACM_IP})
    unit_test_bin(rdmacm rand_full_duplex_msg_rdmacm_ud rand_full_duplex_msg -r DATAGRAM_RDMACM_UD -a $ENV{EVPL_RDMACM_IP})

else()
    message(STATUS "EVPL_RDMACM_IP is not set to a valid RDMACM IP address, so RDMACM tests will be disabled")
endif()
