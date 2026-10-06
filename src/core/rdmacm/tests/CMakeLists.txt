# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

if(EVPL_RDMA_TEST_IP)
    # The configured RDMA device belongs to this network namespace.
    set(LIBEVPL_NETNS_TESTING FALSE)
    unit_test_bin(rdmacm hello_world_msg_rdmacm_ud hello_world_msg -r DATAGRAM_RDMACM_UD -a ${EVPL_RDMA_TEST_IP})
    unit_test_bin(rdmacm hello_world_msg_rdmacm_rc hello_world_connected_msg -r DATAGRAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})
    unit_test_bin(rdmacm hello_world_stream_rdmacm_rc hello_world_stream -r STREAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})

    unit_test_bin(rdmacm ping_pong_msg_rdmacm_ud ping_pong_msg -r DATAGRAM_RDMACM_UD -a ${EVPL_RDMA_TEST_IP})
    unit_test_bin(rdmacm ping_pong_msg_rdmacm_rc ping_pong_connected_msg -r DATAGRAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})
    unit_test_bin(rdmacm ping_pong_stream_rdmacm_rc ping_pong_stream -r STREAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})


    unit_test_bin(rdmacm bulk_msg_rdmacm_rc bulk_connected_msg -r DATAGRAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})
    unit_test_bin(rdmacm bulk_msg_rdmacm_ud bulk_msg -r DATAGRAM_RDMACM_UD -a ${EVPL_RDMA_TEST_IP})
    unit_test_bin(rdmacm bulk_stream_rdmacm_rc bulk_stream -r STREAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})

    unit_test_bin(rdmacm rand_full_duplex_stream_rdmacm_rc rand_full_duplex_stream -r STREAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})
    unit_test_bin(rdmacm rand_full_duplex_msg_rdmacm_ud rand_full_duplex_msg -r DATAGRAM_RDMACM_UD -a ${EVPL_RDMA_TEST_IP})

    unit_test_bin(rdmacm rdma_ops_rc rdma_ops -r DATAGRAM_RDMACM_RC -a ${EVPL_RDMA_TEST_IP})
    unit_test(rdmacm receive_error receive_error.c)
    unit_test(rdmacm dgram_resize dgram_resize.c)
    get_property(rdma_tests DIRECTORY PROPERTY TESTS)
    set_property(TEST ${rdma_tests} APPEND PROPERTY ENVIRONMENT
                 EVPL_TEST_RDMA_IP=${EVPL_RDMA_TEST_IP})
    set_tests_properties(${rdma_tests} PROPERTIES LABELS rdma TIMEOUT 120)
    set_tests_properties(libevpl/rdmacm/receive_error libevpl/rdmacm/dgram_resize PROPERTIES TIMEOUT 20)
else()
    message(STATUS "EVPL_RDMACM_IP is not set to a valid RDMACM IP address, so RDMACM tests will be disabled")
endif()
