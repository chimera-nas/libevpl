# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# The tcp provider is part of libfabric core, so these run wherever the
# backend is compiled in, over loopback like the socket tests.

unit_test_bin_all_mechs(libfabric hello_world_stream hello_world_stream -r STREAM_LIBFABRIC_MSG)
unit_test_bin_all_mechs(libfabric hello_world_connected_msg hello_world_connected_msg -r DATAGRAM_LIBFABRIC_MSG)

unit_test_bin_all_mechs(libfabric ping_pong_stream ping_pong_stream -r STREAM_LIBFABRIC_MSG)
unit_test_bin_all_mechs(libfabric ping_pong_connected_msg ping_pong_connected_msg -r DATAGRAM_LIBFABRIC_MSG)

unit_test_bin_all_mechs(libfabric bulk_stream bulk_stream -r STREAM_LIBFABRIC_MSG)
unit_test_bin_all_mechs(libfabric bulk_connected_msg bulk_connected_msg -r DATAGRAM_LIBFABRIC_MSG)

unit_test_bin_all_mechs(libfabric rand_full_duplex_stream rand_full_duplex_stream -r STREAM_LIBFABRIC_MSG)

unit_test_bin_all_mechs(libfabric rdma_ops rdma_ops -r DATAGRAM_LIBFABRIC_MSG)

# DATAGRAM_LIBFABRIC_RDM is a *reliable* datagram transport: sends to a
# departed peer are retried by the provider rather than dropped, so
# rand_full_duplex_msg (whose sides exit unilaterally, UDP-style) is not
# registered here -- only tests that terminate by mutual exchange.
unit_test_bin_all_mechs(libfabric hello_world_msg hello_world_msg -r DATAGRAM_LIBFABRIC_RDM)
unit_test_bin_all_mechs(libfabric ping_pong_msg ping_pong_msg -r DATAGRAM_LIBFABRIC_RDM)
unit_test_bin_all_mechs(libfabric bulk_msg bulk_msg -r DATAGRAM_LIBFABRIC_RDM)

# External-domain tests open libfabric objects and link it directly.
unit_test_all_mechs(libfabric external_domain external_domain.c)
target_include_directories(libfabric_external_domain PRIVATE ${LIBEVPL_SOURCE_DIR}/src/tests)
target_link_libraries(libfabric_external_domain fabric)

# Real-provider sharing, completion routing, close/reopen, and refill retry.
unit_test_all_mechs(libfabric shared_receive shared_receive.c)
target_include_directories(libfabric_shared_receive PRIVATE ${LIBEVPL_SOURCE_DIR}/src/tests)
target_link_libraries(libfabric_shared_receive fabric)
foreach(mode disabled unsupported eagain)
    foreach(mech ${EVPL_MECHANISMS})
        add_test(NAME libevpl/libfabric/shared_receive_${mode}_${mech}
                 COMMAND $<TARGET_FILE:libfabric_shared_receive>)
        set_tests_properties(libevpl/libfabric/shared_receive_${mode}_${mech}
            PROPERTIES RESOURCE_LOCK evpl_net
            ENVIRONMENT "EVPL_TEST_CORE_MECH=${mech}")
        set_property(TEST libevpl/libfabric/shared_receive_${mode}_${mech}
                     APPEND PROPERTY ENVIRONMENT EVPL_TEST_SRQ_MODE=${mode})
    endforeach()
endforeach()
