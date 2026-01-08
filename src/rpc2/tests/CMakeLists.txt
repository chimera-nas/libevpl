# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# Include path for test_common.h
include_directories(${LIBEVPL_SOURCE_DIR}/src/tests)

# Custom macro for RPC2 tests that need both client and server code
# This builds an executable that can be run with different protocols
macro(unit_test_rpc2 test_name xdr_file)
    set(sources ${ARGN})

    set(XDR_C ${CMAKE_CURRENT_BINARY_DIR}/${test_name}_xdr.c)
    set(XDR_H ${CMAKE_CURRENT_BINARY_DIR}/${test_name}_xdr.h)
    set(XDR_X ${CMAKE_CURRENT_SOURCE_DIR}/${xdr_file})

    # Generate both server (-r) and client (-c) code
    add_custom_command(
        OUTPUT ${XDR_C} ${XDR_H}
        COMMAND ${XDRZCC} -r ${XDR_X} ${XDR_C} ${XDR_H}
        DEPENDS ${xdr_file} ${XDRZCC}
        COMMENT "Compiling ${xdr_file} with server and client support"
    )

    set_source_files_properties(
        ${XDR_C} PROPERTIES COMPILE_OPTIONS "-Wno-unused;-Wno-format-truncation"
    )

    include_directories(${CMAKE_CURRENT_BINARY_DIR})

    add_executable(evpl_rpc2_${test_name} ${sources} ${XDR_C} ${XDR_H})
    target_link_libraries(evpl_rpc2_${test_name} evpl_rpc2 evpl pthread)

    # Set the first source for TEST_FILE environment variable
    list(GET sources 0 first_source)
    set(RPC2_TEST_EXE_${test_name} ${CMAKE_CURRENT_BINARY_DIR}/evpl_rpc2_${test_name})
    set(RPC2_TEST_SRC_${test_name} ${CMAKE_CURRENT_SOURCE_DIR}/${first_source})
endmacro()

# Macro to add a test instance for a specific protocol
macro(unit_test_rpc2_instance test_name protocol port)
    add_test(NAME libevpl/rpc2/${test_name}_${protocol}
             COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh
                     ${RPC2_TEST_EXE_${test_name}} -r ${protocol} -p ${port})

    set_tests_properties(libevpl/rpc2/${test_name}_${protocol} PROPERTIES
        ENVIRONMENT "TEST_FILE=${RPC2_TEST_SRC_${test_name}}"
        TIMEOUT 10)
endmacro()

# Build RPC2 test executables
unit_test_rpc2(hello_world hello_world.x hello_world.c)
unit_test_rpc2(builtin_bool builtin_bool.x builtin_bool.c)
unit_test_rpc2(rdma_ddp rdma_ddp.x rdma_ddp.c)

# Add test instances for STREAM_SOCKET_TCP
unit_test_rpc2_instance(hello_world STREAM_SOCKET_TCP 8100)
unit_test_rpc2_instance(builtin_bool STREAM_SOCKET_TCP 8101)
unit_test_rpc2_instance(rdma_ddp STREAM_SOCKET_TCP 8102)

# Add test instances for DATAGRAM_TCP_RDMA
unit_test_rpc2_instance(hello_world DATAGRAM_TCP_RDMA 8200)
unit_test_rpc2_instance(builtin_bool DATAGRAM_TCP_RDMA 8201)
unit_test_rpc2_instance(rdma_ddp DATAGRAM_TCP_RDMA 8202)
