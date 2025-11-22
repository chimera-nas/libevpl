# SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# Custom macro for RPC2 tests that need both client and server code
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

    # Add the test
    add_test(NAME libevpl/rpc2/${test_name}
             COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh
                     ${CMAKE_CURRENT_BINARY_DIR}/evpl_rpc2_${test_name})

    # Set TEST_FILE environment variable
    list(GET sources 0 first_source)
    set_tests_properties(libevpl/rpc2/${test_name} PROPERTIES
        ENVIRONMENT "TEST_FILE=${CMAKE_CURRENT_SOURCE_DIR}/${first_source}"
        TIMEOUT 10)
endmacro()

# RPC2 test with both client and server
unit_test_rpc2(hello_world_tcp hello_world.x hello_world_tcp.c)
