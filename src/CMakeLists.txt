# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# Tests bind fixed loopback ports (e.g. 127.0.0.1:8000).  On Linux with
# CAP_NET_ADMIN each runs inside its own network namespace, so they are safe to
# run concurrently.  Where network namespaces are unavailable (macOS, or Linux
# without CAP_NET_ADMIN) the test is instead registered to run directly and all
# such tests share the CTest RESOURCE_LOCK "evpl_net", which forces them to run
# one at a time so they cannot collide on a port even under `ctest -j`.
macro(unit_test module test_name)

    set(sources ${ARGN})

    add_executable(${module}_${test_name} ${sources})

    target_link_libraries(${module}_${test_name} evpl pthread)

    list(GET sources 0 first_source)

    if(LIBEVPL_NETNS_TESTING)
        add_test(NAME libevpl/${module}/${test_name} COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh ${CMAKE_CURRENT_BINARY_DIR}/${module}_${test_name})

        set_tests_properties(libevpl/${module}/${test_name} PROPERTIES
            ENVIRONMENT "TEST_FILE=${CMAKE_CURRENT_SOURCE_DIR}/${first_source}")
    else()
        add_test(NAME libevpl/${module}/${test_name} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${module}_${test_name})

        set_tests_properties(libevpl/${module}/${test_name} PROPERTIES
            RESOURCE_LOCK evpl_net
            ENVIRONMENT "TEST_FILE=${CMAKE_CURRENT_SOURCE_DIR}/${first_source}")
    endif()

endmacro()

# Build a test from source and register it once per event-loop core mechanism
# compiled into this build.  The test must select the mechanism from
# EVPL_TEST_CORE_MECH (see test_evpl_config in src/tests/test_common.h).
macro(unit_test_all_mechs module test_name)

    set(sources ${ARGN})

    add_executable(${module}_${test_name} ${sources})

    target_link_libraries(${module}_${test_name} evpl pthread)

    list(GET sources 0 first_source)

    foreach(mech ${EVPL_MECHANISMS})
        set(_test libevpl/${module}/${test_name}_${mech})

        if(LIBEVPL_NETNS_TESTING)
            add_test(NAME ${_test} COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh ${CMAKE_CURRENT_BINARY_DIR}/${module}_${test_name})

            set_tests_properties(${_test} PROPERTIES
                ENVIRONMENT "TEST_FILE=${CMAKE_CURRENT_SOURCE_DIR}/${first_source};EVPL_TEST_CORE_MECH=${mech}")
        else()
            add_test(NAME ${_test} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${module}_${test_name})

            set_tests_properties(${_test} PROPERTIES
                RESOURCE_LOCK evpl_net
                ENVIRONMENT "TEST_FILE=${CMAKE_CURRENT_SOURCE_DIR}/${first_source};EVPL_TEST_CORE_MECH=${mech}")
        endif()
    endforeach()

endmacro()

# Register a prebuilt test binary once per event-loop core mechanism compiled
# into this build, so every mechanism (epoll/kqueue/select) gets exercised by
# the same I/O coverage.  The mechanism is handed to the test through
# EVPL_TEST_CORE_MECH and applied by test_evpl_config() in
# src/tests/test_common.h, so no test source needs to know about it.
macro(unit_test_bin_all_mechs module test_name binary_name)
    foreach(mech ${EVPL_MECHANISMS})
        set(_test libevpl/${module}/${test_name}_${mech})

        get_target_property(test_file ${binary_name} TEST_FILE)

        if(LIBEVPL_NETNS_TESTING)
            add_test(NAME ${_test} COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh ${TEST_BIN}/${binary_name} ${ARGN})

            set_tests_properties(${_test} PROPERTIES
                ENVIRONMENT "TEST_FILE=${test_file};EVPL_TEST_CORE_MECH=${mech}")
        else()
            add_test(NAME ${_test} COMMAND ${TEST_BIN}/${binary_name} ${ARGN})

            set_tests_properties(${_test} PROPERTIES
                RESOURCE_LOCK evpl_net
                ENVIRONMENT "TEST_FILE=${test_file};EVPL_TEST_CORE_MECH=${mech}")
        endif()
    endforeach()
endmacro()

macro(unit_test_bin module test_name binary_name)

    if(LIBEVPL_NETNS_TESTING)
        add_test(NAME libevpl/${module}/${test_name} COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh ${TEST_BIN}/${binary_name} ${ARGN})

        get_target_property(test_file ${binary_name} TEST_FILE)
        set_tests_properties(libevpl/${module}/${test_name} PROPERTIES
            ENVIRONMENT "TEST_FILE=${test_file}")
    else()
        add_test(NAME libevpl/${module}/${test_name} COMMAND ${TEST_BIN}/${binary_name} ${ARGN})

        get_target_property(test_file ${binary_name} TEST_FILE)
        set_tests_properties(libevpl/${module}/${test_name} PROPERTIES
            RESOURCE_LOCK evpl_net
            ENVIRONMENT "TEST_FILE=${test_file}")
    endif()
endmacro()

macro(unit_test_xdr module test_name xdr_file)
    set(sources ${ARGN})


    set(XDR_C ${CMAKE_CURRENT_BINARY_DIR}/${test_name}_xdr.c)
    set(XDR_H ${CMAKE_CURRENT_BINARY_DIR}/${test_name}_xdr.h)
    set(XDR_X ${CMAKE_CURRENT_SOURCE_DIR}/${xdr_file})

    add_custom_command(
        OUTPUT ${XDR_C} ${XDR_H}
        COMMAND ${XDRZCC} ${XDR_X} ${XDR_C} ${XDR_H}
        DEPENDS ${xdr_file} ${XDRZCC}
        COMMENT "Compiling ${xdr_file}"
    )

    set_source_files_properties(
        ${XDR_C} PROPERTIES COMPILE_OPTIONS -Wno-unused
    )

    include_directories(${CMAKE_CURRENT_BINARY_DIR})

    unit_test(${module} ${test_name} ${sources} ${XDR_C} ${XDR_H})

endmacro()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()

add_subdirectory(core)
add_subdirectory(http)
add_subdirectory(rpc2)