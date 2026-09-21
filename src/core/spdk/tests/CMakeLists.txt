# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# SPDK guest-mode tests run under a mini-reactor harness (spdk_test_harness.h)
# rather than the per-mechanism replication used by generic tests, which pump
# evpl from a plain pthread and cannot run in guest mode.  The harness calls
# SPDK env/thread APIs directly, so the test binaries link SPDK themselves.
#
# Keep LeakSanitizer enabled: explicit guest cleanup precedes host teardown.
macro(spdk_unit_test test_name)
    unit_test(spdk ${test_name} spdk_${test_name}.c)

    target_link_libraries(spdk_${test_name} ${SPDK_LINK_TARGETS})
    set_tests_properties(libevpl/spdk/${test_name} PROPERTIES TIMEOUT 30)

    set_property(TEST libevpl/spdk/${test_name} APPEND PROPERTY
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1")
endmacro()

spdk_unit_test(thread_basic)
spdk_unit_test(thread_same_reactor)
spdk_unit_test(threadpool_pingpong)
spdk_unit_test(doorbell)
spdk_unit_test(timer)
spdk_unit_test(memreg)
spdk_unit_test(sock_pingpong)
spdk_unit_test(sock_msg)

# Protocol coverage for STREAM_SPDK_TCP via the shared, evpl_thread-driven
# stream test binary (windowed message ping-pong with segment framing).
if(LIBEVPL_NETNS_TESTING)
    add_test(NAME libevpl/spdk/sock_bulk_connected_msg
             COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh
                     ${TEST_BIN}/ping_pong_connected_msg -r STREAM_SPDK_TCP)
    set_tests_properties(libevpl/spdk/sock_bulk_connected_msg PROPERTIES
        ENVIRONMENT "TEST_FILE=${LIBEVPL_SOURCE_DIR}/src/tests/ping_pong_connected_msg.c;EVPL_TEST_CORE_MECH=spdk;ASAN_OPTIONS=detect_leaks=1")
else()
    add_test(NAME libevpl/spdk/sock_bulk_connected_msg
             COMMAND ${TEST_BIN}/ping_pong_connected_msg -r STREAM_SPDK_TCP)
    set_tests_properties(libevpl/spdk/sock_bulk_connected_msg PROPERTIES
        RESOURCE_LOCK evpl_net
        ENVIRONMENT "TEST_FILE=${LIBEVPL_SOURCE_DIR}/src/tests/ping_pong_connected_msg.c;EVPL_TEST_CORE_MECH=spdk;ASAN_OPTIONS=detect_leaks=1")
endif()

# bdev tests bring up the bdev subsystem from JSON (spdk_init +
# spdk_event_bdev, test-only link modules).
spdk_unit_test(bdev_basic)
target_link_libraries(spdk_bdev_basic ${SPDK_TEST_LINK_TARGETS})
spdk_unit_test(bdev_open_fail)
target_link_libraries(spdk_bdev_open_fail ${SPDK_TEST_LINK_TARGETS})

foreach(name timer sock_pingpong sock_msg)
    add_test(NAME libevpl/spdk/${name}_interrupt COMMAND $<TARGET_FILE:spdk_${name}>)
    set_tests_properties(libevpl/spdk/${name}_interrupt PROPERTIES
        TIMEOUT 30 RESOURCE_LOCK evpl_net
        ENVIRONMENT "EVPL_TEST_INTERRUPT=1;ASAN_OPTIONS=detect_leaks=1")
endforeach()
add_test(NAME libevpl/spdk/sock_no_poll COMMAND $<TARGET_FILE:spdk_sock_pingpong>)
set_tests_properties(libevpl/spdk/sock_no_poll PROPERTIES TIMEOUT 30 RESOURCE_LOCK evpl_net
    ENVIRONMENT "EVPL_TEST_NO_POLL=1;ASAN_OPTIONS=detect_leaks=1")
spdk_unit_test(lifecycle)
spdk_unit_test(migration)
pkg_check_modules(SPDK_EVENT REQUIRED IMPORTED_TARGET spdk_event)
evpl_spdk_link_modules(PkgConfig::SPDK_EVENT)
spdk_unit_test(app_host)
target_link_libraries(spdk_app_host PkgConfig::SPDK_EVENT ${SPDK_TEST_LINK_TARGETS})
add_test(NAME libevpl/spdk/app_host_interrupt COMMAND $<TARGET_FILE:spdk_app_host>)
set_tests_properties(libevpl/spdk/app_host_interrupt PROPERTIES TIMEOUT 30
    ENVIRONMENT "EVPL_TEST_INTERRUPT=1;ASAN_OPTIONS=detect_leaks=1")
add_test(NAME libevpl/spdk/lifecycle_interrupt COMMAND $<TARGET_FILE:spdk_lifecycle>)
set_tests_properties(libevpl/spdk/lifecycle_interrupt PROPERTIES TIMEOUT 30
    ENVIRONMENT "EVPL_TEST_INTERRUPT=1;ASAN_OPTIONS=detect_leaks=1")
add_library(spdk_bdev_faults SHARED bdev_faults.c)
target_link_libraries(spdk_bdev_faults ${SPDK_LINK_TARGETS} ${CMAKE_DL_LIBS})
add_test(NAME libevpl/spdk/bdev_bounce_retry COMMAND $<TARGET_FILE:spdk_bdev_basic>)
set_tests_properties(libevpl/spdk/bdev_bounce_retry PROPERTIES TIMEOUT 30
    ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:spdk_bdev_faults>;ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1")
add_executable(spdk_durability spdk_durability.c)
target_link_libraries(spdk_durability evpl ${SPDK_LINK_TARGETS})
add_test(NAME libevpl/spdk/durability COMMAND $<TARGET_FILE:spdk_durability>)
set_tests_properties(libevpl/spdk/durability PROPERTIES TIMEOUT 30)
target_link_libraries(spdk_durability ${SPDK_TEST_LINK_TARGETS})
set_tests_properties(libevpl/spdk/durability PROPERTIES
    ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:spdk_bdev_faults>;EVPL_TEST_NO_FLUSH=1;ASAN_OPTIONS=detect_leaks=1")
spdk_unit_test(device_events)
target_link_libraries(spdk_device_events ${SPDK_TEST_LINK_TARGETS})
spdk_unit_test(poll_progress)
add_test(NAME libevpl/spdk/poll_progress_interrupt COMMAND $<TARGET_FILE:spdk_poll_progress>)
set_tests_properties(libevpl/spdk/poll_progress_interrupt PROPERTIES TIMEOUT 30
    ENVIRONMENT "EVPL_TEST_INTERRUPT=1;ASAN_OPTIONS=detect_leaks=1")
