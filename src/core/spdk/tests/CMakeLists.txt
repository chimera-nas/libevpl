# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# SPDK guest-mode tests run under a mini-reactor harness (spdk_test_harness.h)
# rather than the per-mechanism replication used by generic tests, which pump
# evpl from a plain pthread and cannot run in guest mode.  The harness calls
# SPDK env/thread APIs directly, so the test binaries link SPDK themselves.
#
# LeakSanitizer is disabled for these tests: DPDK's EAL allocates
# process-lifetime state it never frees, which would otherwise fail every
# debug (ASAN) run.
macro(spdk_unit_test test_name)
    unit_test(spdk ${test_name} spdk_${test_name}.c)

    target_link_libraries(spdk_${test_name} ${SPDK_LINK_TARGETS})

    set_property(TEST libevpl/spdk/${test_name} APPEND PROPERTY
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
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
        ENVIRONMENT "TEST_FILE=${LIBEVPL_SOURCE_DIR}/src/tests/ping_pong_connected_msg.c;EVPL_TEST_CORE_MECH=spdk;ASAN_OPTIONS=detect_leaks=0")
else()
    add_test(NAME libevpl/spdk/sock_bulk_connected_msg
             COMMAND ${TEST_BIN}/ping_pong_connected_msg -r STREAM_SPDK_TCP)
    set_tests_properties(libevpl/spdk/sock_bulk_connected_msg PROPERTIES
        RESOURCE_LOCK evpl_net
        ENVIRONMENT "TEST_FILE=${LIBEVPL_SOURCE_DIR}/src/tests/ping_pong_connected_msg.c;EVPL_TEST_CORE_MECH=spdk;ASAN_OPTIONS=detect_leaks=0")
endif()

# bdev tests bring up the bdev subsystem from JSON (spdk_init +
# spdk_event_bdev, test-only link modules).
spdk_unit_test(bdev_basic)
target_link_libraries(spdk_bdev_basic ${SPDK_TEST_LINK_TARGETS})
spdk_unit_test(bdev_open_fail)
target_link_libraries(spdk_bdev_open_fail ${SPDK_TEST_LINK_TARGETS})
