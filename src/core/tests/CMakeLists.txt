# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

unit_test(core init_no_config init_no_config.c)
unit_test_all_mechs(core destroy_pending destroy_pending.c)
unit_test_all_mechs(core listener_lifetime listener_lifetime.c)

# Builds the binary and registers the platform-default case; the loop below
# then runs the same binary once per mechanism compiled into this build.
# These create and destroy an evpl without touching the network, so they need
# neither a namespace nor the shared port lock.
unit_test(core init_core_mech init_core_mech.c)

foreach(mech ${EVPL_MECHANISMS})
    add_test(NAME libevpl/core/init_core_mech_${mech}
             COMMAND $<TARGET_FILE:core_init_core_mech> ${mech})
endforeach()
unit_test(core init_auto_no_config init_auto_no_config.c)
unit_test(core init_with_clean_config init_with_clean_config.c)
unit_test(core unused_config unused_config.c)
unit_test(core tls_cipher_config tls_cipher_config.c)
unit_test_all_mechs_spdk(core timer_oneshot timer_oneshot.c)

# Retiring a doorbell from inside the dispatch loop.  Touches no network, so it
# needs neither a namespace nor the port lock.  The bounded timeout is
# load-bearing: a regression that strands an entry in the active list stops
# delivery rather than crashing, which shows up here as a hang.
unit_test_all_mechs(core doorbell_remove doorbell_remove.c)
unit_test_all_mechs(core doorbell_sender doorbell_sender.c)

foreach(mech ${EVPL_MECHANISMS})
    set_tests_properties(libevpl/core/doorbell_remove_${mech}
                         PROPERTIES TIMEOUT 10)
endforeach()

# Retiring one poller must leave the other pollers' handles meaning what they
# meant before.  Touches no network, so it needs neither a namespace nor the
# port lock, and it identifies pollers by value, so it fails the same way in a
# Release build as under AddressSanitizer.
unit_test_all_mechs(core poll_remove poll_remove.c)

foreach(mech ${EVPL_MECHANISMS})
    set_tests_properties(libevpl/core/poll_remove_${mech}
                         PROPERTIES TIMEOUT 10)
endforeach()

# Growing an iovec ring with a wrapped waist.  Drives the ring directly rather
# than through a protocol, since the waist is only advanced by the RDMA CM one.
unit_test(core iovec_ring_resize iovec_ring_resize.c)
unit_test(core iovec_ring_gather iovec_ring_gather.c)


# The public fd-event API against a pipe: latched readiness, quiescence after
# drain, mark_readable without a kernel edge, and retiring an event from its
# own callback.  Touches no network.  A regression that keeps a drained event
# active shows up as a spin, one that strands it shows up as a hang; the
# bounded timeout catches both.
if(NOT WIN32)
unit_test_all_mechs(core fd_event_pipe fd_event_pipe.c)

foreach(mech ${EVPL_MECHANISMS})
    set_tests_properties(libevpl/core/fd_event_pipe_${mech}
                         PROPERTIES TIMEOUT 10)
endforeach()

# Local (AF_UNIX) endpoints: addressed by socket name, so no namespace needed.
unit_test_local(core endpoint_local endpoint_local.c)
endif()

# In-process endpoints: named through a registry private to the process, so
# nothing outside it is shared and no namespace is needed either.
unit_test_local(core endpoint_inproc endpoint_inproc.c)

# ---------------------------------------------------------------------------
# Model-based core SDK conformance test
#
# The programs this test runs are generated from the Quint model in quint/ by
# a build step, so the traces and the resulting table are build artifacts
# under the build tree rather than checked-in files that could drift from the
# model they came from.  That makes quint a build dependency, so the whole
# test is registered only when quint and python3 are both present; without
# them the rest of the suite builds and runs as normal.
#
# Registered like the other networked tests: the programs run over TCP and UDP
# as well as the two in-process transports, so they bind real ports and cannot
# run alongside anything else that does.  Under network namespaces each
# instance is isolated; without them they share the "evpl_net" lock.
# ---------------------------------------------------------------------------

find_program(QUINT_EXECUTABLE quint)
find_program(PYTHON3_EXECUTABLE NAMES python3 python)

if(EVPL_CONFORMANCE_CASES_DIR OR (NOT WIN32 AND QUINT_EXECUTABLE AND PYTHON3_EXECUTABLE))
    set(CORE_QUINT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/quint)
    set(CORE_QUINT_WORK_DIR ${CMAKE_CURRENT_BINARY_DIR}/quint)
    if(EVPL_CONFORMANCE_CASES_DIR)
        set(CORE_QUINT_WORK_DIR ${EVPL_CONFORMANCE_CASES_DIR})
    endif()
    set(CORE_CASES ${CORE_QUINT_WORK_DIR}/core_cases.h)

    if(NOT EVPL_CONFORMANCE_CASES_DIR)
    add_custom_command(
        OUTPUT ${CORE_CASES}
        COMMAND ${CORE_QUINT_SRC_DIR}/generate_core_cases.sh
                ${QUINT_EXECUTABLE} ${PYTHON3_EXECUTABLE}
                ${CORE_QUINT_SRC_DIR} ${CORE_QUINT_WORK_DIR} ${CORE_CASES}
        DEPENDS ${CORE_QUINT_SRC_DIR}/core.qnt
                ${CORE_QUINT_SRC_DIR}/core_generation.qnt
                ${CORE_QUINT_SRC_DIR}/itf_to_core_cases.py
                ${CORE_QUINT_SRC_DIR}/generate_core_cases.sh
        COMMENT "Generating core conformance programs from the Quint model"
        VERBATIM)
    endif()

    add_custom_target(core_cases DEPENDS ${CORE_CASES})

    unit_test_all_mechs(core core_conformance core_conformance.c)
    target_sources(core_core_conformance PRIVATE ${CORE_CASES})
    target_include_directories(core_core_conformance
                               PRIVATE ${CORE_QUINT_WORK_DIR})

    # AF_UNIX programs need somewhere to put their socket files.  Appended
    # rather than set, so the mechanism and TEST_FILE the macro already put
    # there survive.
    foreach(mech ${EVPL_MECHANISMS})
        set_property(TEST libevpl/core/core_conformance_${mech} APPEND
                     PROPERTY ENVIRONMENT
                     "EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR}")
    endforeach()

    # Every quiesce runs its full window rather than stopping once its
    # obligations are met, since an absence is only observed by getting to the
    # end without it -- but a window is an advance of libevpl's virtual clock,
    # not a sleep, so the whole suite is a fraction of a second and this
    # timeout is only here to bound a hang.
    foreach(mech ${EVPL_MECHANISMS})
        set_tests_properties(libevpl/core/core_conformance_${mech}
                             PROPERTIES TIMEOUT 60)
    endforeach()

    if(NOT EVPL_CONFORMANCE_CASES_DIR)
    # The model checking itself: scenario tests plus a random-simulation pass
    # against its invariants.  Separate from generation so that a broken
    # specification is a failing test rather than a failing build.
    add_test(NAME libevpl/core/quint_core_model
             COMMAND ${CORE_QUINT_SRC_DIR}/check_core_models.sh
                     ${QUINT_EXECUTABLE} ${CORE_QUINT_SRC_DIR})
    set_tests_properties(libevpl/core/quint_core_model PROPERTIES
                         # 360s, not the 120s these budgets were first set to:
                         # generation and model-checking now run quint's
                         # TYPESCRIPT backend everywhere (see
                         # quint/check_core_models.sh), which is ~2.4x slower
                         # than the rust evaluator but is the only one that runs
                         # on ubuntu 22.04 / rocky 9.  Both models timed out at
                         # exactly 120s on the switch.
                         LABELS "quint" TIMEOUT 360)

    endif()
    message(STATUS "Core conformance test enabled (quint: ${QUINT_EXECUTABLE})")
else()
    message(STATUS
        "Core conformance test disabled (supply EVPL_CONFORMANCE_CASES_DIR, or quint and python3 on a Unix host)")
endif()

# Reply using the borrowed source address after the receive callback returns.
unit_test_all_mechs(core udp_reply_address udp_reply_address.c)
foreach(mech ${EVPL_MECHANISMS})
    set_tests_properties(libevpl/core/udp_reply_address_${mech} PROPERTIES TIMEOUT 10)
endforeach()

# Native wakeup preparation must run before every sleep, independently of
# busy-poll transitions, without replacing application loop hooks.
unit_test_all_mechs(core poll_prepare poll_prepare.c)
target_include_directories(core_poll_prepare PRIVATE ${LIBEVPL_SOURCE_DIR}/src/tests)

foreach(mech ${EVPL_MECHANISMS})
    set_tests_properties(libevpl/core/poll_prepare_${mech} PROPERTIES TIMEOUT 10)
endforeach()

# This regression exercises POSIX descriptor readiness, unavailable with IOCP.
if(NOT WIN32)
    unit_test_all_mechs(core fd_reuse fd_reuse.c)
    foreach(mech ${EVPL_MECHANISMS})
        set_tests_properties(libevpl/core/fd_reuse_${mech} PROPERTIES TIMEOUT 10)
    endforeach()
    unit_test_all_mechs(core close_ready close_ready.c)
    target_include_directories(core_close_ready PRIVATE ${LIBEVPL_SOURCE_DIR}/src/tests)
endif()

if(TARGET core_core_conformance)
    include(${CMAKE_CURRENT_SOURCE_DIR}/config_profiles.cmake)
    foreach(profile ${MBT_CONFIG_PROFILES})
        foreach(mech ${EVPL_MECHANISMS})
            unit_test_mbt_variant(core core_conformance_config_${profile}_${mech} core_core_conformance
                ${mech} TIMEOUT 180 ENVIRONMENT EVPL_TEST_CONFIG_PROFILE=${profile}
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        endforeach()
    endforeach()
    foreach(mech ${EVPL_MECHANISMS})
        unit_test_mbt_variant(core core_conformance_inproc_${mech}
            core_core_conformance ${mech} TIMEOUT 120 ENVIRONMENT
            EVPL_TEST_STREAM_PROTOCOL=STREAM_INPROC
            EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        if(NOT WIN32)
            unit_test_mbt_variant(core core_conformance_unix_${mech}
                core_core_conformance ${mech} TIMEOUT 120 ENVIRONMENT
                EVPL_TEST_STREAM_PROTOCOL=STREAM_SOCKET_UNIX
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        endif()
    endforeach()
    # The guest supplies unrestricted kernel I/O and a disposable NVMe device.
    # Keep hardware-dependent registrations explicit on ordinary developer hosts.
    if(EVPL_STORAGE_TESTS)
        foreach(backend libaio io_uring io_uring_nvme vfio)
            string(TOUPPER "${backend}" feature)
            if(NOT HAVE_${feature})
                message(FATAL_ERROR "Storage MBT requires ${backend}")
            endif()
            foreach(mech ${EVPL_MECHANISMS})
                unit_test_mbt_variant(core core_conformance_${backend}_${mech}
                    core_core_conformance ${mech} GUEST TIMEOUT 300 ENVIRONMENT
                    EVPL_TEST_PORTABLE_ONLY=1 EVPL_TEST_BLOCK_PROTOCOL=${backend}
                    EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
                set_property(TEST libevpl/core/core_conformance_${backend}_${mech}
                    APPEND PROPERTY LABELS mbt_storage)
            endforeach()
        endforeach()
    endif()
    if(HAVE_RDMACM AND EVPL_RDMA_TEST_IP)
        foreach(mech ${EVPL_MECHANISMS})
            unit_test_mbt_variant(core core_conformance_rdma_${mech}
                core_core_conformance ${mech} RDMA TIMEOUT 300 ENVIRONMENT
                EVPL_TEST_PORTABLE_ONLY=1 EVPL_TEST_MAX_DATAGRAM=4096
                EVPL_TEST_DATAGRAM_PROTOCOL=DATAGRAM_RDMACM_UD
                EVPL_TEST_MESSAGE_PROTOCOL=DATAGRAM_RDMACM_RC
                EVPL_TEST_STREAM_PROTOCOL=STREAM_RDMACM_RC
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        endforeach()
    endif()
    if(HAVE_TLS)
        foreach(mech ${EVPL_MECHANISMS})
            foreach(mode software auto)
                unit_test_mbt_variant(core core_conformance_tls_${mode}_${mech}
                    core_core_conformance ${mech} TIMEOUT 180 ENVIRONMENT
                    EVPL_TEST_PORTABLE_ONLY=1 EVPL_TEST_TLS_MODE=${mode}
                    EVPL_TEST_STREAM_PROTOCOL=STREAM_SOCKET_TLS
                    EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            endforeach()
        endforeach()
        if(HAVE_SPDK)
            unit_test_mbt_variant(core core_conformance_tls_software_spdk
                core_core_conformance spdk TIMEOUT 180 ENVIRONMENT
                ASAN_OPTIONS=detect_leaks=1 EVPL_TEST_PORTABLE_ONLY=1
                EVPL_TEST_TLS_MODE=software EVPL_TEST_STREAM_PROTOCOL=STREAM_SOCKET_TLS
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        endif()
    endif()
    if(HAVE_LIBFABRIC)
        # Provider policy belongs to the adapter. Native TCP RDM in libfabric
        # 2.1 loops on simultaneous connects; 2.x also leaks rejection data.
        # RxM runs the same programs with assertions and sanitizers intact.
        set(EVPL_MBT_LIBFABRIC_RDM_PROVIDER "tcp;ofi_rxm" CACHE STRING
            "Provider for RDM model replay (tcp selects native TCP RDM)")
        string(REPLACE ";" "\\;" _rdm_provider "${EVPL_MBT_LIBFABRIC_RDM_PROVIDER}")
        foreach(mech ${EVPL_MECHANISMS})
            unit_test_mbt_variant(core core_conformance_libfabric_${mech}
                core_core_conformance ${mech} TIMEOUT 120 ENVIRONMENT
                EVPL_TEST_PORTABLE_ONLY=1 FI_PROVIDER=tcp
                EVPL_TEST_MESSAGE_PROTOCOL=DATAGRAM_LIBFABRIC_MSG
                EVPL_TEST_STREAM_PROTOCOL=STREAM_LIBFABRIC_MSG
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            unit_test_mbt_variant(core core_conformance_libfabric_rdm_${mech}
                core_core_conformance ${mech} TIMEOUT 120 ENVIRONMENT
                EVPL_TEST_PORTABLE_ONLY=1
                EVPL_TEST_DATAGRAM_PROTOCOL=DATAGRAM_LIBFABRIC_RDM
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            set_property(TEST libevpl/core/core_conformance_libfabric_rdm_${mech}
                APPEND PROPERTY ENVIRONMENT "FI_PROVIDER=${_rdm_provider}")
        endforeach()
    endif()
    if(HAVE_SPDK)
        target_link_libraries(core_core_conformance ${SPDK_TEST_LINK_TARGETS})
        # The core oracle advances virtual time. Interrupt-mode replay uses
        # real-time HTTP/RPC models instead of sleeping on virtual deadlines.
        unit_test_mbt_variant(core core_conformance_spdk core_core_conformance
            spdk TIMEOUT 120 ENVIRONMENT ASAN_OPTIONS=detect_leaks=1
            EVPL_TEST_PORTABLE_ONLY=1
            EVPL_TEST_BLOCK_PROTOCOL=spdk EVPL_TEST_STREAM_PROTOCOL=STREAM_SPDK_TCP
            EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        if(HAVE_LIBFABRIC)
            unit_test_mbt_variant(core core_conformance_libfabric_spdk core_core_conformance
                spdk TIMEOUT 120 ENVIRONMENT ASAN_OPTIONS=detect_leaks=1 FI_PROVIDER=tcp
                EVPL_TEST_PORTABLE_ONLY=1 EVPL_TEST_MESSAGE_PROTOCOL=DATAGRAM_LIBFABRIC_MSG
                EVPL_TEST_BLOCK_PROTOCOL=spdk EVPL_TEST_STREAM_PROTOCOL=STREAM_LIBFABRIC_MSG
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            unit_test_mbt_variant(core core_conformance_libfabric_rdm_spdk core_core_conformance
                spdk TIMEOUT 120 ENVIRONMENT ASAN_OPTIONS=detect_leaks=1
                EVPL_TEST_PORTABLE_ONLY=1 EVPL_TEST_BLOCK_PROTOCOL=spdk
                EVPL_TEST_DATAGRAM_PROTOCOL=DATAGRAM_LIBFABRIC_RDM
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            set_property(TEST libevpl/core/core_conformance_libfabric_rdm_spdk
                APPEND PROPERTY ENVIRONMENT "FI_PROVIDER=${_rdm_provider}")
        endif()
    endif()
endif()

# C trace replays, distinct from the Quint specification checks (label quint).
get_property(_mbt_tests DIRECTORY PROPERTY TESTS)
foreach(_test ${_mbt_tests})
    if(_test MATCHES "^libevpl/core/core_conformance_")
        set_property(TEST ${_test} APPEND PROPERTY LABELS mbt)
    endif()
endforeach()

# Separate SDK state machines share a generated corpus across mechanisms.
if(NOT WIN32 AND (EVPL_CONFORMANCE_CASES_DIR OR (QUINT_EXECUTABLE AND PYTHON3_EXECUTABLE)))
    set(SDK_CASES_DIR ${CMAKE_CURRENT_BINARY_DIR}/quint-sdk)
    if(EVPL_CONFORMANCE_CASES_DIR)
        set(SDK_CASES_DIR ${EVPL_CONFORMANCE_CASES_DIR})
    else()
        add_custom_command(OUTPUT ${SDK_CASES_DIR}/listener_cases.h ${SDK_CASES_DIR}/fd_cases.h ${SDK_CASES_DIR}/lifecycle_cases.h ${SDK_CASES_DIR}/block_lifecycle_cases.h ${SDK_CASES_DIR}/ownership_cases.h ${SDK_CASES_DIR}/block_retry_cases.h ${SDK_CASES_DIR}/rdma_cases.h ${SDK_CASES_DIR}/unix_path_cases.h ${SDK_CASES_DIR}/registration_cases.h
            COMMAND ${PYTHON3_EXECUTABLE} ${CORE_QUINT_SRC_DIR}/generate_sdk_cases.py
                    ${QUINT_EXECUTABLE} ${CORE_QUINT_SRC_DIR} ${SDK_CASES_DIR}
            DEPENDS ${CORE_QUINT_SRC_DIR}/listener.qnt ${CORE_QUINT_SRC_DIR}/generate_sdk_cases.py
                    ${CORE_QUINT_SRC_DIR}/fd.qnt ${CORE_QUINT_SRC_DIR}/lifecycle.qnt ${CORE_QUINT_SRC_DIR}/block_lifecycle.qnt ${CORE_QUINT_SRC_DIR}/ownership.qnt ${CORE_QUINT_SRC_DIR}/block_retry.qnt
                    ${CORE_QUINT_SRC_DIR}/rdma.qnt ${CORE_QUINT_SRC_DIR}/unix_path.qnt ${CORE_QUINT_SRC_DIR}/registration.qnt
            VERBATIM)
    endif()
    foreach(family fd lifecycle listener ownership rdma unix_path registration)
        unit_test_all_mechs(core ${family}_conformance ${family}_conformance.c)
        target_sources(core_${family}_conformance PRIVATE ${SDK_CASES_DIR}/${family}_cases.h)
        target_include_directories(core_${family}_conformance PRIVATE ${SDK_CASES_DIR})
        foreach(mech ${EVPL_MECHANISMS})
            set_tests_properties(libevpl/core/${family}_conformance_${mech}
                PROPERTIES LABELS "mbt" TIMEOUT 60)
        endforeach()
    endforeach()
    # Registration-table symbols are private. Compile the production component
    # into its replay instead of exporting test-only accessors from the SDK.
    target_sources(core_registration_conformance PRIVATE ../rdma_mr.c)
    foreach(mech ${EVPL_MECHANISMS})
        unit_test_mbt_variant(core ownership_conformance_shared_${mech}
            core_ownership_conformance ${mech} TIMEOUT 60 ENVIRONMENT EVPL_TEST_SHARED=1)
    endforeach()
endif()

if(TARGET core_core_conformance)
    foreach(mech ${EVPL_MECHANISMS})
        unit_test_mbt_variant(core core_conformance_capacity_${mech} core_core_conformance
            ${mech} TIMEOUT 120 ENVIRONMENT EVPL_TEST_SMALL_CAPACITY=1
            EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        unit_test_mbt_variant(core core_conformance_tcp_rdma_${mech} core_core_conformance
            ${mech} TIMEOUT 120 ENVIRONMENT EVPL_TEST_MESSAGE_PROTOCOL=DATAGRAM_TCP_RDMA
            EVPL_TEST_PORTABLE_ONLY=1 EVPL_TEST_ASYNC_LISTENER=1
            EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        if(HAVE_TLS)
            unit_test_mbt_variant(core core_conformance_alpn_${mech} core_core_conformance
                ${mech} TIMEOUT 180 ENVIRONMENT EVPL_TEST_ALPN=mbt/1 EVPL_TEST_TLS_ERROR_QUEUE=1
                EVPL_TEST_PORTABLE_ONLY=1 EVPL_TEST_TLS_MODE=software
                EVPL_TEST_STREAM_PROTOCOL=STREAM_SOCKET_TLS
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
        endif()
        if(EVPL_STORAGE_TESTS)
            unit_test_mbt_variant(core core_conformance_io_uring_tcp_${mech} core_core_conformance
                ${mech} GUEST TIMEOUT 180 ENVIRONMENT EVPL_TEST_PORTABLE_ONLY=1
                EVPL_TEST_STREAM_PROTOCOL=STREAM_IO_URING_TCP
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            unit_test_mbt_variant(core core_conformance_vfio_prp_${mech} core_core_conformance
                ${mech} GUEST TIMEOUT 300 ENVIRONMENT EVPL_TEST_PORTABLE_ONLY=1
                EVPL_TEST_BLOCK_PROTOCOL=vfio EVPL_TEST_VFIO_PRP=1
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            set_property(TEST libevpl/core/core_conformance_vfio_prp_${mech}
                APPEND PROPERTY LABELS mbt_storage)
            unit_test_mbt_variant(core core_conformance_vfio_interrupt_${mech} core_core_conformance
                ${mech} GUEST TIMEOUT 300 ENVIRONMENT EVPL_TEST_PORTABLE_ONLY=1
                EVPL_TEST_BLOCK_PROTOCOL=vfio EVPL_TEST_INTERRUPT=1
                EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR})
            set_property(TEST libevpl/core/core_conformance_io_uring_tcp_${mech}
                APPEND PROPERTY LABELS mbt_storage)
            set_property(TEST libevpl/core/core_conformance_vfio_interrupt_${mech}
                APPEND PROPERTY LABELS mbt_storage)
        endif()
    endforeach()
endif()
if(HAVE_SPDK AND TARGET core_lifecycle_conformance)
    unit_test_mbt_variant(core lifecycle_conformance_spdk core_lifecycle_conformance
        spdk TIMEOUT 120 ENVIRONMENT ASAN_OPTIONS=detect_leaks=1)
endif()

if(HAVE_SPDK AND TARGET core_lifecycle_conformance)
    add_executable(core_block_retry_conformance block_retry_conformance.c ${SDK_CASES_DIR}/block_retry_cases.h)
    target_include_directories(core_block_retry_conformance PRIVATE ${SDK_CASES_DIR})
    target_link_libraries(core_block_retry_conformance evpl ${SPDK_TEST_LINK_TARGETS} ${CMAKE_DL_LIBS})
    set_target_properties(core_block_retry_conformance PROPERTIES ENABLE_EXPORTS ON)
    unit_test_mbt_variant(core block_retry_conformance_spdk core_block_retry_conformance
        spdk TIMEOUT 120 ENVIRONMENT ASAN_OPTIONS=detect_leaks=1:detect_stack_use_after_return=1)
    add_executable(core_block_lifecycle_conformance block_lifecycle_conformance.c ${SDK_CASES_DIR}/block_lifecycle_cases.h)
    target_include_directories(core_block_lifecycle_conformance PRIVATE ${SDK_CASES_DIR})
    target_link_libraries(core_block_lifecycle_conformance evpl ${SPDK_TEST_LINK_TARGETS})
    unit_test_mbt_variant(core block_lifecycle_conformance_spdk core_block_lifecycle_conformance
        spdk TIMEOUT 120 ENVIRONMENT ASAN_OPTIONS=detect_leaks=1)
endif()

if(TARGET core_listener_conformance)
    foreach(mech ${EVPL_MECHANISMS})
        set_property(TEST libevpl/core/listener_conformance_${mech} APPEND PROPERTY ENVIRONMENT EVPL_TEST_ASYNC_LISTENER=1)
        foreach(protocol STREAM_INPROC DATAGRAM_TCP_RDMA)
            unit_test_mbt_variant(core listener_conformance_${protocol}_${mech} core_listener_conformance
                ${mech} TIMEOUT 60 ENVIRONMENT EVPL_TEST_ASYNC_LISTENER=1
                EVPL_TEST_STREAM_PROTOCOL=${protocol})
        endforeach()
        if(HAVE_TLS)
            unit_test_mbt_variant(core listener_conformance_TLS_${mech} core_listener_conformance
                ${mech} TIMEOUT 120 ENVIRONMENT EVPL_TEST_ASYNC_LISTENER=1
                EVPL_TEST_STREAM_PROTOCOL=STREAM_SOCKET_TLS EVPL_TEST_TLS_MODE=software)
        endif()
        if(EVPL_STORAGE_TESTS)
            unit_test_mbt_variant(core listener_conformance_io_uring_${mech} core_listener_conformance
                ${mech} GUEST TIMEOUT 120 ENVIRONMENT EVPL_TEST_ASYNC_LISTENER=1
                EVPL_TEST_STREAM_PROTOCOL=STREAM_IO_URING_TCP)
            set_property(TEST libevpl/core/listener_conformance_io_uring_${mech} APPEND PROPERTY LABELS mbt_storage)
        endif()
    endforeach()
endif()
