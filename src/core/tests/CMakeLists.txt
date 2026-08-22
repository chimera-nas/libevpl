# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

unit_test(core init_no_config init_no_config.c)

# Builds the binary and registers the platform-default case; the loop below
# then runs the same binary once per mechanism compiled into this build.
# These create and destroy an evpl without touching the network, so they need
# neither a namespace nor the shared port lock.
unit_test(core init_core_mech init_core_mech.c)

foreach(mech ${EVPL_MECHANISMS})
    add_test(NAME libevpl/core/init_core_mech_${mech}
             COMMAND ${CMAKE_CURRENT_BINARY_DIR}/core_init_core_mech ${mech})
endforeach()
unit_test(core init_auto_no_config init_auto_no_config.c)
unit_test(core init_with_clean_config init_with_clean_config.c)
unit_test(core unused_config unused_config.c)
unit_test(core tls_cipher_config tls_cipher_config.c)
unit_test_all_mechs(core timer_oneshot timer_oneshot.c)

# Retiring a doorbell from inside the dispatch loop.  Touches no network, so it
# needs neither a namespace nor the port lock.  The bounded timeout is
# load-bearing: a regression that strands an entry in the active list stops
# delivery rather than crashing, which shows up here as a hang.
unit_test_all_mechs(core doorbell_remove doorbell_remove.c)

foreach(mech ${EVPL_MECHANISMS})
    set_tests_properties(libevpl/core/doorbell_remove_${mech}
                         PROPERTIES TIMEOUT 10)
endforeach()

# Growing an iovec ring with a wrapped waist.  Drives the ring directly rather
# than through a protocol, since the waist is only advanced by the RDMA CM one.
unit_test(core iovec_ring_resize iovec_ring_resize.c)

# The public fd-event API against a pipe: latched readiness, quiescence after
# drain, mark_readable without a kernel edge, and retiring an event from its
# own callback.  Touches no network.  A regression that keeps a drained event
# active shows up as a spin, one that strands it shows up as a hang; the
# bounded timeout catches both.
unit_test_all_mechs(core fd_event_pipe fd_event_pipe.c)

foreach(mech ${EVPL_MECHANISMS})
    set_tests_properties(libevpl/core/fd_event_pipe_${mech}
                         PROPERTIES TIMEOUT 10)
endforeach()

# Local (AF_UNIX) endpoints: addressed by socket name, so no namespace needed.
unit_test_local(core endpoint_local endpoint_local.c)

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

if(QUINT_EXECUTABLE AND PYTHON3_EXECUTABLE)
    set(CORE_QUINT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/quint)
    set(CORE_QUINT_WORK_DIR ${CMAKE_CURRENT_BINARY_DIR}/quint)
    set(CORE_CASES ${CORE_QUINT_WORK_DIR}/core_cases.h)

    add_custom_command(
        OUTPUT ${CORE_CASES}
        COMMAND ${CORE_QUINT_SRC_DIR}/generate_core_cases.sh
                ${QUINT_EXECUTABLE} ${PYTHON3_EXECUTABLE}
                ${CORE_QUINT_SRC_DIR} ${CORE_QUINT_WORK_DIR} ${CORE_CASES}
        DEPENDS ${CORE_QUINT_SRC_DIR}/core.qnt
                ${CORE_QUINT_SRC_DIR}/itf_to_core_cases.py
                ${CORE_QUINT_SRC_DIR}/generate_core_cases.sh
        COMMENT "Generating core conformance programs from the Quint model"
        VERBATIM)

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

    # The model checking itself: scenario tests plus a random-simulation pass
    # against its invariants.  Separate from generation so that a broken
    # specification is a failing test rather than a failing build.
    add_test(NAME libevpl/core/quint_core_model
             COMMAND ${CORE_QUINT_SRC_DIR}/check_core_models.sh
                     ${QUINT_EXECUTABLE} ${CORE_QUINT_SRC_DIR})
    set_tests_properties(libevpl/core/quint_core_model PROPERTIES
                         LABELS "quint" TIMEOUT 120)

    message(STATUS "Core conformance test enabled (quint: ${QUINT_EXECUTABLE})")
else()
    message(STATUS
        "Core conformance test disabled (needs quint and python3 on PATH)")
endif()
