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

# Add a test instance for a specific protocol, once per event-loop core
# mechanism compiled into this build.  Mirrors the shared macros in
# src/CMakeLists.txt: under network namespaces each instance is isolated, and
# without them they run directly but share the "evpl_net" resource lock so no
# two ever hold a listening port at the same time.
macro(unit_test_rpc2_instance test_name protocol port)
    foreach(mech ${EVPL_MECHANISMS})
        set(_test libevpl/rpc2/${test_name}_${protocol}_${mech})

        if(LIBEVPL_NETNS_TESTING)
            add_test(NAME ${_test}
                     COMMAND ${LIBEVPL_SOURCE_DIR}/scripts/netns_test_wrapper.sh
                             ${RPC2_TEST_EXE_${test_name}} -r ${protocol} -p ${port})

            set_tests_properties(${_test} PROPERTIES
                ENVIRONMENT "TEST_FILE=${RPC2_TEST_SRC_${test_name}};EVPL_TEST_CORE_MECH=${mech}"
                TIMEOUT 10)
        else()
            add_test(NAME ${_test}
                     COMMAND ${RPC2_TEST_EXE_${test_name}} -r ${protocol} -p ${port})

            set_tests_properties(${_test} PROPERTIES
                RESOURCE_LOCK evpl_net
                ENVIRONMENT "TEST_FILE=${RPC2_TEST_SRC_${test_name}};EVPL_TEST_CORE_MECH=${mech}"
                TIMEOUT 10)
        endif()
    endforeach()
endmacro()

# As unit_test_rpc2_instance, but for a transport that names its peer rather
# than addressing it -- AF_UNIX or inproc.  Neither contends for a port, so
# neither needs a network namespace or the shared "evpl_net" lock, and both run
# fully in parallel including where CAP_NET_ADMIN is unavailable.  The port
# argument is accepted and ignored; the name comes from test_address().
macro(unit_test_rpc2_instance_named test_name protocol)
    foreach(mech ${EVPL_MECHANISMS})
        set(_test libevpl/rpc2/${test_name}_${protocol}_${mech})

        add_test(NAME ${_test}
                 COMMAND ${RPC2_TEST_EXE_${test_name}} -r ${protocol} -p 0)

        set_tests_properties(${_test} PROPERTIES
            ENVIRONMENT "TEST_FILE=${RPC2_TEST_SRC_${test_name}};EVPL_TEST_CORE_MECH=${mech};EVPL_TEST_SOCKET_DIR=${EVPL_TEST_SOCKET_DIR}"
            TIMEOUT 10)
    endforeach()
endmacro()

# Build RPC2 test executables
unit_test_rpc2(hello_world hello_world.x hello_world.c)
unit_test_rpc2(builtin_bool builtin_bool.x builtin_bool.c)
unit_test_rpc2(rdma_ddp rdma_ddp.x rdma_ddp.c)
unit_test_rpc2(multifrag hello_world.x multifrag.c)

# Add test instances for STREAM_SOCKET_TCP
unit_test_rpc2_instance(hello_world STREAM_SOCKET_TCP 8100)
unit_test_rpc2_instance(builtin_bool STREAM_SOCKET_TCP 8101)
unit_test_rpc2_instance(rdma_ddp STREAM_SOCKET_TCP 8102)
# multifrag is TCP-only: RDMA bypasses rpc2_segment_callback entirely.
unit_test_rpc2_instance(multifrag STREAM_SOCKET_TCP 8103)

# Add test instances for DATAGRAM_TCP_RDMA
unit_test_rpc2_instance(hello_world DATAGRAM_TCP_RDMA 8200)
unit_test_rpc2_instance(builtin_bool DATAGRAM_TCP_RDMA 8201)
unit_test_rpc2_instance(rdma_ddp DATAGRAM_TCP_RDMA 8202)

# AF_UNIX.  rpc2 is transport-agnostic above the bind, so these mirror the
# STREAM_SOCKET_TCP set exactly; rdma_ddp is included for the same reason it is
# registered for TCP, to cover the path where the transport reports no RDMA and
# the chunks fall back to being carried inline.
unit_test_rpc2_instance_named(hello_world STREAM_SOCKET_UNIX)
unit_test_rpc2_instance_named(builtin_bool STREAM_SOCKET_UNIX)
unit_test_rpc2_instance_named(rdma_ddp STREAM_SOCKET_UNIX)

# In-process transport.  DATAGRAM_INPROC is the point of the exercise: it puts
# rpc2's RDMA/DDP path under test with no RDMA hardware, and without
# TCP_RDMA's request/reply emulation standing in for one-sided operations.
# STREAM_INPROC covers the same programs over rpc2's stream framing instead.
#
# multifrag is absent from both deliberately: it hand-writes malformed RPC
# fragments into its own AF_INET socket, and neither transport gives it a
# descriptor to write to.
unit_test_rpc2_instance_named(hello_world DATAGRAM_INPROC)
unit_test_rpc2_instance_named(builtin_bool DATAGRAM_INPROC)
unit_test_rpc2_instance_named(rdma_ddp DATAGRAM_INPROC)

unit_test_rpc2_instance_named(hello_world STREAM_INPROC)
unit_test_rpc2_instance_named(builtin_bool STREAM_INPROC)
unit_test_rpc2_instance_named(rdma_ddp STREAM_INPROC)

# ---------------------------------------------------------------------------
# Model-based XDR/RPC2 conformance test
#
# The cases this test runs are generated from the Quint models in quint/ by a
# build step, so the traces and the resulting case table are build artifacts
# under the build tree rather than checked-in files that could drift from the
# models they came from.  That makes quint a build dependency, so the whole
# test is registered only when quint and python3 are both present; without
# them the rest of the suite builds and runs as normal.
# ---------------------------------------------------------------------------

find_program(QUINT_EXECUTABLE quint)
find_program(PYTHON3_EXECUTABLE NAMES python3 python)

if(QUINT_EXECUTABLE AND PYTHON3_EXECUTABLE)
    set(QUINT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/quint)
    set(QUINT_WORK_DIR ${CMAKE_CURRENT_BINARY_DIR}/quint)
    set(CONFORMANCE_CASES ${QUINT_WORK_DIR}/conformance_cases.h)

    add_custom_command(
        OUTPUT ${CONFORMANCE_CASES}
        COMMAND ${QUINT_SRC_DIR}/generate_cases.sh
                ${QUINT_EXECUTABLE} ${PYTHON3_EXECUTABLE}
                ${QUINT_SRC_DIR} ${QUINT_WORK_DIR} ${CONFORMANCE_CASES}
        DEPENDS ${QUINT_SRC_DIR}/values.qnt
                ${QUINT_SRC_DIR}/defects.qnt
                ${QUINT_SRC_DIR}/itf_to_cases.py
                ${QUINT_SRC_DIR}/generate_cases.sh
        COMMENT "Generating RPC2 conformance cases from the Quint models"
        VERBATIM)

    add_custom_target(conformance_cases DEPENDS ${CONFORMANCE_CASES})

    unit_test_rpc2(conformance conformance.x conformance.c gss_stub.c)
    target_link_libraries(evpl_rpc2_conformance m)
    target_sources(evpl_rpc2_conformance PRIVATE ${CONFORMANCE_CASES})

    # The ERR_VERS check builds an RPC-over-RDMA transport header by hand, so
    # it needs the rpcrdma1 codec.  Compiled into the test rather than linked
    # from libevpl_rpc2 (which does not export it): a conformance test that
    # encoded with the same code it is checking would pass on any pair of
    # matching bugs.
    # Generated code, so it gets the same exemptions unit_test_rpc2 applies to
    # the XDR it generates itself.
    set_source_files_properties(
        ${CMAKE_CURRENT_BINARY_DIR}/../rpcrdma1_xdr.c PROPERTIES
        COMPILE_OPTIONS "-Wno-unused;-Wno-format-truncation"
    )

    target_sources(evpl_rpc2_conformance PRIVATE
                   ${CMAKE_CURRENT_BINARY_DIR}/../rpcrdma1_xdr.c)
    target_include_directories(evpl_rpc2_conformance PRIVATE
                               ${CMAKE_CURRENT_BINARY_DIR}/..)
    target_include_directories(evpl_rpc2_conformance PRIVATE ${QUINT_WORK_DIR})

    unit_test_rpc2_instance(conformance STREAM_SOCKET_TCP 8104)

    # Also over RDMA-on-TCP: that transport needs no RDMA hardware or verbs but
    # does carry the RPC-over-RDMA framing, so it reaches the chunk-negotiation
    # and rdma_msg paths in rpc2.c that the stream transport never touches.  The
    # raw-socket defect phase self-skips there (record marking is stream-only).
    unit_test_rpc2_instance(conformance DATAGRAM_TCP_RDMA 8205)

    # The same models over the name-addressed transports.  Neither contends for
    # a port, so neither needs a network namespace or the shared lock: the
    # socket name test_address() derives carries the pid and lives under the
    # build tree, which is what makes these safe to run concurrently.
    #
    # AF_UNIX is a stream transport with a descriptor of its own, so it runs
    # the raw-socket defect phase too -- record marking is a property of the
    # framing, not of the address family, so the whole defect matrix applies.
    unit_test_rpc2_instance_named(conformance STREAM_SOCKET_UNIX)

    # Inproc, both ways round: DATAGRAM_INPROC reports RDMA and so exercises
    # the chunk and rdma_msg paths with no hardware and none of TCP_RDMA's
    # emulation in the way, while STREAM_INPROC covers the same models over
    # rpc2's stream framing.  Neither has a descriptor the defect phase could
    # write to, so both self-skip it.
    unit_test_rpc2_instance_named(conformance DATAGRAM_INPROC)
    unit_test_rpc2_instance_named(conformance STREAM_INPROC)

    # Several hundred RPCs per run, plus a raw-socket defect matrix in which a
    # few cases deliberately wait out a reply timeout -- more than the 10s the
    # macro grants by default.
    foreach(proto STREAM_SOCKET_TCP DATAGRAM_TCP_RDMA STREAM_SOCKET_UNIX
            DATAGRAM_INPROC STREAM_INPROC)
        foreach(mech ${EVPL_MECHANISMS})
            set_tests_properties(libevpl/rpc2/conformance_${proto}_${mech}
                                 PROPERTIES TIMEOUT 120)
        endforeach()
    endforeach()

    # The models checking themselves: scenario tests plus a random-simulation
    # pass against their invariants.  Separate from generation so that a broken
    # specification is a failing test rather than a failing build.
    add_test(NAME libevpl/rpc2/quint_model
             COMMAND ${QUINT_SRC_DIR}/check_models.sh
                     ${QUINT_EXECUTABLE} ${QUINT_SRC_DIR})
    set_tests_properties(libevpl/rpc2/quint_model PROPERTIES
                         LABELS "quint" TIMEOUT 120)

    message(STATUS "RPC2 conformance test enabled (quint: ${QUINT_EXECUTABLE})")
else()
    message(STATUS
        "RPC2 conformance test disabled (needs quint and python3 on PATH)")
endif()
