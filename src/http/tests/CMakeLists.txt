# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

find_package(CURL REQUIRED)

unit_test(http basic http_basic.c)
unit_test(http chunked http_chunked.c)

target_link_libraries(http_basic evpl_http CURL::libcurl)
target_link_libraries(http_chunked evpl_http CURL::libcurl)

# evpl HTTP/1.1 client <-> evpl server (no nghttp2 required)
unit_test(http client http1_client.c)
target_link_libraries(http_client evpl_http)

# Configurable header block limit (http_max_header_size): outbound refusal
# via evpl_http_request_add_header, server-side 400 on an oversized inbound
# request block, client-side disconnect on an oversized response block.
unit_test(http max_headers http_max_headers.c)
target_link_libraries(http_max_headers evpl_http)

# Trailer fields in both directions over HTTP/1.1 chunked framing (the h2
# variant of the same file is registered below with the other nghttp2 tests)
unit_test(http trailers http_trailers.c)
target_link_libraries(http_trailers evpl_http)

# ---------------------------------------------------------------------------
# Model-based HTTP/1.x conformance test
#
# The cases this test runs are generated from the Quint model in quint/ by a
# build step, so the traces and the resulting case table are build artifacts
# under the build tree rather than checked-in files that could drift from the
# model they came from.  That makes quint a build dependency, so the whole test
# is registered only when quint and python3 are both present; without them the
# rest of the suite builds and runs as normal.
#
# Pass -DQUINT_EXECUTABLE=OFF to force it off.
# ---------------------------------------------------------------------------

find_program(QUINT_EXECUTABLE quint)
find_program(PYTHON3_EXECUTABLE NAMES python3 python)

if(EVPL_CONFORMANCE_CASES_DIR OR (NOT WIN32 AND QUINT_EXECUTABLE AND PYTHON3_EXECUTABLE))
    set(HTTP_QUINT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/quint)
    set(HTTP_QUINT_WORK_DIR ${CMAKE_CURRENT_BINARY_DIR}/quint)
    if(EVPL_CONFORMANCE_CASES_DIR)
        set(HTTP_QUINT_WORK_DIR ${EVPL_CONFORMANCE_CASES_DIR})
    endif()
    set(HTTP_CASES ${HTTP_QUINT_WORK_DIR}/http_cases.h)

    if(NOT EVPL_CONFORMANCE_CASES_DIR)
    add_custom_command(
        OUTPUT ${HTTP_CASES}
        COMMAND ${HTTP_QUINT_SRC_DIR}/generate_cases.sh
                ${QUINT_EXECUTABLE} ${PYTHON3_EXECUTABLE}
                ${HTTP_QUINT_SRC_DIR} ${HTTP_QUINT_WORK_DIR} ${HTTP_CASES}
        DEPENDS ${HTTP_QUINT_SRC_DIR}/http1x.qnt
                ${HTTP_QUINT_SRC_DIR}/itf_to_cases.py
                ${HTTP_QUINT_SRC_DIR}/generate_cases.sh
        COMMENT "Generating HTTP/1.x conformance cases from the Quint model"
        VERBATIM)
    endif()

    add_custom_target(http_conformance_cases DEPENDS ${HTTP_CASES})

    unit_test(http conformance conformance.c)
    target_sources(http_conformance PRIVATE ${HTTP_CASES})
    target_include_directories(http_conformance PRIVATE ${HTTP_QUINT_WORK_DIR})
    target_link_libraries(http_conformance evpl_http)

    # Well over a thousand exchanges, a handful of which deliberately wait out
    # a response deadline to prove no answer arrives -- far more than the 60s
    # the unit_test macro grants by default.
    set_tests_properties(libevpl/http/conformance PROPERTIES TIMEOUT 300)

    # -----------------------------------------------------------------------
    # The same idea inverted: a hostile server driving libevpl's *client*.
    #
    # conformance.c can only reach the client's outbound path, because the
    # responses it sees come from a real libevpl server and are therefore
    # always well formed.  conformance_client.c is a raw socket pretending to
    # be a server, so the response bytes are chosen by the test.  It shares the
    # generated case table, whose client half comes from the http1x_client
    # module of the same model.
    # -----------------------------------------------------------------------

    unit_test(http conformance_client conformance_client.c)
    target_sources(http_conformance_client PRIVATE ${HTTP_CASES})
    target_include_directories(http_conformance_client
                               PRIVATE ${HTTP_QUINT_WORK_DIR})
    target_link_libraries(http_conformance_client evpl_http)

    # A hundred exchanges, several of which deliberately wait out a response
    # deadline to prove no callback arrives.
    set_tests_properties(libevpl/http/conformance_client PROPERTIES TIMEOUT 180)

    if(NOT EVPL_CONFORMANCE_CASES_DIR)
    # The model checking itself: scenario tests plus a random-simulation pass
    # against its invariants.  Separate from generation so that a broken
    # specification is a failing test rather than a failing build.
    add_test(NAME libevpl/http/quint_model
             COMMAND ${HTTP_QUINT_SRC_DIR}/check_models.sh
                     ${QUINT_EXECUTABLE} ${HTTP_QUINT_SRC_DIR})
    set_tests_properties(libevpl/http/quint_model PROPERTIES
                         LABELS "quint" TIMEOUT 360)

    endif()
    message(STATUS "HTTP conformance test enabled (quint: ${QUINT_EXECUTABLE})")
else()
    message(STATUS
        "HTTP conformance test disabled (supply EVPL_CONFORMANCE_CASES_DIR, or quint and python3 on a Unix host)")
endif()

if (HAVE_NGHTTP2)
    # evpl HTTP/2 client <-> evpl server (h2c prior-knowledge, and h2 over TLS)
    unit_test(http h2_client http2_client.c)
    target_link_libraries(http_h2_client evpl_http)

    unit_test(http h2_client_tls http2_client_tls.c)
    target_link_libraries(http_h2_client_tls evpl_http)

    # the http_trailers exchanges over h2c: trailing HEADERS frames
    unit_test(http h2_trailers http2_trailers.c)
    target_link_libraries(http_h2_trailers evpl_http)

    # libevpl HTTP/2 server driven by libcurl (reference client)
    unit_test(http h2_basic http2_basic.c)
    target_link_libraries(http_h2_basic evpl_http CURL::libcurl)

    unit_test(http h2_tls http2_tls.c)
    target_link_libraries(http_h2_tls evpl_http CURL::libcurl)
endif()
