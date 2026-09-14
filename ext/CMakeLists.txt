# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

add_subdirectory(prometheus-c)
if(EVPL_BOOTSTRAP_NATIVE)
    return()
endif()
add_subdirectory(xdrzcc)

set(XDRZCC ${XDRZCC} PARENT_SCOPE)
message(STATUS "XDRZCC: ${XDRZCC}")

# oteltracing-c is an optional OTLP/gRPC span tracer.  It needs protobuf-c (and
# protoc-c to generate the OTLP bindings); build it only when those are present
# so libevpl still builds on toolchains without them.
find_program(PROTOC_C protoc-c)
find_library(PROTOBUF_C_LIB protobuf-c)
if(WIN32)
    find_package(protobuf-c CONFIG QUIET)
    if(TARGET protobuf-c::protobuf-c)
        set(EVPL_NATIVE_PROTOBUF_C ON)
    endif()
endif()
if ((PROTOC_C AND PROTOBUF_C_LIB) OR EVPL_NATIVE_PROTOBUF_C)
    message(STATUS "oteltracing-c enabled (protoc-c ${PROTOC_C})")
    add_subdirectory(oteltracing-c)
    set(HAVE_OTELTRACING 1 PARENT_SCOPE)
else()
    message(STATUS "protobuf-c not found; oteltracing-c disabled")
endif()
