# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

add_subdirectory(prometheus-c)
add_subdirectory(xdrzcc)

set(XDRZCC ${XDRZCC} PARENT_SCOPE)
message(STATUS "XDRZCC: ${XDRZCC}")

# oteltracing-c is an optional OTLP/gRPC span tracer.  It needs protobuf-c (and
# protoc-c to generate the OTLP bindings); build it only when those are present
# so libevpl still builds on toolchains without them.
find_program(PROTOC_C protoc-c)
find_library(PROTOBUF_C_LIB protobuf-c)
if (PROTOC_C AND PROTOBUF_C_LIB)
    message(STATUS "oteltracing-c enabled (protoc-c ${PROTOC_C})")
    add_subdirectory(oteltracing-c)
    set(HAVE_OTELTRACING 1 PARENT_SCOPE)
else()
    message(STATUS "protobuf-c not found; oteltracing-c disabled")
endif()
