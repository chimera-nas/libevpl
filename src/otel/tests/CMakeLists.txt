# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

# The test decodes the OTLP body the exporter produced, so it needs its own copy
# of the generated protobuf-c bindings.  Regenerate them from the vendored protos
# (PROTOC_C / PROTOBUF_C_LIB are resolved in ext/CMakeLists.txt).
set(OTEL_PROTO_ROOT ${LIBEVPL_SOURCE_DIR}/ext/oteltracing-c)
set(OTEL_PROTOS
    opentelemetry/proto/common/v1/common
    opentelemetry/proto/resource/v1/resource
    opentelemetry/proto/trace/v1/trace
    opentelemetry/proto/collector/trace/v1/trace_service)

get_directory_property(OTEL_TEST_PROTOC
    DIRECTORY ${LIBEVPL_SOURCE_DIR}/ext/oteltracing-c
    DEFINITION OTEL_PROTOC_COMMAND)
if(TARGET protobuf-c::protobuf-c)
    set(OTEL_TEST_PROTOBUF protobuf-c::protobuf-c)
else()
    set(OTEL_TEST_PROTOBUF ${PROTOBUF_C_LIB})
endif()
set(OTEL_TEST_PB_SRCS "")
foreach(proto ${OTEL_PROTOS})
    set(pb_c ${CMAKE_CURRENT_BINARY_DIR}/${proto}.pb-c.c)
    set(pb_h ${CMAKE_CURRENT_BINARY_DIR}/${proto}.pb-c.h)
    add_custom_command(
        OUTPUT ${pb_c} ${pb_h}
        COMMAND ${OTEL_TEST_PROTOC}
                --c_out=${CMAKE_CURRENT_BINARY_DIR}
                --proto_path=${OTEL_PROTO_ROOT}
                ${OTEL_PROTO_ROOT}/${proto}.proto
        DEPENDS ${OTEL_PROTO_ROOT}/${proto}.proto
        COMMENT "protoc-c (otel test) ${proto}.proto")
    list(APPEND OTEL_TEST_PB_SRCS ${pb_c})
endforeach()

set_source_files_properties(${OTEL_TEST_PB_SRCS} PROPERTIES COMPILE_OPTIONS "${EVPL_XDR_WARNING_FLAGS}")

unit_test(otel export otel_export.c ${OTEL_TEST_PB_SRCS})
target_include_directories(otel_export PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(otel_export evpl_otel evpl_http oteltracing-c ${OTEL_TEST_PROTOBUF})
