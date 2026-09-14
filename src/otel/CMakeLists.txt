# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

add_library(evpl_otel SHARED evpl_otel.c)
target_compile_definitions(evpl_otel PRIVATE EVPL_OTEL_BUILD)

# oteltracing-c propagates its include dir (PUBLIC); evpl_http brings the client.
target_link_libraries(evpl_otel evpl evpl_http oteltracing-c)

install(TARGETS evpl_otel RUNTIME DESTINATION bin LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()

if(WIN32)
    add_custom_command(TARGET evpl_otel POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:oteltracing-c> $<TARGET_FILE_DIR:evpl_otel>)
endif()
