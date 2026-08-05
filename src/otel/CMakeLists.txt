# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

add_library(evpl_otel SHARED evpl_otel.c)

# oteltracing-c propagates its include dir (PUBLIC); evpl_http brings the client.
target_link_libraries(evpl_otel evpl evpl_http oteltracing-c)

install(TARGETS evpl_otel DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()
