# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

set(HTTP_SRC http.c)

if (HAVE_NGHTTP2)
    set(HTTP_SRC ${HTTP_SRC} http2.c)
endif()

add_library(evpl_http SHARED ${HTTP_SRC})

target_link_libraries(evpl_http evpl)

if (HAVE_NGHTTP2)
    target_link_libraries(evpl_http ${NGHTTP2_LIB})
endif()

install(TARGETS evpl_http DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()