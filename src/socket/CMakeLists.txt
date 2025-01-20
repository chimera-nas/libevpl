# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

add_library(evpl_socket SHARED tcp.c udp.c)

install(TARGETS evpl_socket DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()
