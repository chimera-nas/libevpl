# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

add_library(evpl_xlio SHARED xlio.c tcp.c)

install(TARGETS evpl_xlio DESTINATION lib)

if (NOT DISABLE_TESTS)
    add_subdirectory(tests)
endif()
