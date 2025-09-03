# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

add_subdirectory(prometheus-c)
add_subdirectory(xdrzcc)

set(XDRZCC ${XDRZCC} PARENT_SCOPE)
message(STATUS "XDRZCC: ${XDRZCC}")
