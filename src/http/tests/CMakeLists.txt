# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: LGPL

unit_test(http basic http_basic.c)
unit_test(http chunked http_chunked.c)

target_link_libraries(http_basic evpl_http curl)
target_link_libraries(http_chunked evpl_http curl)