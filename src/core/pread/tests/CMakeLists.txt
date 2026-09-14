# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

unit_test(pread basic basic.c)
unit_test(pread threads threads.c)

if(WIN32)
    unit_test(pread windows_file windows_file.c)
endif()
