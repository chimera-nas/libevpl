// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include "core/os.h"
#include <fcntl.h>
#ifdef _WIN32
static inline int
evpl_test_open(
    const char *path,
    int         flags,
    int         mode)
{
    return _open(path, flags | _O_BINARY, mode);
} // evpl_test_open
#define evpl_test_truncate _chsize_s
#define evpl_test_close    _close
#define evpl_test_unlink   _unlink
#else // ifdef _WIN32
#define evpl_test_open     open
#define evpl_test_truncate ftruncate
#define evpl_test_close    close
#define evpl_test_unlink   unlink
#endif // ifdef _WIN32
