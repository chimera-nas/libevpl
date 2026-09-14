// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include "core/os.h"
#include <limits.h>

/* Raw peers used by protocol tests must preserve the native handle width. */
#ifdef _WIN32
typedef SOCKET test_socket_t;
#define TEST_INVALID_SOCKET INVALID_SOCKET
#define test_socket_close   closesocket
#else // ifdef _WIN32
typedef int test_socket_t;
#define TEST_INVALID_SOCKET (-1)
#define test_socket_close   close
#endif // ifdef _WIN32

static inline int
test_socket_option(
    test_socket_t socket,
    int           level,
    int           option,
    const void   *value,
    socklen_t     length)
{
    return setsockopt(socket, level, option, (const char *) value, length);
} // test_socket_option
static inline ssize_t
test_socket_recv(
    test_socket_t socket,
    void         *buffer,
    size_t        length,
    int           flags)
{
    return recv(socket, (char *) buffer, length > INT_MAX ? INT_MAX : (int) length, flags);
} // test_socket_recv
static inline ssize_t
test_socket_send(
    test_socket_t socket,
    const void   *buffer,
    size_t        length,
    int           flags)
{
    return send(socket, (const char *) buffer, length > INT_MAX ? INT_MAX : (int) length, flags);
} // test_socket_send
