// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include "core/os.h"
#include <limits.h>
#include <fcntl.h>
static inline int test_socket_error(
    int result);

/* Raw peers used by protocol tests must preserve the native handle width. */
#ifdef _WIN32
typedef SOCKET test_socket_t;
#define TEST_INVALID_SOCKET INVALID_SOCKET
#define SHUT_WR             SD_SEND
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
    return test_socket_error(recv(socket, (char *) buffer, length > INT_MAX ? INT_MAX : (int) length, flags));
} // test_socket_recv
static inline ssize_t
test_socket_send(
    test_socket_t socket,
    const void   *buffer,
    size_t        length,
    int           flags)
{
    return test_socket_error(send(socket, (const char *) buffer, length > INT_MAX ? INT_MAX : (int) length, flags));
} // test_socket_send

static inline int
test_socket_error(int result)
{
#ifdef _WIN32
    if (result == SOCKET_ERROR) {
        switch (WSAGetLastError()) {
            case WSAEWOULDBLOCK: errno = EAGAIN; break;
            case WSAEINTR: errno       = EINTR; break;
            case WSAECONNRESET: errno  = ECONNRESET; break;
            case WSAENOTCONN: errno    = ENOTCONN; break;
            default: errno             = EIO; break;
        } // switch
    }
#endif // ifdef _WIN32
    return result;
} // test_socket_error

static inline int
test_socket_nonblocking(test_socket_t socket)
{
#ifdef _WIN32
    u_long one = 1;
    return test_socket_error(ioctlsocket(socket, FIONBIO, &one));
#else // ifdef _WIN32
    int    flags = fcntl(socket, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(socket, F_SETFL, flags | O_NONBLOCK);
#endif // ifdef _WIN32
} // test_socket_nonblocking
static inline int
test_socket_connect(
    test_socket_t          socket,
    const struct sockaddr *address,
    socklen_t              length)
{
    int rc = test_socket_error(connect(socket, address, length));

#ifdef _WIN32
    if (rc < 0 && errno == EAGAIN) {
        errno = EINPROGRESS;
    }
#endif // ifdef _WIN32
    return rc;
} // test_socket_connect
static inline test_socket_t
test_socket_accept(
    test_socket_t    socket,
    struct sockaddr *address,
    socklen_t       *length)
{
    test_socket_t accepted = accept(socket, address, length);

    if (accepted == TEST_INVALID_SOCKET) {
        test_socket_error(-1);
    }
    return accepted;
} // test_socket_accept
#ifdef _WIN32
#include <afunix.h>
static inline int
test_socket_poll(
    struct pollfd *fds,
    unsigned int   count,
    int            timeout)
{
    return test_socket_error(WSAPoll(fds, count, timeout));
} // test_socket_poll
#else // ifdef _WIN32
#include <poll.h>
#define test_socket_poll poll
#endif // ifdef _WIN32
