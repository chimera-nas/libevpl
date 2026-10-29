// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>

struct evpl;
struct evpl_bind;
struct evpl_event;
struct evpl_protocol;

extern struct evpl_protocol evpl_socket_tcp;

/* Map a connect timeout to the TCP_SYNCNT that stays within it.  Linux
 * retransmits the SYN after 1, 2, 4, ... seconds, so TCP_SYNCNT n gives up
 * after 2^(n+1) - 1 seconds: 3, 7, 15, 31, 63, 127 (the default of 6).  The
 * largest n in [1, 30] whose bound fits is returned, so the wait never
 * exceeds the setting and never drops below the kernel's 3 s floor. */
static inline unsigned int
evpl_socket_tcp_syn_retries(unsigned int timeout_ms)
{
    unsigned int n = 1;

    while (n < 30 && ((1ull << (n + 2)) - 1) * 1000ull <= timeout_ms) {
        n++;
    }

    return n;
} /* evpl_socket_tcp_syn_retries */

int evpl_socket_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind);

/* Family-agnostic once a connected fd exists: these operate purely on
 * evpl_socket::fd and the bind's iovec rings, so AF_UNIX reuses them as-is. */

void evpl_socket_tcp_read(
    struct evpl       *evpl,
    struct evpl_event *event);

void evpl_socket_tcp_write(
    struct evpl       *evpl,
    struct evpl_event *event);

void evpl_socket_tcp_error(
    struct evpl       *evpl,
    struct evpl_event *event);

void evpl_accept_tcp(
    struct evpl       *evpl,
    struct evpl_event *event);
