// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <sys/time.h>
#include <pthread.h>

#include "core/address.h"


enum evpl_endpoint_kind {
    /* Hostname or IP literal plus port, resolved via getaddrinfo.  Zero so
     * that a zalloc'd endpoint is an inet endpoint by default. */
    EVPL_ENDPOINT_INET  = 0,
    /* AF_UNIX socket, named by a filesystem path, or by an abstract name if
     * the stored address begins with '@'. */
    EVPL_ENDPOINT_LOCAL = 1
};

/*
 * address holds the hostname or IP literal for an inet endpoint, and the path
 * or "@name" exactly as supplied for a local one; the sockaddr_un is derived
 * from it at resolve time.  256 bytes is larger than sun_path (108), so a
 * valid local address can never be truncated here -- an over-long path is
 * rejected at create time rather than silently shortened.  port is zero for a
 * local endpoint.
 */
struct evpl_endpoint {
    char                  address[256];
    int                   port;
    enum evpl_endpoint_kind kind;
    struct timespec       last_resolved;
    struct evpl_address  *resolved_addr;
    pthread_rwlock_t      lock;
    struct evpl_endpoint *prev;
    struct evpl_endpoint *next;
};

struct evpl_address *
evpl_endpoint_resolve(
    struct evpl_endpoint *endpoint);

/* 0 if endpoint may be used with protocol, -1 otherwise.  A local endpoint
 * requires a local protocol and vice versa. */
static inline int
evpl_endpoint_check_protocol(
    const struct evpl_endpoint *endpoint,
    const struct evpl_protocol *protocol)
{
    return ((endpoint->kind == EVPL_ENDPOINT_LOCAL) == (protocol->local != 0))
           ? 0 : -1;
} /* evpl_endpoint_check_protocol */