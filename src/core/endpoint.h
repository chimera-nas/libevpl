// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <sys/time.h>
#include <pthread.h>

#include "core/address.h"


/* enum evpl_endpoint_kind is defined in core/protocol.h, which this header
 * pulls in via address.h -> evpl_shared.h: struct evpl_protocol needs it too,
 * and protocol.h is the one of the two that can be included on its own. */

/*
 * address holds the hostname or IP literal for an inet endpoint, the path or
 * "@name" exactly as supplied for a local one, and the full "inproc://name"
 * for an in-process one; the sockaddr is derived from it at resolve time.
 * 256 bytes is larger than sun_path (108) and than an inproc name, so a valid
 * address can never be truncated here -- an over-long one is rejected at
 * create time rather than silently shortened.  port is zero for anything but
 * an inet endpoint.
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

/* Human-readable name for a kind, for diagnostics. */
static inline const char *
evpl_endpoint_kind_name(enum evpl_endpoint_kind kind)
{
    switch (kind) {
        case EVPL_ENDPOINT_LOCAL:
            return "local-path";
        case EVPL_ENDPOINT_INPROC:
            return "in-process";
        default:
            return "network";
    } /* switch */
} /* evpl_endpoint_kind_name */

struct evpl_address *
evpl_endpoint_resolve(
    struct evpl_endpoint *endpoint);

/* 0 if endpoint may be used with protocol, -1 otherwise.  How a peer is named
 * is a property of both, and they have to agree: a socket path means nothing
 * to TCP and a host/port means nothing to AF_UNIX. */
static inline int
evpl_endpoint_check_protocol(
    const struct evpl_endpoint *endpoint,
    const struct evpl_protocol *protocol)
{
    return endpoint->kind == protocol->endpoint_kind ? 0 : -1;
} /* evpl_endpoint_check_protocol */