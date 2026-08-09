// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_endpoint.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_endpoint;
struct evpl_address;

/*
 * Create an endpoint naming a peer by IP address or DNS name plus a port.
 * The address is resolved lazily and re-resolved periodically, see
 * evpl_global_config_set_resolve_timeout_ms().
 */
struct evpl_endpoint *
evpl_endpoint_create(
    const char *address,
    int         port);

/*
 * Create an endpoint naming a local (AF_UNIX) socket.
 *
 * path must be one of:
 *
 *   "/absolute/path"  a filesystem socket.  At most 107 bytes; longer paths
 *                     are rejected rather than truncated, since a shortened
 *                     path is a different socket.  Relative paths are
 *                     rejected.
 *
 *   "@name"           a Linux abstract-namespace socket.  Not backed by a
 *                     filesystem entry, so it needs no cleanup and cannot be
 *                     left stale by a crash.  Scoped to the caller's network
 *                     namespace.  Linux only.
 *
 * Endpoints created here may only be used with protocols for which
 * evpl_protocol_is_local() is true.
 *
 * Returns NULL if the path is malformed or too long.
 */
struct evpl_endpoint *
evpl_endpoint_create_local(
    const char *path);

/*
 * Create an endpoint naming a peer thread inside this process.
 *
 * name is a bare name -- "backend", not "inproc://backend"; at most 107 bytes.
 * It is resolved through a registry private to this process, so it is subject
 * to no kernel namespace at all: two processes may each own the same name, and
 * there is nothing for a crash to leave behind.
 *
 * The listening and connecting ends must be different evpl contexts, or the
 * same one -- both work.
 *
 * Endpoints created here may only be used with protocols for which
 * evpl_protocol_is_inproc() is true.
 *
 * Returns NULL if the name is empty or too long.
 */
struct evpl_endpoint *
evpl_endpoint_create_inproc(
    const char *name);

void evpl_endpoint_close(
    struct evpl_endpoint *endpoint);

/* 1 iff this endpoint names a local (AF_UNIX) socket. */
int evpl_endpoint_is_local(
    const struct evpl_endpoint *ep);

/* 1 iff this endpoint names a peer thread inside this process. */
int evpl_endpoint_is_inproc(
    const struct evpl_endpoint *ep);

const char *
evpl_endpoint_address(
    const struct evpl_endpoint *ep);

int evpl_endpoint_port(
    const struct evpl_endpoint *ep);