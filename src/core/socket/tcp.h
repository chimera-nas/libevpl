// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

struct evpl;
struct evpl_bind;
struct evpl_event;
struct evpl_protocol;

extern struct evpl_protocol evpl_socket_tcp;

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
