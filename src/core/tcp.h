/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

struct evpl_socket {
    int              fd;
    int              connected;
    int              recv_size;
    struct evpl_bvec recv1;
    struct evpl_bvec recv2;
};

int
evpl_listen_tcp(
    struct evpl        *evpl,
    struct evpl_socket *s,
    struct evpl_event  *event,
    const char         *address,
    int                 port);

int
evpl_connect_tcp(
    struct evpl        *evpl,
    struct evpl_socket *s,
    struct evpl_event  *event,
    const char         *address,
    int                 port);

void
evpl_close_tcp(
    struct evpl        *evpl,
    struct evpl_socket *s);
