// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

struct evpl_framework;
struct evpl_protocol;

extern struct evpl_framework evpl_framework_inproc;

/* Byte stream between two threads, the analogue of STREAM_SOCKET_TCP. */
extern struct evpl_protocol  evpl_inproc_stream;

/* Connected message transport with one-sided RDMA, the analogue of
 * DATAGRAM_TCP_RDMA. */
extern struct evpl_protocol  evpl_inproc_datagram;
