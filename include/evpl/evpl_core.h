// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <time.h>

#ifndef EVPL_INCLUDED
#error "Do not include evpl_core.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

enum evpl_framework_id {
    EVPL_FRAMEWORK_RDMACM   = 0,
    EVPL_FRAMEWORK_XLIO     = 1,
    EVPL_FRAMEWORK_IO_URING = 2,
    EVPL_FRAMEWORK_VFIO     = 3,
    EVPL_FRAMEWORK_TLS      = 4,
    EVPL_FRAMEWORK_TCP_RDMA = 5,
    EVPL_FRAMEWORK_LIBAIO   = 6,
    EVPL_NUM_FRAMEWORK      = 7
};

enum evpl_protocol_id {
    EVPL_DATAGRAM_SOCKET_UDP = 0,
    EVPL_DATAGRAM_RDMACM_RC  = 1,
    EVPL_DATAGRAM_RDMACM_UD  = 2,
    EVPL_STREAM_SOCKET_TCP   = 3,
    EVPL_STREAM_XLIO_TCP     = 4,
    EVPL_STREAM_IO_URING_TCP = 5,
    EVPL_STREAM_RDMACM_RC    = 6,
    EVPL_STREAM_SOCKET_TLS   = 7,
    EVPL_DATAGRAM_TCP_RDMA   = 8,
    EVPL_NUM_PROTO           = 9
};

enum evpl_block_protocol_id {
    EVPL_BLOCK_PROTOCOL_IO_URING = 0,
    EVPL_BLOCK_PROTOCOL_VFIO     = 1,
    EVPL_BLOCK_PROTOCOL_LIBAIO   = 2,
    EVPL_NUM_BLOCK_PROTOCOL      = 3
};

struct evpl;
struct evpl_global_config;
struct evpl_thread_config;

void evpl_init(
    struct evpl_global_config *global_config);

struct evpl * evpl_create(
    struct evpl_thread_config *config);

void
evpl_get_hf_monotonic_time(
    struct evpl     *evpl,
    struct timespec *ts);

void evpl_destroy(
    struct evpl *evpl);

void evpl_continue(
    struct evpl *evpl);

void evpl_run(
    struct evpl *evpl);

void evpl_stop(
    struct evpl *evpl);

int evpl_protocol_lookup(
    enum evpl_protocol_id *id,
    const char            *name);

int evpl_protocol_is_stream(
    enum evpl_protocol_id protocol);

struct evpl_config *
evpl_config(
    struct evpl *evpl);
