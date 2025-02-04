// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_core.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

enum evpl_framework_id {
    EVPL_FRAMEWORK_RDMACM   = 0,
    EVPL_FRAMEWORK_XLIO     = 1,
    EVPL_FRAMEWORK_IO_URING = 2,
    EVPL_FRAMEWORK_VFIO     = 3,
    EVPL_NUM_FRAMEWORK      = 4
};

enum evpl_protocol_id {
    EVPL_DATAGRAM_SOCKET_UDP = 0,
    EVPL_DATAGRAM_RDMACM_RC  = 1,
    EVPL_DATAGRAM_RDMACM_UD  = 2,
    EVPL_STREAM_SOCKET_TCP   = 3,
    EVPL_STREAM_XLIO_TCP     = 4,
    EVPL_STREAM_RDMACM_RC    = 5,
    EVPL_NUM_PROTO           = 6
};

enum evpl_block_protocol_id {
    EVPL_BLOCK_PROTOCOL_IO_URING = 0,
    EVPL_BLOCK_PROTOCOL_VFIO     = 1,
    EVPL_NUM_BLOCK_PROTOCOL      = 2
};

struct evpl;
struct evpl_global_config;
struct evpl_thread_config;

void evpl_init(
    struct evpl_global_config *global_config);

struct evpl * evpl_create(
    struct evpl_thread_config *config);

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
