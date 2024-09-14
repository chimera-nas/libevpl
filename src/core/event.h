/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

#include "core/evpl.h"

struct evpl_listener;
struct evpl_conn;
struct evpl_event;

typedef void (*evpl_event_read_callback_t)(
    struct evpl       *evpl,
    struct evpl_event *event);
typedef void (*evpl_event_write_callback_t)(
    struct evpl       *evpl,
    struct evpl_event *event);
typedef void (*evpl_event_error_callback_t)(
    struct evpl       *evpl,
    struct evpl_event *event);

#define EVPL_READABLE       0x01
#define EVPL_WRITABLE       0x02
#define EVPL_READ_INTEREST  0x04
#define EVPL_WRITE_INTEREST 0x08
#define EVPL_ACTIVE         0x10
#define EVPL_FINISH         0x20
#define EVPL_CLOSE          0x40

#define EVPL_READ_READY     (EVPL_READABLE | EVPL_READ_INTEREST)
#define EVPL_WRITE_READY    (EVPL_WRITABLE | EVPL_WRITE_INTEREST)

struct evpl_event {
    int                         fd;
    unsigned int                flags;
    evpl_event_read_callback_t  read_callback;
    evpl_event_write_callback_t write_callback;
    evpl_event_error_callback_t error_callback;
};

void evpl_event_read_interest(
    struct evpl       *evpl,
    struct evpl_event *event);
void evpl_event_read_disinterest(
    struct evpl_event *event);
void evpl_event_write_interest(
    struct evpl       *evpl,
    struct evpl_event *event);
void evpl_event_write_disinterest(
    struct evpl_event *event);


void evpl_event_mark_readable(
    struct evpl       *evpl,
    struct evpl_event *event);
void evpl_event_mark_unreadable(
    struct evpl_event *event);
void evpl_event_mark_writable(
    struct evpl       *evpl,
    struct evpl_event *event);
void evpl_event_mark_unwritable(
    struct evpl_event *event);
void evpl_event_mark_finish(
    struct evpl       *evpl,
    struct evpl_event *event);
void evpl_event_mark_close(
    struct evpl       *evpl,
    struct evpl_event *event);


void evpl_accept(
    struct evpl          *evpl,
    struct evpl_listener *listener,
    struct evpl_conn     *conn);
/*
 * The evpl_core is always the first member of evpl,
 * so we can cast between them
 */

#define evpl_from_core(core)       ((struct evpl *) core)
/*
 * The backend structure is always immediately following the evpl_event
 * in an evpl_conn, and evpl_event is always first, so we can do
 * some pointer casting to get backends from the opaque structure
 */

#define evpl_event_backend(conn) \
    (void *) (((struct evpl_event *) conn) + 1)

#define evpl_conn_backend(conn)    evpl_event_backend(conn)

#define evpl_event_conn(event)     ((struct evpl_conn *) event)
#define evpl_event_listener(event) ((struct evpl_listener *) event)
