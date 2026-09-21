// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include "core/test_log.h"
#include "evpl/evpl.h"

struct test_block_result {
    struct evpl_block_device *device;
    int                       status;
    int                       done;
};

static void
test_block_open_done(
    struct evpl              *evpl,
    struct evpl_block_device *device,
    int                       status,
    void                     *private_data)
{
    struct test_block_result *result = private_data;

    result->device = device;
    result->status = status;
    result->done   = 1;
} // test_block_open_done

/* Only for tests pumping an ordinary event loop on their own thread. */
static struct evpl_block_device *
test_block_open(
    struct evpl                *evpl,
    enum evpl_block_protocol_id protocol,
    const char                 *uri)
{
    struct test_block_result result = { 0 };

    evpl_block_open_device(evpl, protocol, uri, test_block_open_done, &result);
    evpl_test_abort_if(result.done, "open callback ran inline");
    while (!result.done) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if((result.device != NULL) != (result.status == 0),
                       "inconsistent block open result");
    return result.device;
} // test_block_open

static void
test_block_close_done(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct test_block_result *result = private_data;

    result->status = status;
    result->done   = 1;
} // test_block_close_done

static void
test_block_close(
    struct evpl              *evpl,
    struct evpl_block_device *device)
{
    struct test_block_result result = { 0 };

    evpl_block_close_device(evpl, device, test_block_close_done, &result);
    evpl_test_abort_if(result.done, "close callback ran inline");
    while (!result.done) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(result.status, "block close failed: %d", result.status);
} // test_block_close
