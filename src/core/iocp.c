// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/evpl.h"
#include "core/iocp.h"
#include "core/macros.h"

static int
evpl_iocp_init(
    struct evpl_core *core,
    int               max_events)
{
    (void) max_events;
    core->u.iocp.port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    return core->u.iocp.port ? 0 : (int) GetLastError();
} /* evpl_iocp_init */

static int
evpl_iocp_wait(
    struct evpl_core *core,
    int               max_msecs)
{
    struct evpl_core_iocp *iocp    = &core->u.iocp;
    DWORD                  timeout = max_msecs < 0 ? INFINITE : (DWORD) max_msecs;

    evpl_core_assert(!iocp->count);
    while (iocp->count < 64) {
        OVERLAPPED *overlapped = NULL;
        DWORD       bytes      = 0;
        ULONG_PTR   key        = 0;
        BOOL        ok         = GetQueuedCompletionStatus(iocp->port, &bytes, &key, &overlapped, timeout);
        DWORD       error      = ok ? 0 : GetLastError();
        if (!overlapped) {
            evpl_core_abort_if(error != WAIT_TIMEOUT, "IOCP wait failed: %lu", error);
            break;
        }
        iocp->results[iocp->count].request = (struct evpl_iocp_request *) overlapped;
        iocp->results[iocp->count].bytes   = bytes;
        iocp->results[iocp->count].error   = error;
        iocp->count++;
        timeout = 0;
    }
    return (int) iocp->count;
} /* evpl_iocp_wait */

static void
evpl_iocp_dispatch(struct evpl_core *core)
{
    struct evpl_core_iocp *iocp  = &core->u.iocp;
    unsigned int           count = iocp->count;

    iocp->count = 0;
    for (unsigned int i = 0; i < count; i++) {
        struct evpl_iocp_result result = iocp->results[i];
        result.request->callback(evpl_from_core(core), result.request, result.bytes, result.error);
    }
} /* evpl_iocp_dispatch */

static void
evpl_iocp_destroy(struct evpl_core *core)
{
    /* Network operations are already retired and doorbells revoked. Posted
     * doorbell packets still hold references which must be released. */
    evpl_iocp_dispatch(core);
    while (evpl_iocp_wait(core, 0)) {
        evpl_iocp_dispatch(core);
    }
    CloseHandle(core->u.iocp.port);
} /* evpl_iocp_destroy */

static void
evpl_iocp_fd_unsupported(
    struct evpl_core  *core,
    struct evpl_event *event)
{
    (void) core; (void) event;
    evpl_core_abort("descriptor readiness is unavailable with IOCP");
} /* evpl_iocp_fd_unsupported */

int
evpl_iocp_post(
    struct evpl              *evpl,
    struct evpl_iocp_request *request)
{
    return PostQueuedCompletionStatus(evpl->core.u.iocp.port, 0, 1, &request->overlapped) ? 0 : (int) GetLastError();
} /* evpl_iocp_post */

int
evpl_iocp_associate(
    struct evpl *evpl,
    HANDLE       handle)
{
    return CreateIoCompletionPort(handle, evpl->core.u.iocp.port, 0, 0) ? 0 : (int) GetLastError();
} /* evpl_iocp_associate */

const struct evpl_core_ops evpl_core_iocp_ops = {
    .name = "iocp",                   .init     = evpl_iocp_init,           .destroy = evpl_iocp_destroy,
    .add  = evpl_iocp_fd_unsupported, .remove   = evpl_iocp_fd_unsupported,
    .wait = evpl_iocp_wait,           .dispatch = evpl_iocp_dispatch,
};
