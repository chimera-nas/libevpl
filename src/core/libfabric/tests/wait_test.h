// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* Additional real-provider scenarios for shared_receive.c.  Force each wait
 * negotiation path and augment real CQ pollfd snapshots with shared, mutable
 * descriptors.  Only the calling thread's CQs are instrumented; the listener
 * still uses the forced mode but runs without these observations. */
#include <poll.h>
#include <sys/socket.h>
#include <rdma/fi_eq.h>
#include "core/evpl.h"
#include "core/event.h"

#define WAIT_TEST_FDS 80

struct wait_test_cq {
    struct fid          *fid;
    struct fi_ops        ops;
    struct fi_ops       *real;
    struct wait_test_cq *next;
};

static                             _Thread_local struct wait_test_cq *wait_test_cqs;
static _Thread_local int           wait_test_observe;
static int                         wait_test_enabled, wait_test_mode;
static struct fi_ops_domain        wait_test_domain_ops;
static struct fi_ops_domain       *wait_test_real_domain;
static struct fi_ops_fabric        wait_test_fabric_ops;
static struct fi_ops_fabric       *wait_test_real_fabric;
static int                         wait_test_pairs[WAIT_TEST_FDS][2];
static struct evpl_event          *wait_test_events[WAIT_TEST_FDS];
static unsigned int                wait_test_count = WAIT_TEST_FDS, wait_test_generation;
static short                       wait_test_interest = POLLIN;
static unsigned int                wait_test_veto, wait_test_injected, wait_test_waits, wait_test_busy;
static unsigned int                wait_test_ready;
static const struct evpl_core_ops *wait_test_real_core;
static struct evpl_core_ops        wait_test_core;

static struct wait_test_cq *
wait_test_find(struct fid *fid)
{
    struct wait_test_cq *cq;

    for (cq = wait_test_cqs; cq; cq = cq->next) {
        if (cq->fid == fid) {
            return cq;
        }
    }
    evpl_test_abort("unknown instrumented CQ");
    return NULL;
} // wait_test_find

static int
wait_test_close(struct fid *fid)
{
    struct wait_test_cq *cq = wait_test_find(fid), **link = &wait_test_cqs;
    int                  rc;

    fid->ops = cq->real;
    rc       = cq->real->close(fid);
    evpl_test_abort_if(rc, "instrumented CQ close failed");
    while (*link != cq) {
        link = &(*link)->next;
    }
    *link = cq->next;
    free(cq);
    return 0;
} // wait_test_close

static int
wait_test_control(
    struct fid *fid,
    int         command,
    void       *arg)
{
    struct wait_test_cq   *cq = wait_test_find(fid);
    struct fi_wait_pollfd *out = arg, real = { 0 };
    struct pollfd         *fds;
    unsigned int           capacity, i;
    int                    rc;

    if (command != FI_GETWAIT || wait_test_mode != FI_WAIT_POLLFD) {
        return cq->real->control(fid, command, arg);
    }
    rc = cq->real->control(fid, command, &real);
    evpl_test_abort_if(rc && rc != -FI_ETOOSMALL, "pollfd size query failed");
    capacity          = out->nfds;
    out->nfds         = real.nfds + wait_test_count;
    out->change_index = real.change_index * 32 + wait_test_generation;
    if (capacity < out->nfds) {
        return -FI_ETOOSMALL;
    }
    fds     = calloc(real.nfds ? real.nfds : 1, sizeof(*fds));
    real.fd = fds;
    rc      = cq->real->control(fid, command, &real);
    evpl_test_abort_if(rc, "pollfd snapshot changed inside test query");
    memcpy(out->fd, fds, real.nfds * sizeof(*fds));
    free(fds);
    for (i = 0; i < wait_test_count; i++) {
        out->fd[real.nfds + i] = (struct pollfd) {
            .fd = wait_test_pairs[i][0], .events = wait_test_interest
        };
    }
    return 0;
} // wait_test_control

static int
wait_test_cq_open(
    struct fid_domain *domain,
    struct fi_cq_attr *attr,
    struct fid_cq    **result,
    void              *context)
{
    struct wait_test_cq *cq;
    int                  rc;

    if (attr->wait_obj != wait_test_mode) {
        return -FI_ENOSYS;
    }
    rc = wait_test_real_domain->cq_open(domain, attr, result, context);
    if (rc || !wait_test_observe) {
        return rc;
    }
    cq              = calloc(1, sizeof(*cq));
    cq->fid         = &(*result)->fid;
    cq->real        = cq->fid->ops;
    cq->ops         = *cq->real;
    cq->ops.control = wait_test_control;
    cq->ops.close   = wait_test_close;
    cq->fid->ops    = &cq->ops;
    cq->next        = wait_test_cqs;
    wait_test_cqs   = cq;
    return 0;
} // wait_test_cq_open

static int
wait_test_eq_open(
    struct fid_fabric *fabric,
    struct fi_eq_attr *attr,
    struct fid_eq    **result,
    void              *context)
{
    struct fi_eq_attr copy = *attr;

    if (wait_test_mode == FI_WAIT_NONE && attr->wait_obj == FI_WAIT_UNSPEC) {
        copy.wait_obj = FI_WAIT_NONE;
    } else if (attr->wait_obj != wait_test_mode) {
        return -FI_ENOSYS;
    }
    return wait_test_real_fabric->eq_open(fabric, &copy, result, context);
} // wait_test_eq_open

static int
wait_test_trywait(
    struct fid_fabric *fabric,
    struct fid       **fids,
    int                count)
{
    if (wait_test_observe && wait_test_veto) {
        wait_test_veto--;
        wait_test_injected++;
        wait_test_busy = 1;
        return -FI_EAGAIN;
    }
    return wait_test_real_fabric->trywait(fabric, fids, count);
} // wait_test_trywait

static void
wait_test_setup(void)
{
    const char  *mode = getenv("EVPL_TEST_WAIT_MODE");
    unsigned int i;

    if (!mode) {
        return;
    }
    wait_test_enabled = wait_test_observe = 1;
    wait_test_mode    = !strcmp(mode, "fd") ? FI_WAIT_FD :
        !strcmp(mode, "pollfd") ? FI_WAIT_POLLFD : FI_WAIT_NONE;
    for (i = 0; i < WAIT_TEST_FDS; i++) {
        evpl_test_abort_if(socketpair(AF_UNIX, SOCK_STREAM, 0, wait_test_pairs[i]),
                           "socketpair failed");
    }
    wait_test_real_domain        = external_domain->ops;
    wait_test_domain_ops         = *wait_test_real_domain;
    wait_test_domain_ops.cq_open = wait_test_cq_open;
    external_domain->ops         = &wait_test_domain_ops;
    wait_test_real_fabric        = external_fabric->ops;
    wait_test_fabric_ops         = *wait_test_real_fabric;
    wait_test_fabric_ops.eq_open = wait_test_eq_open;
    wait_test_fabric_ops.trywait = wait_test_trywait;
    external_fabric->ops         = &wait_test_fabric_ops;
} // wait_test_setup

static void
wait_test_add(
    struct evpl_core  *core,
    struct evpl_event *event)
{
    unsigned int i;

    for (i = 0; i < WAIT_TEST_FDS; i++) {
        if (event->fd == wait_test_pairs[i][0]) {
            evpl_test_abort_if(wait_test_events[i], "shared fd registered twice");
            wait_test_events[i] = event;
        }
    }
    wait_test_real_core->add(core, event);
} // wait_test_add

static void
wait_test_remove(
    struct evpl_core  *core,
    struct evpl_event *event)
{
    unsigned int i;

    for (i = 0; i < WAIT_TEST_FDS; i++) {
        if (wait_test_events[i] == event) {
            wait_test_events[i] = NULL;
        }
    }
    wait_test_real_core->remove(core, event);
} // wait_test_remove

static int
wait_test_wait(
    struct evpl_core *core,
    int               msecs)
{
    int rc;

    evpl_test_abort_if(wait_test_busy && msecs != 0, "slept during fi_trywait retry");
    wait_test_busy = 0;
    wait_test_waits++;
    rc = wait_test_real_core->wait(core, msecs);
    if (wait_test_events[0] && (wait_test_events[0]->flags & EVPL_READABLE)) {
        wait_test_ready++;
    }
    return rc;
} // wait_test_wait

static void
wait_test_loop(struct evpl *evpl)
{
    if (!wait_test_enabled) {
        return;
    }
    evpl->config.poll_mode = 0;
    evpl->config.wait_ms   = 1;
    wait_test_real_core    = evpl->core.ops;
    wait_test_core         = *wait_test_real_core;
    wait_test_core.add     = wait_test_add;
    wait_test_core.remove  = wait_test_remove;
    wait_test_core.wait    = wait_test_wait;
    evpl->core.ops         = &wait_test_core;
} // wait_test_loop

static void
wait_test_pump(struct evpl *evpl)
{
    unsigned int i;

    for (i = 0; i < 24; i++) {
        evpl_continue(evpl);
    }
} // wait_test_pump

static void
wait_test_checkpoint(struct evpl *evpl)
{
    unsigned int i;
    int          replacement[2], fd;
    char         byte = 1;

    if (!wait_test_enabled) {
        return;
    }
    evpl_test_abort_if(!wait_test_cqs, "test did not instrument any CQs");
    evpl_test_abort_if((wait_test_mode == FI_WAIT_NONE) != (evpl->num_timers != 0),
                       "fallback timer does not match negotiated wait mode");
    if (wait_test_mode != FI_WAIT_NONE) {
        wait_test_injected = 0;
        wait_test_veto     = 12;
        wait_test_pump(evpl);
        evpl_test_abort_if(wait_test_injected != 12, "fi_trywait retries not exercised");
    }
    if (wait_test_mode != FI_WAIT_POLLFD) {
        return;
    }
    for (i = 0; i < WAIT_TEST_FDS; i++) {
        evpl_test_abort_if(!wait_test_events[i], "large pollfd list was truncated");
    }
    /* Removed fds stay open, which catches stale watchers hidden by automatic
    * kernel cleanup on close.  The remaining subscribers change direction. */
    wait_test_count    = WAIT_TEST_FDS / 2;
    wait_test_interest = POLLOUT;
    wait_test_generation++;
    wait_test_pump(evpl);
    for (i = 0; i < WAIT_TEST_FDS; i++) {
        evpl_test_abort_if((i < wait_test_count) != !!wait_test_events[i],
                           "changed pollfd membership was not applied");
        if (i < wait_test_count) {
            evpl_test_abort_if(!(wait_test_events[i]->flags & EVPL_WRITE_INTEREST) ||
                               (wait_test_events[i]->flags & EVPL_READ_INTEREST),
                               "changed pollfd interests were not applied");
        }
    }
    /* Replace a provider fd while retaining its numeric value. */
    evpl_test_abort_if(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement), "socketpair failed");
    fd = wait_test_pairs[0][0];
    close(fd);
    evpl_test_abort_if(dup2(replacement[0], fd) != fd, "descriptor reuse failed");
    close(replacement[0]);
    close(wait_test_pairs[0][1]);
    wait_test_pairs[0][1] = replacement[1];
    wait_test_count       = WAIT_TEST_FDS;
    wait_test_interest    = POLLIN;
    wait_test_generation++;
    wait_test_pump(evpl);
    for (i = 0; i < WAIT_TEST_FDS; i++) {
        evpl_test_abort_if(!wait_test_events[i] ||
                           !(wait_test_events[i]->flags & EVPL_READ_INTEREST),
                           "pollfd registration was not restored");
    }
    wait_test_ready = 0;
    evpl_test_abort_if(write(wait_test_pairs[0][1], &byte, 1) != 1, "write failed");
    wait_test_pump(evpl);
    evpl_test_abort_if(wait_test_ready < 2, "reused fd did not provide level-triggered wakeups");
    evpl_test_abort_if(read(wait_test_pairs[0][0], &byte, 1) != 1, "read failed");
} // wait_test_checkpoint

static void
wait_test_finish(void)
{
    unsigned int i;

    if (!wait_test_enabled) {
        return;
    }
    evpl_test_abort_if(wait_test_cqs || !wait_test_waits, "CQ teardown or core waits missing");
    for (i = 0; i < WAIT_TEST_FDS; i++) {
        evpl_test_abort_if(wait_test_events[i], "borrowed descriptor watcher survived close");
        evpl_test_abort_if(fcntl(wait_test_pairs[i][0], F_GETFD) < 0,
                           "libevpl closed a borrowed provider descriptor");
        close(wait_test_pairs[i][0]);
        close(wait_test_pairs[i][1]);
    }
} // wait_test_finish
