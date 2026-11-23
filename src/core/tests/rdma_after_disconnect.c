// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * An RDMA operation queued on a bind from inside its DISCONNECTED
 * notification could only complete after that notification, which the
 * contract forbids, so libevpl aborts and names the call.  ctest passes this
 * test when the abort message appears (PASS_REGULAR_EXPRESSION); "no abort"
 * or "callback ran" means the rule was not enforced.
 *
 * ctest fails any test killed by a signal, whatever its output, so the
 * scenario runs in a child process that is expected to abort.  The child
 * inherits stderr, so its abort message reaches ctest's output.
 */

#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "evpl/evpl.h"
#include "tests/test_common.h"

static struct evpl_iovec local;

static void
completed(
    int   status,
    void *arg)
{
    (void) arg;
    fprintf(stderr, "callback ran with %d\n", status);
} /* completed */

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *arg)
{
    struct evpl_iovec iov;

    (void) arg;

    if (event->notify_type != EVPL_NOTIFY_DISCONNECTED) {
        return;
    }

    evpl_iovec_clone(&iov, &local);
    evpl_rdma_read(evpl, bind, 1, 4096, &iov, 1, completed, NULL);
    evpl_iovec_release(evpl, &iov);
} /* notify */

static int
run(void)
{
    struct evpl_global_config *config = evpl_global_config_init();
    struct evpl_thread_config *thread_config;
    struct evpl               *evpl;
    struct evpl_endpoint      *endpoint;
    int                        n;

    evpl_global_config_set_buffer_size(config, 4096);
    test_evpl_set_core_mech(config);
    evpl_init(config);

    /* Never block: once the bind is gone nothing would wake the loop. */
    thread_config = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(thread_config, 0);
    evpl = evpl_create(thread_config);
    if (evpl_iovec_alloc(evpl, 4096, 1, 1, 0, &local) != 1) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    /* Nobody listens on this name, so the bind closes itself at once. */
    endpoint = evpl_endpoint_create("inproc://rdma-after-disconnect-nobody", 0);
    if (!evpl_connect(evpl, EVPL_DATAGRAM_INPROC, NULL, endpoint, notify, NULL, NULL)) {
        fprintf(stderr, "connect failed\n");
        return 1;
    }

    for (n = 0; n < 1000; n++) {
        evpl_continue(evpl);
    }

    fprintf(stderr, "no abort\n");
    return 0;
} /* run */

int
main(void)
{
    struct rlimit no_core = { 0, 0 };
    pid_t         child;
    int           status;

    fflush(NULL);
    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* The abort is expected; do not leave a core file behind. */
        setrlimit(RLIMIT_CORE, &no_core);
        _exit(run());
    }

    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT) {
        fprintf(stderr, "child aborted\n");
        return 0;
    }

    fprintf(stderr, "child did not abort (status %d)\n", status);
    return 1;
} /* main */
