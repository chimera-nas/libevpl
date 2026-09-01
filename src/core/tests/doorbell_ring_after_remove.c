/* SPDX-FileCopyrightText: 2025 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Ringing a doorbell that has been removed is a use-after-close of its
 * eventfd, and libevpl aborts on it.  What this pins is not the abort -- that
 * behaviour predates it -- but what the abort SAYS.
 *
 * The message is the entire diagnosis available for this class of bug: it
 * fires on whichever thread rang the doorbell, long after the owner retired
 * it, and it is not reproducible on demand.  A report that says only "fd -1"
 * names neither the poster nor the owner, which in a process running several
 * doorbells across several threads is not enough to act on -- so this test
 * requires the message to name both call sites, and fails if a future change
 * quietly drops one.
 *
 * The abort runs in a forked child whose stderr is a pipe, and the parent does
 * the checking, so this stays an ordinary passing test.  Letting the abort take
 * down the test process instead would mean asking ctest to interpret a death,
 * and it does not do so portably: a raw SIGABRT is an "exception" that
 * PASS_REGULAR_EXPRESSION does not rescue on macOS, while on Linux the
 * sanitizer converts the same abort into an ordinary exit and the regex
 * applies.  Checking the text here works the same way everywhere, and puts the
 * assertion next to the reason for it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "evpl/evpl.h"

static void
doorbell_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    (void) evpl;
    (void) doorbell;
} /* doorbell_callback */

/* Rings a removed doorbell, and so never returns. */
static void
ring_after_remove(void)
{
    struct evpl         *evpl;
    struct evpl_doorbell doorbell;

    evpl_init(NULL);

    evpl = evpl_create(NULL);

    evpl_add_doorbell(evpl, &doorbell, doorbell_callback);

    /* A live doorbell rings without complaint; without this the test would
     * also pass against a build that aborted on every ring. */
    evpl_ring_doorbell(&doorbell);

    evpl_remove_doorbell(evpl, &doorbell);

    evpl_ring_doorbell(&doorbell);

    fprintf(stderr, "ringing a removed doorbell did not abort\n");

    _exit(0);
} /* ring_after_remove */

int
main(
    int    argc,
    char **argv)
{
    int    pipefd[2];
    pid_t  pid;
    char   out[8192];
    size_t len = 0;
    int    status, ok = 1;

    (void) argc;
    (void) argv;

    if (pipe(pipefd) != 0) {
        fprintf(stderr, "pipe failed\n");
        return 1;
    }

    pid = fork();

    if (pid < 0) {
        fprintf(stderr, "fork failed\n");
        return 1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        ring_after_remove();
        _exit(0);
    }

    close(pipefd[1]);

    while (len < sizeof(out) - 1) {
        ssize_t n = read(pipefd[0], out + len, sizeof(out) - 1 - len);

        if (n <= 0) {
            break;
        }
        len += (size_t) n;
    }
    out[len] = '\0';
    close(pipefd[0]);

    waitpid(pid, &status, 0);

    /* The child must have died rather than reached its own complaint. */
    if (strstr(out, "ringing a removed doorbell did not abort")) {
        fprintf(stderr, "FAIL: ringing a removed doorbell did not abort\n");
        return 1;
    }

    if (!strstr(out, "failed to ring doorbell")) {
        fprintf(stderr, "FAIL: no doorbell abort in the child's output\n");
        ok = 0;
    }

    /* Both ends, which is the whole point: the site that rang it, and the site
     * that removed it.  Each is reported as a file:line in this file. */
    if (!strstr(out, "REMOVED at")) {
        fprintf(stderr, "FAIL: the abort does not say the doorbell was "
                "REMOVED, so it names no owner\n");
        ok = 0;
    }

    if (!strstr(out, "doorbell_ring_after_remove.c")) {
        fprintf(stderr, "FAIL: the abort names no call site in this file\n");
        ok = 0;
    }

    if (!ok) {
        fprintf(stderr, "--- child output ---\n%s\n", out);
        return 1;
    }

    printf("ok - a doorbell rung after removal names both call sites\n");

    return 0;
} /* main */
