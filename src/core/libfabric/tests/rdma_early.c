// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* Run a fresh process: forking an initialized provider with worker threads
 * would test unsupported provider behavior rather than the key-export guard. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "core/test_log.h"

int
main(
    int    argc,
    char **argv)
{
    int           fd[2], status, found = 0;
    pid_t         child;
    ssize_t       count;
    char          buffer[4096];
    size_t        used  = 0;
    struct rlimit limit = { 0, 0 };

    alarm(30);
    evpl_test_abort_if(argc != 3 || pipe(fd), "invalid test invocation");
    child = fork();
    evpl_test_abort_if(child < 0, "fork failed");
    if (!child) {
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        dup2(fd[1], STDERR_FILENO);
        close(fd[1]);
        setrlimit(RLIMIT_CORE, &limit);
        setenv("EVPL_TEST_EARLY_RDMA", argv[2], 1);
        execl(argv[1], argv[1], "-r", "DATAGRAM_LIBFABRIC_MSG", (char *) NULL);
        _exit(127);
    }
    close(fd[1]);
    while ((count = read(fd[0], buffer + used, sizeof(buffer) - 1 - used)) != 0) {
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            evpl_test_abort("reading child diagnostics failed");
        }
        used        += count;
        buffer[used] = 0;
        if (strstr(buffer, "evpl_rdma_get_address requires EVPL_NOTIFY_CONNECTED")) {
            found = 1;
        }
        if (used > sizeof(buffer) / 2) {
            memmove(buffer, buffer + used - 256, 256);
            used = 256;
        }
    }
    close(fd[0]);
    evpl_test_abort_if(waitpid(child, &status, 0) != child, "waitpid failed");
    evpl_test_abort_if(!found || !WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT,
                       "premature key export did not fail at the connected-state guard");
    return 0;
} /* main */
