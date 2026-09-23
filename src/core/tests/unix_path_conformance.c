// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include "evpl/evpl.h"
#include "tests/test_mbt.h"
#include "unix_path_cases.h"

static struct sockaddr_un    address;
static struct evpl_listener *listener;
static int                   foreign_fd = -1;
static const char            contents[] = "This file belongs to another application.\n";

static void
cleanup(void)
{
    if (listener) {
        evpl_listener_destroy(listener);
        listener = NULL;
    }
    if (foreign_fd >= 0) {
        close(foreign_fd);
        foreign_fd = -1;
    }
    unlink(address.sun_path);
} /* cleanup */

static int
make_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    evpl_test_abort_if(fd < 0, "socket failed");
    evpl_test_abort_if(fcntl(fd, F_SETFL, O_NONBLOCK) < 0, "nonblocking socket failed");
    return fd;
} /* make_socket */

static void
check_path(
    int    state,
    size_t step)
{
    struct stat st;
    int         rc = lstat(address.sun_path, &st);

    if (state == 0) {
        evpl_test_abort_if(rc == 0 || errno != ENOENT, "step %zu: path should be absent", step);
    } else if (state == 3) {
        char data[sizeof(contents)];
        evpl_test_abort_if(rc || !S_ISREG(st.st_mode) || st.st_size != sizeof(contents),
                           "step %zu: regular file changed", step);
        int  fd = open(address.sun_path, O_RDONLY);
        evpl_test_abort_if(fd < 0 || read(fd, data, sizeof(data)) != sizeof(data) ||
                           memcmp(data, contents, sizeof(data)), "step %zu: file contents changed", step);
        close(fd);
    } else {
        evpl_test_abort_if(rc || !S_ISSOCK(st.st_mode), "step %zu: socket path lost", step);
    }
    if (state == 2) {
        /* Drain libevpl's stale-path probes before checking that the foreign
         * listener still accepts connections at the original name. */
        int fd;
        while ((fd = accept(foreign_fd, NULL, NULL)) >= 0) {
            close(fd);
        }
        fd = make_socket();
        evpl_test_abort_if(connect(fd, (struct sockaddr *) &address, sizeof(address)),
                           "step %zu: live listener displaced", step);
        int accepted = accept(foreign_fd, NULL, NULL);
        evpl_test_abort_if(accepted < 0, "step %zu: original listener unreachable", step);
        close(accepted);
        close(fd);
    }
} /* check_path */

int
main(void)
{
    char                         directory[] = "/tmp/evpl-path-mbt-XXXXXX";
    struct evpl_global_config   *config      = evpl_global_config_init();
    struct stat                  before, after;
    const struct unix_path_step *previous = NULL;

    test_evpl_set_core_mech(config);
    evpl_init(config);
    evpl_test_abort_if(!mkdtemp(directory), "mkdtemp failed");
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", directory);
    struct evpl_endpoint        *endpoint = evpl_endpoint_create_local(address.sun_path);
    evpl_test_abort_if(!endpoint, "local endpoint failed");
    for (size_t i = 0; i < sizeof(unix_path_steps) / sizeof(unix_path_steps[0]); i++) {
        const struct unix_path_step *s = &unix_path_steps[i];
        switch (s->op) {
            case unix_path_Reset: cleanup(); break;
            case unix_path_Stale:
            case unix_path_Live:
                foreign_fd = make_socket();
                evpl_test_abort_if(bind(foreign_fd, (struct sockaddr *) &address, sizeof(address)), "bind failed");
                if (s->op == unix_path_Live) {
                    evpl_test_abort_if(listen(foreign_fd, 16), "listen failed");
                } else {
                    close(foreign_fd); foreign_fd = -1;
                }
                break;
            case unix_path_File: {
                int fd = open(address.sun_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
                evpl_test_abort_if(fd < 0 || write(fd, contents, sizeof(contents)) != sizeof(contents),
                                   "create file failed");
                close(fd);
                break;
            }
            case unix_path_Listen: {
                if (previous->path == 2 || previous->path == 3) {
                    evpl_test_abort_if(lstat(address.sun_path, &before), "lstat before failed");
                }
                listener = evpl_listener_create();
                int rc = evpl_listen(listener, EVPL_STREAM_SOCKET_UNIX, endpoint);
                evpl_test_abort_if((rc == 0) != s->success, "step %zu: listen result differs from model", i);
                if (rc) {
                    evpl_listener_destroy(listener); listener = NULL;
                    evpl_test_abort_if(lstat(address.sun_path, &after) || before.st_ino != after.st_ino ||
                                       before.st_dev != after.st_dev, "step %zu: failed listen replaced path", i);
                }
                break;
            }
            case unix_path_Stop: evpl_listener_destroy(listener); listener = NULL; break;
            case unix_path_Crash: close(foreign_fd); foreign_fd            = -1; break;
            case unix_path_Remove:
                evpl_test_abort_if(unlink(address.sun_path), "remove fixture failed"); break;
            case unix_path_Inspect: break;
            default: abort();
        } /* switch */
        check_path(s->path, i);
        previous = s;
    }
    cleanup();
    evpl_endpoint_close(endpoint);
    evpl_test_abort_if(rmdir(directory), "remove fixture directory failed");
    return 0;
} /* main */
