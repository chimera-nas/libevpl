// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <evpl/evpl.h>
#include <evpl/evpl_http.h>
int main(void)
{
    struct evpl *loop = evpl_create(NULL);
    struct evpl_http_agent *http = evpl_http_init(loop);
    struct evpl_iovec iov[2];
    int niov = evpl_iovec_alloc(loop, 4096, 64, 2, 0, iov);
    if (niov <= 0) {
        return 1;
    }
    evpl_iovecs_release(loop, iov, niov);
    evpl_http_destroy(http);
    evpl_destroy(loop);
    return 0;
}
