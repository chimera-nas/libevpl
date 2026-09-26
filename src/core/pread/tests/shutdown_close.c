// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>
#include "evpl/evpl.h"
static struct evpl_block_device *device;
static atomic_int                opened, closed;
static void
open_done(
    struct evpl              *evpl,
    struct evpl_block_device *dev,
    int                       status,
    void                     *arg)
{
    if (status) {
        _exit(2);
    }
    device = dev;
    atomic_store(&opened, 1);
} /* open_done */
static void
close_done(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    atomic_store(&closed, 1);
} /* close_done */
static void *
start(
    struct evpl *evpl,
    void        *arg)
{
    evpl_block_open_device(evpl, EVPL_BLOCK_PROTOCOL_PREAD, "shutdown-close.img", open_done, NULL);
    return NULL;
} /* start */
static void
stop(
    struct evpl *evpl,
    void        *arg)
{
    evpl_block_close_device(evpl, device, close_done, NULL);
} /* stop */
int
main(void)
{
    FILE               *f = fopen("shutdown-close.img", "w");

    if (!f) {
        perror("shutdown-close.img");
        return 1;
    }
    fseek(f, 4095, SEEK_SET); fputc(0, f); fclose(f);
    struct evpl_thread *thread = evpl_thread_create(NULL, start, stop, NULL);
    while (!atomic_load(&opened)) {
        usleep(1000);
    }
    evpl_thread_destroy(thread);
    fprintf(stderr, "close callback delivered: %d\n", atomic_load(&closed));
    unlink("shutdown-close.img");
    return atomic_load(&closed) ? 0 : 1;
} /* main */
