/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#include <unistd.h>
#include "eventpoll_config.h"
#include "eventpoll_internal.h"


struct eventpoll_config *
eventpoll_config_init(void)
{
    struct eventpoll_config *config = eventpoll_zalloc(sizeof(*config));

    config->max_pending     = 16;
    config->max_poll_fd     = 16;
    config->buffer_size     = 2*1024*1024;
    config->refcnt          = 1;
    config->bvec_ring_size  = 256;

    config->page_size = sysconf(_SC_PAGESIZE);

    if (config->page_size == -1) {
        config->page_size = 4096;
    }

    return config;
}

void
eventpoll_config_release(struct eventpoll_config *config)
{
    --config->refcnt;

    if (config->refcnt == 0) {
        eventpoll_free(config);
    }
}
