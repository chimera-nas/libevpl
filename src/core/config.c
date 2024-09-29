/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#include <unistd.h>
#include "core/config.h"
#include "core/internal.h"


struct evpl_config *
evpl_config_init(void)
{
    struct evpl_config *config = evpl_zalloc(sizeof(*config));

    config->max_pending     = 16;
    config->max_poll_fd     = 16;
    config->buffer_size     = 2 * 1024 * 1024;
    config->refcnt          = 1;
    config->bvec_ring_size  = 256;
    config->dgram_ring_size = 256;
    config->max_msg_size    = 65536;
    config->max_msg_batch   = 16;

    config->page_size = sysconf(_SC_PAGESIZE);

    if (config->page_size == -1) {
        config->page_size = 4096;
    }

    return config;
} /* evpl_config_init */

void
evpl_config_release(struct evpl_config *config)
{
    --config->refcnt;

    if (config->refcnt == 0) {
        evpl_free(config);
    }
} /* evpl_config_release */
