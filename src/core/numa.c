// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <numa.h>

#include "numa.h"
#include "logging.h"
#include "evpl.h"

struct evpl_numa_config *
evpl_numa_discover(void)
{
    struct evpl_numa_config *config;

    if (numa_available() < 0) {
        return NULL;
    }

    config = evpl_zalloc(sizeof(*config));

    config->num_nodes = numa_num_configured_nodes();
    config->num_cpus  = numa_num_configured_cpus();

    return config;
} /* evpl_numa_disdover */

void
evpl_numa_config_release(struct evpl_numa_config *config)
{
    evpl_free(config);
} /* evpl_numa_config_release */