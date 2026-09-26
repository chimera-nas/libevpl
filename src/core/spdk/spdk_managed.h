// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once

/*
 * Managed SPDK env/reactor bootstrap.
 *
 * When evpl_global_config_set_spdk_managed is enabled (the default), libevpl
 * owns the SPDK env under EVPL_CORE_MECH_SPDK instead of requiring the host
 * application to bootstrap it: init() brings up the SPDK env (no hugepages)
 * and registers a thread-library scheduler that spawns one reactor pthread per
 * spdk_thread (pinned to the thread's cpumask), and fini() tears them down.
 * No SPDK types appear here so this header is safe to include anywhere.
 */

struct evpl_global_config;

void evpl_spdk_managed_init(
    struct evpl_global_config *config);

void evpl_spdk_managed_fini(
    void);

int evpl_spdk_managed_is_active(
    void);
