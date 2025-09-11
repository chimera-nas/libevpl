// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once


struct evpl_numa_config {
    int num_nodes;
    int num_cpus;
};


struct evpl_numa_config *
evpl_numa_discover(
    void);

void
evpl_numa_config_release(
    struct evpl_numa_config *config);