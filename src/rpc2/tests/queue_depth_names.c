// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * The rpc2 queue depth series is labelled with the name of the event loop
 * thread, and several rpc2 contexts on one thread share one series per role.
 * Checks the exposition: one series per role for a named thread however many
 * contexts it runs, and gone only when the last context is destroyed.
 */

#include "core/os.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "evpl/evpl.h"
#include "evpl/evpl_config.h"
#include "evpl/evpl_rpc2.h"

static void
check(
    int         condition,
    const char *what)
{
    if (!condition) {
        fprintf(stderr, "check failed: %s\n", what);
        abort();
    }
} /* check */

static int
count(const char *needle)
{
    static char scrape[1 << 20];
    int         n, found = 0;
    const char *p = scrape;

    n = evpl_metrics_scrape(scrape, sizeof(scrape));
    check(n > 0, "scrape produced nothing");

    while ((p = strstr(p, needle))) {
        found++;
        p += strlen(needle);
    }

    return found;
} /* count */

int
main(void)
{
    struct evpl_thread_config *config = evpl_thread_config_init();
    struct evpl               *evpl;
    struct evpl_rpc2_thread   *a, *b;

    evpl_thread_config_set_name(config, "qdnames");
    evpl = evpl_create(config);

    check(count("thread=\"qdnames\"") == 0, "series exist before any context");

    a = evpl_rpc2_thread_init(evpl, NULL, 0, NULL, NULL);

    check(count("evpl_rpc2_queue_depth{role=\"server\",thread=\"qdnames\"}") == 1, "server series after one context");
    check(count("evpl_rpc2_queue_depth{role=\"client\",thread=\"qdnames\"}") == 1, "client series after one context");
    check(count("evpl_rpc2_requests_total{role=\"server\",thread=\"qdnames\"}") == 1, "server request series");
    check(count("evpl_rpc2_requests_total{role=\"client\",thread=\"qdnames\"}") == 1, "client request series");

    b = evpl_rpc2_thread_init(evpl, NULL, 0, NULL, NULL);

    check(count("evpl_rpc2_queue_depth{role=\"server\",thread=\"qdnames\"}") == 1,
          "second context duplicated the server series");
    check(count("evpl_rpc2_requests_total{role=\"server\",thread=\"qdnames\"}") == 1,
          "second context duplicated a request series");
    check(count("evpl_rpc2_queue_depth{role=\"client\",thread=\"qdnames\"}") == 1,
          "second context duplicated the client series");

    evpl_rpc2_thread_destroy(a);

    check(count("evpl_rpc2_queue_depth{role=\"server\",thread=\"qdnames\"}") == 1,
          "series dropped while a context still uses it");

    evpl_rpc2_thread_destroy(b);

    check(count("thread=\"qdnames\"") == 0, "series outlived its last context");

    evpl_destroy(evpl);

    return 0;
} /* main */
