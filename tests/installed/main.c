// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <evpl/evpl.h>
#include <evpl/evpl_http.h>
int main(void)
{
    struct evpl *loop = evpl_create(NULL);
    struct evpl_http_agent *http = evpl_http_init(loop);
    evpl_http_destroy(http);
    evpl_destroy(loop);
    return 0;
}
