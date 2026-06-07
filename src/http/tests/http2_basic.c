// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Drives the libevpl HTTP/2 server with libcurl using h2c prior-knowledge
 * (cleartext HTTP/2, no Upgrade).  The server code is identical to the HTTP/1.x
 * server tests -- proof of the transparent, unified API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#define TEST_PORT 8081

struct test_server {
    pthread_t            thread;
    volatile int         run;
    struct evpl_doorbell doorbell;
};

static void
server_wake(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
} /* server_wake */

static void
server_notify(
    struct evpl                *evpl,
    struct evpl_http_agent     *agent,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  notify_type,
    enum evpl_http_request_type request_type,
    const char                 *uri,
    void                       *notify_data,
    void                       *private_data)
{
    struct evpl_iovec iov;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            evpl_http_request_add_header(request, "MyHeader", "MyValue");
            evpl_iovec_alloc(evpl, 11, 0, 1, 0, &iov);
            memcpy(iov.data, "hello world", 11);
            iov.length = 11;
            evpl_http_server_set_response_length(request, 11);
            evpl_http_request_add_datav(request, &iov, 1);
            evpl_http_server_dispatch_default(request, 200);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
        case EVPL_HTTP_NOTIFY_WANT_DATA:
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
    } /* switch */
} /* server_notify */

static void
server_dispatch(
    struct evpl                 *evpl,
    struct evpl_http_agent      *agent,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify_callback,
    void                       **notify_data,
    void                        *private_data)
{
    *notify_callback = server_notify;
    *notify_data     = NULL;
} /* server_dispatch */

static void *
server_function(void *ptr)
{
    struct test_server      *server_ctx = ptr;
    struct evpl_http_server *server;
    struct evpl             *evpl;
    struct evpl_endpoint    *endpoint;
    struct evpl_listener    *listener;
    struct evpl_http_agent  *agent;

    evpl = evpl_create(NULL);
    evpl_add_doorbell(evpl, &server_ctx->doorbell, server_wake);
    agent    = evpl_http_init(evpl);
    endpoint = evpl_endpoint_create("0.0.0.0", TEST_PORT);
    listener = evpl_listener_create();
    server   = evpl_http_attach(agent, listener, server_dispatch, NULL);

    evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, endpoint);

    __sync_synchronize();
    server_ctx->run = 1;

    while (server_ctx->run) {
        evpl_continue(evpl);
    }

    evpl_http_server_destroy(agent, server);
    evpl_http_destroy(agent);
    evpl_listener_destroy(listener);
    evpl_destroy(evpl);

    return NULL;
} /* server_function */

static size_t
write_callback(
    char  *ptr,
    size_t size,
    size_t nmemb,
    void  *userdata)
{
    return size * nmemb;
} /* write_callback */

int
main(
    int   argc,
    char *argv[])
{
    struct test_server server;
    CURL              *curl;
    CURLcode           res;
    long               http_code    = 0;
    long               http_version = 0;
    char               url[64];

    server.run = 0;
    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return 1;
    }

    snprintf(url, sizeof(url), "http://localhost:%d", TEST_PORT);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                     (long) CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &http_version);
        fprintf(stderr, "http_code %ld http_version %ld\n", http_code, http_version);
    } else {
        fprintf(stderr, "curl failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    return (res == CURLE_OK && http_code == 200 &&
            http_version == CURL_HTTP_VERSION_2_0) ? 0 : 1;
} /* main */
