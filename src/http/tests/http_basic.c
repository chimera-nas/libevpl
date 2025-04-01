// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <pthread.h>
#include <curl/curl.h>

#include "http/http.h"
#include "evpl/evpl.h"

struct test_server {
    pthread_t            thread;
    int                  run;
    struct evpl_doorbell doorbell;
};

static void
server_wake(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    /* do nothing */
} /* server_wake */

static void
server_notify(
    struct evpl               *evpl,
    struct evpl_http_agent    *agent,
    struct evpl_http_request  *request,
    enum evpl_http_notify_type notify_type,
    void                      *private_data)
{
    struct evpl_iovec iov;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            fprintf(stderr, "notify request\n");
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            fprintf(stderr, "notify request complete\n");
            evpl_http_request_add_header(request, "MyHeader", "MyValue");

            evpl_iovec_alloc(evpl, 11, 0, 1, &iov);

            memcpy(iov.data, "hello world", 11);
            iov.length = 11;
            evpl_http_server_set_response_length(request, 11);
            evpl_http_request_add_datav(request, &iov, 1);
            evpl_http_server_dispatch_default(request, 200);
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            fprintf(stderr, "notify want data\n");
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            fprintf(stderr, "notify response complete\n");
            break;
    } /* switch */
} /* server_notify */

static void
server_dispatch(
    struct evpl                 *evpl,
    struct evpl_http_agent      *agent,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify_callback,
    void                        *private_data)
{
    fprintf(stderr, "dispatch request\n");
    *notify_callback = server_notify;
} /* server_dispatch */

void *
server_function(void *ptr)
{
    struct test_server      *server_ctx = (struct test_server *) ptr;
    struct evpl_http_server *server;
    struct evpl             *evpl;
    struct evpl_endpoint    *endpoint;
    struct evpl_http_agent  *agent;

    evpl = evpl_create(NULL);

    evpl_add_doorbell(evpl, &server_ctx->doorbell, server_wake);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("0.0.0.0", 80);

    server = evpl_http_listen(agent, endpoint, server_dispatch, NULL);

    __sync_synchronize();

    server_ctx->run = 1;

    while (server_ctx->run) {
        evpl_continue(evpl);
    }

    evpl_http_server_destroy(agent, server);
    evpl_http_destroy(agent);

    evpl_destroy(evpl);

    return NULL;
} /* server */

static size_t
header_callback(
    char  *buffer,
    size_t size,
    size_t nitems,
    void  *userdata)
{
    size_t total_size = size * nitems;

    fprintf(stderr, "Received header: %.*s", (int) total_size, buffer);
    return total_size;
} /* header_callback */

static size_t
write_callback(
    char  *ptr,
    size_t size,
    size_t nmemb,
    void  *userdata)
{
    size_t total_size = size * nmemb;

    fprintf(stderr, "Response body: %.*s\n", (int) total_size, ptr);
    return total_size;
} /* write_callback */

int
main(
    int   argc,
    char *argv[])

{
    struct test_server server;
    CURL              *curl;
    CURLcode           res;
    long               http_code = 0;

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

    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:80");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "hello world");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        fprintf(stderr, "http_code %ld\n", http_code);


    }

    curl_easy_cleanup(curl);

    server.run = 0;
    __sync_synchronize();

    evpl_ring_doorbell(&server.doorbell);

    pthread_join(server.thread, NULL);

    return (res == CURLE_OK && http_code == 200) ? 0 : 1;
} /* main */