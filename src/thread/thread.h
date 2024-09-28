#pragma once

struct evpl;
struct evpl_thread;
struct evpl_threadpool;

typedef void (*evpl_thread_init_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_thread *
evpl_thread_create(
    evpl_thread_init_callback_t init_function,
    void                       *private_data);

void
evpl_thread_destroy(
    struct evpl_thread *thread);

struct evpl_threadpool *
evpl_threadpool_create(
    int                         nthreads,
    evpl_thread_init_callback_t init_function,
    void                       *private_data);

void
evpl_threadpool_destroy(
    struct evpl_threadpool *threadpool);
