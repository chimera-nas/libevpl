#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "core/internal.h"
#include "core/evpl.h"
#include "core/event.h"
#include "thread/thread.h"

#define evpl_thread_debug(...) evpl_debug("thread", __VA_ARGS__)
#define evpl_thread_info(...)  evpl_info("thread", __VA_ARGS__)
#define evpl_thread_error(...) evpl_error("thread", __VA_ARGS__)
#define evpl_thread_fatal(...) evpl_fatal("thread", __VA_ARGS__)
#define evpl_thread_abort(...) evpl_abort("thread", __VA_ARGS__)

#define evpl_thread_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "thread", __VA_ARGS__)

#define evpl_thread_abort_if(cond, ...) \
        evpl_abort_if(cond, "thread", __VA_ARGS__)

struct evpl_thread {
    pthread_t                      thread;
    struct evpl_event              event;
    evpl_thread_init_callback_t    init_callback;
    evpl_thread_wake_callback_t    wake_callback;
    evpl_thread_destroy_callback_t destroy_callback;
    void                          *private_data;
    int                            run;
    int                            eventfd;
};

struct evpl_threadpool {
    struct evpl_thread **threads;
    int                  nthreads;
};

void
evpl_thread_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_thread *evpl_thread;
    uint64_t            word;
    ssize_t             rc;

    rc = read(event->fd, &word, sizeof(word));

    evpl_thread_abort_if(rc != sizeof(word),
                         "Short read from thread eventfd");

    evpl_event_mark_unreadable(event);

    evpl_thread = container_of(event, struct evpl_thread, event);

    if (evpl_thread->wake_callback) {
        evpl_thread->wake_callback(evpl, evpl_thread->private_data);
    }

} /* evpl_thread_event */

void *
evpl_thread_function(void *ptr)
{
    struct evpl_thread *evpl_thread = ptr;
    struct evpl        *evpl;

    evpl = evpl_create();

    evpl_thread->event.fd            = evpl_thread->eventfd;
    evpl_thread->event.read_callback = evpl_thread_event;

    evpl_add_event(evpl, &evpl_thread->event);
    evpl_event_read_interest(evpl, &evpl_thread->event);

    evpl_thread->private_data = evpl_thread->init_callback(evpl, evpl_thread->
                                                           private_data);

    while (evpl_thread->run) {
        evpl_wait(evpl, -1);
    }

    evpl_remove_event(evpl, &evpl_thread->event);

    evpl_thread->destroy_callback(evpl, evpl_thread->private_data);

    evpl_destroy(evpl);

    return NULL;
} /* evpl_thread_function */

struct evpl_thread *
evpl_thread_create(
    evpl_thread_init_callback_t    init_function,
    evpl_thread_wake_callback_t    wake_function,
    evpl_thread_destroy_callback_t destroy_function,
    void                          *private_data)
{
    struct evpl_thread *evpl_thread;

    evpl_thread = evpl_zalloc(sizeof(*evpl_thread));

    evpl_thread->init_callback    = init_function;
    evpl_thread->wake_callback    = wake_function;
    evpl_thread->destroy_callback = destroy_function;
    evpl_thread->private_data     = private_data;
    evpl_thread->run              = 1;

    evpl_thread->eventfd = eventfd(0, 0);

    evpl_thread_abort_if(evpl_thread->eventfd < 0,
                         "Failed to create eventfd for thread");

    pthread_create(&evpl_thread->thread, NULL,
                   evpl_thread_function, evpl_thread);

    return evpl_thread;
} /* evpl_thread_create */

void
evpl_thread_destroy(struct evpl_thread *evpl_thread)
{
    uint64_t word = 1;
    ssize_t  rc;

    evpl_thread->run = 0;

    rc = write(evpl_thread->eventfd, &word, sizeof(word));

    evpl_thread_abort_if(rc != sizeof(word),
                         "Short write to thread eventfd");

    pthread_join(evpl_thread->thread, NULL);

    close(evpl_thread->eventfd);

    evpl_free(evpl_thread);
} /* evpl_thread_destroy */

void
evpl_thread_wake(struct evpl_thread *evpl_thread)
{
    uint64_t word = 1;
    ssize_t  rc;

    rc = write(evpl_thread->eventfd, &word, sizeof(word));

    evpl_thread_abort_if(rc != sizeof(word),
                         "Short write to thread eventfd");

} /* evpl_thread_wake */

struct evpl_threadpool *
evpl_threadpool_create(
    int                            nthreads,
    evpl_thread_init_callback_t    init_function,
    evpl_thread_wake_callback_t    wake_function,
    evpl_thread_destroy_callback_t destroy_function,
    void                          *private_data)
{
    struct evpl_threadpool *threadpool;
    int                     i;

    threadpool = evpl_zalloc(sizeof(*threadpool));

    threadpool->threads  = evpl_zalloc(sizeof(struct evpl_thread *) * nthreads);
    threadpool->nthreads = nthreads;

    for (i = 0; i < nthreads; ++i) {
        threadpool->threads[i] = evpl_thread_create(init_function,
                                                    wake_function,
                                                    destroy_function,
                                                    private_data);
    }

    return threadpool;
} /* evpl_threadpool_create */

void
evpl_threadpool_destroy(struct evpl_threadpool *threadpool)
{
    int i;

    for (i = 0; i < threadpool->nthreads; ++i) {
        evpl_thread_destroy(threadpool->threads[i]);
    }

    evpl_free(threadpool->threads);
    evpl_free(threadpool);
} /* evpl_threadpool_destroy */
