#include "core/test_log.h"
#include "thread/thread.h"
#include "core/evpl.h"

void
thread_init(struct evpl *evpl, void *private_data)
{
    int *number = private_data;

    evpl_test_info("thread_init ran with number=%d", number);

    evpl_test_abort_if(*number != 42, 
        "got wrong argument in thread init function");
}

int main(int argc, char *argv[])
{
    struct evpl_threadpool *threadpool;
    int number = 42;

    evpl_init(NULL);

    threadpool = evpl_threadpool_create(16, thread_init, &number);

    evpl_threadpool_destroy(threadpool);

    evpl_cleanup();
}
