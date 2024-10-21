#include "core/test_log.h"
#include "thread/thread.h"
#include "core/evpl.h"


void
thread_init(struct evpl *evpl, void *private_data)
{
    int *number = private_data;

    evpl_test_info("thread_init ran with number=%d", *number);

    evpl_test_abort_if(*number != 42, 
        "got wrong argument in thread init function");
}

int main(int argc, char *argv[])
{
    struct evpl_thread *thread;
    int number = 42;

    evpl_init(NULL);

    thread = evpl_thread_create(thread_init, NULL, &number);

    evpl_thread_destroy(thread);

    evpl_cleanup();
}
