#include "eventpoll_config.h"
#include "eventpoll_internal.h"


struct eventpoll_config *
eventpoll_config_init(void)
{
    struct eventpoll_config *config = eventpoll_zalloc(sizeof(*config));

    config->max_pending = 16;
    config->max_poll_fd = 16;
    config->refcnt      = 1;

    return config;
}

void
eventpoll_config_release(struct eventpoll_config *config)
{
    --config->refcnt;

    if (config->refcnt == 0) {
        eventpoll_free(config);
    }
}
