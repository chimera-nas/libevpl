#pragma once

typedef void (*evpl_poll_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_poll {
    evpl_poll_callback_t callback;
    void                *private_data;
};

void
evpl_add_poll(
    struct evpl         *evpl,
    evpl_poll_callback_t callback,
    void                *private_data);
