#pragma once


typedef void (*evpl_poll_enter_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_poll_exit_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_poll_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_poll {
    evpl_poll_enter_callback_t enter_callback;
    evpl_poll_exit_callback_t  exit_callback;
    evpl_poll_callback_t       callback;
    void                      *private_data;
};

struct evpl_poll *
evpl_add_poll(
    struct evpl               *evpl,
    evpl_poll_enter_callback_t enter_callback,
    evpl_poll_exit_callback_t  exit_callback,
    evpl_poll_callback_t       callback,
    void                      *private_data);

void
evpl_remove_poll(
    struct evpl      *evpl,
    struct evpl_poll *poll);