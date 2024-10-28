#pragma once

struct evpl_allocator;

struct evpl_shared {
    struct evpl_config    *config;
    struct evpl_allocator *allocator;
    struct evpl_framework *framework[EVPL_NUM_FRAMEWORK];
    void                  *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_protocol  *protocol[EVPL_NUM_PROTO];
    void                  *protocol_private[EVPL_NUM_PROTO];
};