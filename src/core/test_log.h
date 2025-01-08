#pragma once

#include "core/internal.h"

#define evpl_test_debug(...) evpl_debug("test", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_test_info(...)  evpl_info("test", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_test_error(...) evpl_error("test", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_test_fatal(...) evpl_fatal("test", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_test_abort(...) evpl_abort("test", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_test_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "test", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_test_abort_if(cond, ...) \
        evpl_fatal_if(cond, "test", __FILE__, __LINE__, __VA_ARGS__)
