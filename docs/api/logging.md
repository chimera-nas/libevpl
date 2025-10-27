---
title: Logging
layout: default
parent: Core
nav_order: 13
permalink: /api/logging
---

# Logging

By default, libevpl logs to stderr in logfmt format.

The log output can be redirected to an application level function if desired.

## Functions

### `evpl_set_log_fn`

```c

typedef void (*evpl_log_fn)(
    const char *level,
    const char *module,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    va_list     argp);

typedef void (*evpl_flush_fn)(void);

void evpl_set_log_fn(
    evpl_log_fn   log_fn,
    evpl_flush_fn flush_fn);
```

Set custom logging callbacks.

**Parameters:**
- `log_fn` - Called for each emitted log message
- `flush_fn` - Called before crashing or asserting (optional, can be `NULL`)


**Callback Parameters:**
- `level` - Log level string ("ERROR", "WARN", "INFO", "DEBUG")
- `module` - Module name ("core", "rdma", "http", etc.)
- `srcfile` - Source file where log originated
- `lineno` - Line number in source file
- `fmt` - Printf-style format string
- `argp` - Variable arguments list

**Notes:**
- The callback must be thread-safe if using multi-threaded event loops
- Logging may want to be buffered and flushed asynchronously to minimize performance impact
- Use `vsnprintf()` or similar to format the message
- Must be called before `evpl_init()` to capture all log messages.
