---
title: Examples
layout: default
nav_order: 7
has_children: true
permalink: /examples
---

# Examples

Complete, working examples that demonstrate various features of libevpl. All examples are compiled and tested as part of the build process.

## Available Examples

- **[Echo Server (Stream)](/examples/echo-stream)** - Simple echo server using stream semantics
- **[Echo Server (Message)](/examples/echo-message)** - Echo server with message framing and segmentation

## Building and Running

These examples are built as part of the test suite:

```bash
make debug
cd build/debug
ctest -R "libevpl/examples"
```

Or run them manually:

```bash
./build/debug/src/tests/echo_stream
./build/debug/src/tests/echo_connected_msg
```
