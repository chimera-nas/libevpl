# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

libevpl is a high-performance network library providing a unified API for various networking backends (kernel sockets, RDMA, XLIO). It's designed for 400Gbps+ networking with automatic switching between event-driven and polling modes.

## Essential Development Commands

### Building
```bash
make debug          # Build debug version with AddressSanitizer and run tests
make release        # Build release version with optimizations and run tests
make clean          # Remove all build artifacts
```

**Note**: When running in a dev container, the build directory is automatically set to `/build` via the `LIBEVPL_BUILD_DIR` environment variable. Outside of dev containers, builds will use a `build/` subdirectory in the source tree.

### Testing
```bash
make test_debug     # Run all tests on debug build
make test_release   # Run all tests on release build

# Run specific test
cd build/debug && ctest -R "libevpl/core/init_no_config"
cd build/debug && ctest -R "libevpl/http"  # All tests in http module
```

### Code Formatting
```bash
make uncrustify     # Format all C source files according to etc/uncrustify.cfg
```

## Architecture Overview

### Module Structure
```
src/
├── core/           # Core event loop, protocol abstraction
│   ├── socket/     # Traditional TCP/UDP
│   ├── rdmacm/     # RDMA CM (RC/UD)
│   ├── xlio/       # NVIDIA XLIO acceleration
│   └── io_uring/   # io_uring support
├── http/           # HTTP client/server
├── rpc2/           # ONC RPC2 protocol
└── tests/          # Integration tests
```

### Key Abstractions

1. **Event Loop (`struct evpl`)**: Per-thread context managing I/O events, timers, and deferrals
2. **Bind (`struct evpl_bind`)**: Protocol-agnostic connection/socket abstraction
3. **Protocol (`struct evpl_protocol`)**: Interface for different network implementations
4. **Framework (`struct evpl_framework`)**: Global initialization for I/O frameworks

### Threading Model
- Single-threaded event loops (one `evpl` per thread)
- Thread pools via `evpl_threadpool`
- Inter-thread communication via doorbells (eventfd)
- No shared state between threads

### Memory Management
- Slab allocator for fixed-size objects
- Buffer management with reference counting
- iovec rings for zero-copy I/O
- Framework-specific memory registration (RDMA/VFIO)

## Development Guidelines

### Code Style
- Pure C (not C++)
- Follow existing patterns in neighboring files
- Use uncrustify for formatting
- No C++ style comments (`//`)

### API Design
- All operations are asynchronous/non-blocking
- Callbacks for completion notification
- Protocol-agnostic where possible
- Zero-copy optimized

### Testing
- Each module has its own test directory
- Tests use CTest framework
- Debug builds include AddressSanitizer
- Test timeout is 10 seconds

### Platform Support
- Linux: Uses epoll, supports io_uring
- macOS: Uses kqueue
- Optional features auto-detected: RDMA CM, XLIO, VFIO