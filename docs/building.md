---
title: Building
layout: default
nav_order: 2
permalink: /build
---

# Building & Installation

This guide covers building libevpl from source, including dependencies, build options, and platform-specific considerations.

## Prerequisites

### Required

- **CMake** 3.22 or later
- **Ninja** build system
- **GCC** or compatible C compiler
- **Linux** (primary support) or **macOS**

### Optional Dependencies

The following dependencies enable specific protocol backends. All are detected automatically at build time:

- **liburing** - Enables io_uring support for block I/O and future network protocol support
- **VFIO** - Enables VFIO-based NVMe block device support (Linux kernel headers)
- **RDMA CM** (librdmacm) - Enables RDMA Reliable Connection (RC) and Unreliable Datagram (UD) protocols
- **NVIDIA XLIO** - Enables hardware-accelerated TCP for Mellanox NICs
- **libnuma-dev** - NUMA awareness (recommended for multi-socket systems)

### Installing Dependencies

**Ubuntu/Debian:**
```bash
# Required
sudo apt-get install cmake ninja-build gcc

# Optional - all features
sudo apt-get install liburing-dev libibverbs-dev librdmacm-dev libnuma-dev

# For XLIO support (Mellanox NICs only)
# See: https://github.com/Mellanox/libxlio
```

**RHEL/Fedora:**
```bash
# Required
sudo dnf install cmake ninja-build gcc

# Optional
sudo dnf install liburing-devel rdma-core-devel numactl-devel
```

**macOS:**
```bash
# Using Homebrew
brew install cmake ninja

# Note: RDMA and XLIO are not available on macOS
```

## Quick Build

The Makefile provides convenient targets for common build workflows:

```bash
# Build release version with optimizations and run tests (default)
make release

# Build debug version with AddressSanitizer and run tests
make debug

# Clean all build artifacts
make clean
```

## Build Directory Location

By default, builds are placed in the `build/` subdirectory:
- `build/Release/` - Release builds
- `build/Debug/` - Debug builds

When using the dev container, the `LIBEVPL_BUILD_DIR` environment variable is automatically set to `/build` to place build artifacts outside the source tree.

You can override the build directory:
```bash
BUILD_DIR=/tmp/evpl-build make release
```

## Build Types

### Release Build

Optimized for performance:

```bash
make release
```

Or manually with CMake:
```bash
mkdir -p build/Release
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -S . -B build/Release
ninja -C build/Release
cd build/Release && ctest --output-on-failure --timeout 10
```

Characteristics:
- `-O3` optimization level
- No debug symbols (use `-DCMAKE_BUILD_TYPE=RelWithDebInfo` if needed)
- No assertions
- No AddressSanitizer

### Debug Build

Includes debugging and testing tools:

```bash
make debug
```

Or manually:
```bash
mkdir -p build/Debug
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -S . -B build/Debug
ninja -C build/Debug
cd build/Debug && ctest --output-on-failure --timeout 10
```

Characteristics:
- Debug symbols (`-g`)
- **AddressSanitizer** (`-fsanitize=address`) for memory error detection
- Stack protections
- Assertions enabled
- No optimizations

**Note:** Debug builds with AddressSanitizer are significantly slower but catch memory errors like buffer overflows, use-after-free, and memory leaks.

## Platform Support

### Linux

Full support for all features:
- Uses **epoll** for event notification
- All protocol backends available (socket, XLIO, RDMA, io_uring)
- VFIO-based NVMe support

Tested on:
- Ubuntu 22.04+
- Debian 12+
- RHEL 9+

### macOS

Limited support:
- Uses **kqueue** for event notification
- Only kernel socket protocols (TCP/UDP)
- No RDMA, XLIO, or VFIO support

## Running Tests

Tests are automatically run by the `make debug` and `make release` targets.

To run tests manually:

```bash
# Run all tests
cd build/Debug && ctest --output-on-failure --timeout 10

# Run specific test
cd build/Debug && ctest -R "libevpl/core/init_no_config"

# Run all tests in a module
cd build/Debug && ctest -R "libevpl/http"

# Verbose output
cd build/Debug && ctest -V
```

All tests have a 10-second timeout. Debug builds use AddressSanitizer to detect memory errors.

## Build Configuration Detection

During configuration, CMake automatically detects available optional features:

```bash
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -S . -B build/Release
```

Look for messages like:
```
-- Building Release for Linux
-- io_uring library /usr/lib/x86_64-linux-gnu/liburing.so
-- RDMACM library /usr/lib/x86_64-linux-gnu/librdmacm.so
-- XLIO library /opt/nvidia/xlio/lib/libxlio.so
-- VFIO include /usr/include
```

Or for missing features:
```
-- xlio library not found.
```

## Code Formatting

libevpl uses **uncrustify** for consistent code formatting:

```bash
# Check formatting (CI validation)
make syntax-check

# Auto-format all source files
make syntax

# Format manually with uncrustify
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/core/evpl.c
```

The configuration is in `etc/uncrustify.cfg`. All contributions should be formatted before submission.

## Dev Container

A dev container configuration is provided with all dependencies pre-installed:

1. Open the repository in **VS Code** with the Remote-Containers extension
2. Click "Reopen in Container"
3. Build with `make debug` or `make release`

The dev container sets `LIBEVPL_BUILD_DIR=/build` to keep build artifacts outside the mounted source directory for better performance.

## Installation

After building, you can install the library system-wide:

```bash
cd build/Release
sudo ninja install
```

By default, this installs to `/usr/local/`:
- Headers: `/usr/local/include/evpl/`
- Libraries: `/usr/local/lib/`

To install to a custom prefix:
```bash
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/evpl -S . -B build/Release
ninja -C build/Release
sudo ninja -C build/Release install
```

## Linking Against libevpl

In your CMake project:

```cmake
find_package(PkgConfig REQUIRED)
pkg_check_modules(EVPL REQUIRED libevpl)

include_directories(${EVPL_INCLUDE_DIRS})
link_directories(${EVPL_LIBRARY_DIRS})

add_executable(myapp main.c)
target_link_libraries(myapp ${EVPL_LIBRARIES})
```

Or manually:
```bash
gcc -o myapp main.c -levpl -luring -lrdmacm -lpthread
```

## Troubleshooting

### Build Failures

**Problem:** `fatal error: rdma/rdma_cma.h: No such file or directory`
**Solution:** Install `librdmacm-dev` (Debian/Ubuntu) or `rdma-core-devel` (RHEL/Fedora), or proceed without RDMA support

**Problem:** `fatal error: liburing/io_uring.h: No such file or directory`
**Solution:** Install `liburing-dev` or proceed without io_uring support

**Problem:** Tests fail with AddressSanitizer errors
**Solution:** This indicates a real memory error - please report the issue

### Linking Failures

**Problem:** `undefined reference to evpl_init`
**Solution:** Make sure to link with `-levpl` and that the library path is in `LD_LIBRARY_PATH` or `/etc/ld.so.conf`

**Problem:** `libevpl.so: cannot open shared object file`
**Solution:** Run `sudo ldconfig` after installation, or set `LD_LIBRARY_PATH=/usr/local/lib`

## Next Steps

- Read the [Architecture & Concepts](/architecture) guide to understand libevpl's design
- Explore the [API Reference](/api) for detailed function documentation
- Try the [Examples](/examples) to see libevpl in action
