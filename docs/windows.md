---
title: Windows
layout: default
parent: Building
nav_order: 1
permalink: /build/windows
---

# Native Windows support

libevpl builds with MSVC as native Windows DLLs on x64 and ARM64. It uses
IOCP, overlapped Winsock, Windows synchronization primitives, and the Windows
file APIs. No Cygwin, MSYS runtime, or POSIX emulation layer is required.

## Build and test

Install Visual Studio 2022 (or its Build Tools) with the Desktop development
with C++ workload, a Windows SDK, and CMake. Select the ARM64 compiler tools
when building on Windows ARM64. Use a recent MSVC toolset supporting C11 atomics;
the build enables `/experimental:c11atomics`.

Clone recursively, then run these commands from the repository in PowerShell.
The vcpkg manifest builds dependencies with MSVC, including OpenSSL, nghttp2,
protobuf-c, and SQLite. The pinned vcpkg revision matches CI.

```powershell
git submodule update --init --recursive
git clone https://github.com/microsoft/vcpkg.git _vcpkg
git -C _vcpkg checkout a1cae005c39be7b18ba319fced856b68d7276271
./_vcpkg/bootstrap-vcpkg.bat -disableMetrics

$archive = "$env:TEMP/winflexbison.zip"
Invoke-WebRequest https://github.com/lexxmark/winflexbison/releases/download/v2.5.25/win_flex_bison-2.5.25.zip -OutFile $archive
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne '8d324b62be33604b2c45ad1dd34ab93d722534448f55a16ca7292de32b6ac135') { throw 'WinFlexBison checksum mismatch' }
Expand-Archive $archive "$env:TEMP/winflexbison" -Force

$arch = 'ARM64' # use 'x64' on x64 Windows
$triplet = $arch.ToLower() + '-windows'
cmake -S . -B build -G "Visual Studio 17 2022" -A $arch `
  "-DCMAKE_TOOLCHAIN_FILE=$pwd/_vcpkg/scripts/buildsystems/vcpkg.cmake" `
  "-DVCPKG_TARGET_TRIPLET=$triplet" "-DVCPKG_HOST_TRIPLET=$triplet" `
  "-DFLEX_EXECUTABLE=$env:TEMP/winflexbison/win_flex.exe" `
  "-DBISON_EXECUTABLE=$env:TEMP/winflexbison/win_bison.exe" `
  -DOTEL_SQLITE=ON
cmake --build build --config Debug --parallel 4
ctest --test-dir build -C Debug --output-on-failure --timeout 300
cmake --build build --config Release --parallel 4
ctest --test-dir build -C Release --output-on-failure --timeout 300
cmake --install build --config Release --prefix "$pwd/install"
```

Check each command's exit status before proceeding. Configure separate build
directories when changing architecture. Put the installed `bin` directory and
the matching vcpkg runtime DLL directory on `PATH` when running a consumer.
Keep Debug and Release dependency DLLs separate. `tests/installed` demonstrates
compiling and linking a separate application against the installed headers and
import libraries. When linking manually to a Debug libevpl, define
`EVPL_IOVEC_TRACE=1` in the consumer as well: it changes inline iovec reference
handling. CMake consumers linking the in-tree `evpl` target inherit that flag.
Use the matching MSVC DLL runtime (`/MDd` for Debug, `/MD` for Release).

The commands above run the ordinary unit and integration tests. For the
model-generated core, HTTP, and RPC conformance suites, download the
`native-conformance-corpus` artifact from the GitHub Actions run for the same
commit, extract its four headers to `corpus`, and reconfigure with
`-DEVPL_CONFORMANCE_CASES_DIR=<absolute-path-to-corpus>`. CI generates these cases
on Linux with pinned Quint tools, then replays them in native MSVC executables
on Windows. Case generation does not require a Unix shell in the Windows VM.

## Available functionality

| Area | Windows implementation |
| --- | --- |
| Event loop | IOCP, selected automatically; `iocp` is the explicit mechanism name |
| TCP and UDP | Native overlapped Winsock, retaining the existing socket protocol IDs |
| TLS | OpenSSL memory BIOs over the native TCP transport |
| TCP_RDMA | Existing software framing protocol over the portable TCP transport |
| In-process messaging | Existing datagram and stream protocols with native synchronization |
| Doorbells | IOCP packets with independently owned, revocable sender handles |
| Ordinary file I/O | PREAD service thread using Windows file handles and explicit offsets |
| HTTP and RPC | HTTP/1.x, HTTP/2, and ONC RPC2 over supported transports |
| Observability | Prometheus and OpenTelemetry, including optional SQLite support |

Windows TLS uses the same OpenSSL certificate and cipher configuration as the
Unix implementation. Schannel and Windows certificate-store integration are
not implemented. The portable TLS engine is selected automatically on Windows;
on Linux or macOS it can be selected with `-DEVPL_TLS_MEMORY_BIO=ON`. Unix builds
retain their existing socket TLS/kTLS path by default.

The ordinary-file backend accepts UTF-8 paths and converts them to UTF-16 for
Windows. It supports 64-bit offsets; tests cover Unicode filenames and a sparse
file beyond 4 GiB. It currently uses the file service thread rather than
submitting file operations directly to IOCP.

AF_UNIX transports, POSIX file-descriptor readiness events, retained-iovec stack
profiling, and Linux-specific accelerated backends (io_uring, libaio, VFIO,
RDMA CM/verbs, XLIO) are not implemented on Windows. Selecting an unavailable
protocol does not make it available through emulation. The native dependency
manifest does not include a GSS/Kerberos provider; protected RPC conformance
cases report themselves skipped when that provider is absent.

## API and ownership changes

Application protocol IDs remain portable. Winsock's pointer-sized `SOCKET` and
Windows `HANDLE` stay inside backend implementations; neither is squeezed into
a POSIX `int` descriptor. `evpl_doorbell_fd()` returns `-1` with `ENOTSUP` on
Windows. Applications that used that descriptor to wake a loop should use
`evpl_doorbell_signal()` instead. POSIX fd-event registration is unsupported
with IOCP; a Windows handle is not an fd-event argument.

Use [owned doorbell senders](../api/doorbells.md) for cross-thread producers.
Receiver removal revokes all senders, while sender references keep only their
control object alive. A sender does not keep the receiver, its loop, or an
application work queue alive. Existing `evpl_ring_doorbell(receiver)` remains
available when the caller synchronizes the receiver's lifetime externally.

Internally, submitted operations retain their bind until the final completion
has been consumed, including cancellation completions. Destruction stops new
work, cancels outstanding operations, drains completions, and only then frees
buffers and bind storage. Layered TLS and TCP_RDMA hold a child TCP bind under
the same ownership rules. Accepted connections have an explicit discard path;
queued accepts retain their listener binding until attachment or disposal.

Public sent-byte and sent-message counters use `uint64_t`, avoiding Windows'
32-bit `long`. Rebuild consumers against the new headers. Public functions have
explicit DLL import/export annotations. Release library-owned allocations with
the matching libevpl API; never pass them to the application's CRT `free()`.

## CI coverage

The build workflow runs MSVC Debug and Release on both x64 and ARM64 runners,
with native dependencies, model-corpus replay, and an installed-DLL consumer
smoke test. New jobs limit their GitHub token to `contents: read`. Existing
Linux and macOS build/test jobs and Linux static-analysis jobs remain required.
Use the workflow's `platform=windows` dispatch input for a focused development
run; the default runs all platforms.
