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

Install Visual Studio 2022 or newer (or its Build Tools) with the Desktop development
with C++ workload, a Windows SDK, and CMake. Select the ARM64 compiler tools
when building on Windows ARM64. Use a recent MSVC toolset supporting C11 atomics;
the build enables `/experimental:c11atomics`.

Clone recursively, then run these commands from the repository in PowerShell.
The vcpkg manifest builds dependencies with MSVC, including nghttp2, protobuf-c, and SQLite.
OpenSSL is neither built nor linked on Windows. PowerShell 7 (`pwsh`) generates
the test certificates using .NET cryptography. The pinned vcpkg revision matches CI.

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
| TLS | Windows Schannel over the native TCP transport |
| TCP_RDMA | Existing software framing protocol over the portable TCP transport |
| In-process messaging | Existing datagram and stream protocols with native synchronization |
| Doorbells | IOCP packets with independently owned, revocable sender handles |
| Ordinary file I/O | PREAD service thread using Windows file handles and explicit offsets |
| HTTP and RPC | HTTP/1.x, HTTP/2, and ONC RPC2 over supported transports |
| Observability | Prometheus and OpenTelemetry, including optional SQLite support |

Windows TLS uses Schannel (SSPI), CNG key management, and Crypt32 certificate
APIs. TLS 1.2 and TLS 1.3 are available on Windows 11 and Server 2022 or later.
ALPN supports HTTP/2. Windows manages the enabled cipher suites; a non-null
OpenSSL cipher-list setting is rejected when credentials are created, rather
than silently ignored. The kTLS setting has no effect on Windows.

The existing certificate/key file settings accept PEM X.509 certificates and
unencrypted PKCS#8 private keys (RSA or EC), plus traditional PKCS#1 RSA PEM
keys. The leaf must match the private key. Schannel constructs the chain it
sends using the Windows intermediate-certificate cache; supplying a PEM bundle
alone does not install intermediates in that cache. Encrypted PEM and traditional SEC1 EC keys are not supported;
use an unencrypted PKCS#8 key with appropriate filesystem access restrictions.
Without configured certificate/key files, libevpl generates a self-signed
certificate and RSA key through Windows APIs. Schannel requires named CNG keys
on some supported Windows versions, so generated/imported private keys use
randomly named, user-scoped CNG containers that are deleted at library cleanup.
A forcibly terminated process can leave a container behind. Certificates are
not installed in the system trust store.

Peer verification checks the certificate chain, validity, and TLS usage. A
configured PEM CA bundle supplies an exclusive trust store; otherwise the
Windows trust store is used. Server-side peer verification requires a client
certificate. Configured certificate/key files also supply the client identity
on Windows. Chain building uses local/supplied intermediates and does not fetch
certificates or revocation information over the network from the event loop.
As with the existing OpenSSL backend, the current API has no expected-peer-name
setting and does not provide hostname verification.

Linux and macOS retain OpenSSL and their existing socket TLS/kTLS path. The
shared byte-stream transport can be tested there with
`-DEVPL_TLS_MEMORY_BIO=ON`; only the crypto engine changes between OpenSSL and
Schannel.

The ordinary-file backend accepts UTF-8 paths and converts them to UTF-16 for
Windows. It supports 64-bit offsets; tests cover Unicode filenames and a sparse
file beyond 4 GiB. It currently uses the file service thread rather than
submitting file operations directly to IOCP.

AF_UNIX transports, POSIX file-descriptor readiness events, retained-iovec stack
profiling, the libfabric backend, and Linux-specific accelerated backends
(io_uring, libaio, VFIO, RDMA CM/verbs, XLIO) are not implemented on Windows. Selecting an unavailable
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

Windows CI additionally checks RSA PKCS#1/PKCS#8 and EC PKCS#8 identities,
mutual certificate authentication, ALPN, and rejection of untrusted and expired
certificates, plus TLS 1.2/1.3 interoperability with .NET SslStream. It checks
that normal process exit deletes temporary CNG key containers, and fails if
the dependency tree installs OpenSSL or the build contains OpenSSL DLLs. ARM64 CI uses Visual Studio 2026; select the corresponding
CMake generator (`Visual Studio 18 2026`) when using that installation locally.

For backend development, `platform=tls` skips model-corpus generation and runs
the native TLS tests plus the installed-DLL consumer on all four MSVC jobs.
Pull requests still run the complete matrix and model-conformance suites.
