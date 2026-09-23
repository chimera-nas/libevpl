<!-- SPDX-FileCopyrightText: 2026 Ben Jarvis -->
<!-- SPDX-License-Identifier: LGPL-2.1-only -->

# Core model testing

`src/core/tests/quint/core.qnt` describes API state and callback obligations.
`core_generation.qnt` selects legal transitions and controls sampling budgets.
`core_conformance.c` interprets the resulting traces using backend adapters.
The HTTP and RPC suites still include generated message-conformance taxonomies;
this refactor does not turn those into stateful session models.

The core generator has no operation-position prologues. Stream, connected
message, connectionless datagram, block, event, mixed, and native-poll profiles
focus sampling on different action families. Interior steps are selected from
currently legal transitions; only reset and the final observation boundary are
prescribed. Each program has 64 operations. Fixed seeds make CI reproducible.

Transport names and device selection belong to adapters. The model describes
stream/message/datagram contracts and accepts a datagram limit. Traces carry
concrete byte lengths and expected totals, so adapters cannot silently shrink
payloads or rewrite expectations. A bounded datagram profile runs on every
compatible adapter, including UDP and RDMA UD. The larger profile additionally
exercises adapters that support its limit. Storage operations share one oracle
across pread, SPDK, libaio, io_uring, io_uring_nvme and VFIO; an external device
supplies the same 64 KiB modeled region window as a temporary file.

`OpProgress` pumps one iteration without advancing virtual time or asserting
which I/O completed. Subsequent operations can add work before `OpQuiesce`
checks the cumulative obligations. This explores submission/completion
interleavings without demanding a particular backend's completion order.
Progress is currently restricted to I/O: timers, coalescing callbacks and
notification opt-in require additional observation state before arbitrary
interleavings can be modeled precisely. Connection acceptance is still limited
to one outstanding attempt because the harness attributes accepted endpoints
by the initiating slot. These are explicit exploration limits, not API rules.

Native poll timing has a separate profile with no provider I/O. Optional
backends execute all portable profiles rather than discarding mixed programs
that happen to include an incompatible poll operation. Inproc and Unix socket
adapters retain coverage alongside the default TCP adapter.

The converter requires witnesses for bursts, bidirectional sends,
send/progress/send, finish with queued data, concurrent work on different block
queues, cross-queue reads, reads of known data, queue reopening, and connection
reuse. The replay checks that each witness occurred in a passing program after
adapter filtering and prints the program counts. These are behavioral coverage
checks, not an exhaustive state-space claim. Ordinary line/branch coverage is
reported separately.

## Libfabric providers

MSG replays use the TCP provider; a separate RDM replay uses `tcp;ofi_rxm`.
Both execute every portable profile, with their selected transport replacing
only the corresponding adapter. RDM is also replayed on the SPDK core.
Set `EVPL_MBT_LIBFABRIC_RDM_PROVIDER=tcp` to reproduce native TCP RDM defects.

The generated bidirectional sequence reproduces a simultaneous-connect loop
in native TCP RDM in libfabric 2.1 (program 62 with the pinned corpus). The same
trace completes on 2.3. Sanitized 2.1/2.3 replays also expose an upstream
8-byte-per-rejection leak: `xnet_ep_disable` duplicates the CM rejection data,
while `xnet_handle_event_list` / `xnet_close_conn` free the internal event
without freeing that data. CI uses RxM to preserve behavioral coverage without
suppressing leaks or changing legal operations. Native TCP RDM remains an
explicitly reproducible provider limitation; this PR does not fix libfabric.

## Guest storage coverage

`scripts/run_mbt_vm.sh` boots the existing Linux KVM guest with Soft-RoCE and two
disposable QEMU NVMe devices. One stays on the kernel NVMe driver for libaio,
io_uring and direct NVMe `uring_cmd`; the other is bound to vfio-pci behind the
emulated Intel IOMMU. Device serials and PCI addresses are checked before binding. The container reuses the
native coverage build and runs each storage adapter under epoll and select.
Only generated model replays enter the merged coverage report. Per-backend
profiles and execution checks prevent a missing device or empty suite from
silently reporting success.

Local native replays need no NVMe hardware. Set `EVPL_STORAGE_TESTS=ON` to
register the guest storage variants. `EVPL_TEST_BLOCK_URI` supplies an explicit
test device; without it, file-capable adapters use temporary files. VFIO needs
a PCI address already bound to vfio-pci. `io_uring_nvme` needs a whole NVMe
namespace block-device URI (including by-id aliases), its matching `/dev/ng*`
character device, and mounted sysfs. The block node supplies geometry; the
character node submits NVMe read/write and flush commands. Partition URIs are
rejected because passthrough offsets address the whole namespace. The CI image
pins liburing 2.14 so this backend is compiled and required, rather than omitted
by feature detection. These replays write their modeled region window, so guest CI uses only newly created disposable images.

## TLS stream coverage

The core state-machine programs and RPC server conformance cases also run over
`STREAM_SOCKET_TLS`, using the same operations, payloads and callback oracles.
The core replay selects software TLS and the default kTLS-enabled configuration
on each native mechanism; kTLS is permitted, not assumed available. Software
TLS additionally runs on the SPDK core, and RPC runs on SPDK in polling and
interrupt modes. Windows exercises the memory-BIO TLS implementation.

These adapters use generated self-signed certificates with peer verification
disabled, matching the existing transport tests. They cover successful
handshakes, data transfer, framing, notifications and connection lifecycle;
they do not claim coverage of authentication policy or malformed TLS records.
HTTP and raw RPC-client peers remain plaintext until their adapters can speak
TLS. Coverage CI requires the TLS replay registrations and execution in both
OpenSSL setup and a TLS transport implementation; their profiles enter the
existing model-only coverage union.
