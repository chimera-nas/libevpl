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
Progress is currently restricted to I/O: timers and coalescing callbacks
require additional observation state before arbitrary interleavings can be
modeled precisely. Send notifications are enabled only before an endpoint's
first send. Before opt-in, peer receipt cannot prove local send completion
(particularly with RDMA), so quiesce retains those unobserved sends instead of
allowing an ambiguous late opt-in. A replacement connection resets this state.
Connection acceptance is still limited
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

## Transport backpressure and cancellation

`backpressure.qnt` controls an independent TCP peer: connect, queue, hold reads,
consume a prefix, drain, finish, local close, and peer reset. The same generated
programs run over socket TCP, TLS (software and automatic kTLS selection), SPDK
TCP (polling and interrupt modes), and io_uring TCP in the KVM storage job.
The peer uses POSIX sockets and OpenSSL directly; an evpl receiver would continue
reading into its own buffers and would not reliably apply transport pressure.

A burst contains 4096 nonuniform 4093-byte vectors, exceeding ordinary socket
buffering and SPDK's in-flight request limit. Up to two bursts can be queued.
Reads advance by quarter-burst prefixes. `Hold` pumps the sender while leaving
the peer unread and requires an outstanding suffix. `Drain` checks every byte
in order and the exact cumulative send-notification byte count. Notification
batching and the amount completed during a hold remain implementation choices.
`Finish` must eventually deliver the entire queue before disconnecting;
cancellation may discard the unobserved suffix. Both local close and peer reset
are tested after a delivered prefix, including reset while finish is pending.

Each buffer has an independent reference ledger. Borrowed application references
must survive completion and cancellation with their contents intact; transferred
references must be released exactly once. Connections are reopened after
cancellation. Six mandatory scenarios and four seeded random traces are replayed;
the generator rejects a corpus missing the required pressure/partial-delivery
outcomes. CI also requires execution of `evpl_spdk_sock_check_active`, so merely
registering a pressure replay cannot hide loss of SPDK queue-pressure coverage.
This model tests bounded single-connection schedules, not exhaustive network
failure behavior or a precise relationship between callbacks and wire delivery.

## RDMA operations and UNIX path ownership

`rdma.qnt` models batches of direct TCP-RDMA reads and writes, successful and
invalid accesses, connection reuse, and cancellation with requests outstanding.
The adapter progresses only the initiator after submission, holding the peer
at an event-loop boundary until the model selects completion or disconnect.
This makes pending-operation pressure deterministic without fault injection.
Bursts of 15, 16, 17 and 33 operations exercise capacity boundaries and growth
after earlier completions have advanced the ring. The oracle checks each
callback once, its status, nonuniform data across split iovecs, untouched guard
bytes, and the release of library buffer references. Both write ownership modes
are exercised. The model can also request close from the Nth completion
callback, preserving a completed prefix while cancelling the outstanding
suffix. Mandatory scenarios cover successful and invalid accesses, both write
ownership modes, and first/middle/penultimate completion boundaries in wrapped and
grown rings. The adapter checks each operation's status and data separately,
including that cancellation neither revisits completed callbacks nor overwrites
uncompleted read buffers. A cancelled write may already have modified remote
memory before its acknowledgement is discarded. This model does not yet explore
overlapping mixed read/write dependencies.

`registration.qnt` separately models registration, reuse, revocation, bounds
validation, and growth while old keys remain live or revoked. Its adapter uses
the production registration-table component with small explicit extents.
Public iovec releases do not revoke individual regions: the allocator registers
whole slabs and retains their registrations until shutdown. Consequently, a
transport test cannot treat the end of an iovec as the registration boundary.

`unix_path.qnt` models absent paths, stale sockets, foreign live listeners,
regular files, listen attempts, crashes, and restarts. Failed listen attempts
must preserve the existing inode and file contents; foreign listeners must
remain reachable, while successful listener teardown must remove its own path.

These models replay four seeded random walks plus explicit Quint scenarios on
each native mechanism. Generation requires the relevant success/error outcomes,
and Linux coverage CI requires the new replays and previously untouched growth,
error, stale-path, and bind-abort functions to execute. No RDMA hardware or KVM
is needed for these replays.

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

### Datagram boundaries and wildcard listeners

`datagram_boundary.qnt` generates fragmentation, ownership, pause/drain, local
close, peer close, reconnect, and cancellation-from-receive-callback sequences.
Both libfabric MSG/TCP and RDM/RxM adapters replay the same table. Each burst
contains 256 messages. Shapes use 1, 4, 5, or 65 nonuniform fragments; the large
shape contains roughly 32 KiB per message and exceeds libevpl's maximum provider
iovec limit. Bursts exceed the configured 128-entry transmit queue. The receiver
has four posted receive buffers and is progressed independently of the sender.

The oracle checks message identities, exact boundaries and bytes, absence of
repeated deliveries, cumulative send bytes/messages on drain, unchanged guard
bytes, and one retained application buffer reference after completion or close.
Borrowed and transferred fragment views both retain a separate application view
for inspection. Cancellation occurs on the first or seventh receive callback
while the sender still has an outstanding suffix; deliveries already in flight
are permitted, but no callback may use a disconnected endpoint. Six mandatory
scenarios and four seeded traces include reuse after cancellation.

The listener model additionally runs with `0.0.0.0` listeners and loopback dial
addresses, exercising wildcard device selection and accepted-connection address
matching, including detach with an accept queued for a worker. Datagram replays
also bind/listen on the wildcard address. CI requires the three address-selection
helpers, the completion-queue error handler, and the listener's queued-accept
discard callback to execute.

The queued-accept discard scenario also guards asynchronous accept teardown.
On libfabric 1.17, immediately closing an endpoint after `fi_accept` could drop
the accept response and leave the client waiting indefinitely. Libevpl retains
the endpoint until the accept succeeds or fails, then completes shutdown and
close. The same scenario runs on older and newer libfabric CI images.

RDM `Connect` includes a one-byte adapter readiness exchange, with both receive
and send completion checked before model counters begin. This establishes RxM's
lazy underlying connection before exploring application-transfer cancellation.
Without it, closing during setup exposed provider allocations leaking from
inside libfabric in ASan. The RDM boundary variants set
`FI_OFI_RXM_BUFFER_SIZE=65536`, keeping the same large messages in RxM's eager
path. With the provider's default buffer size, cancelling these transfers
reproduced a null-PC crash inside libfabric 2.1's `fi_close`. Neither failure is
suppressed: ASan and leak checking remain enabled. Cancellation during lazy
connection setup and pending non-eager RxM transfers remain provider limitations
of these replays. The knob is documented in the upstream
[RxM manual](https://github.com/ofiwg/libfabric/blob/main/man/fi_rxm.7.md).

On macOS, the RDM boundary adapter binds explicitly to `127.0.0.1`: Homebrew
libfabric 2.7 crashes inside `rxm_getinfo` when querying the wildcard source
address, before a transfer starts. The complete RDM replay remains enabled for
both kqueue and select. MSG datagrams and listeners still use wildcard addresses
on macOS, and Linux additionally exercises the wildcard RDM bind.

## Guest storage coverage

`scripts/run_mbt_vm.sh` boots the existing Linux KVM guest with Soft-RoCE and two
disposable QEMU NVMe devices. One stays on the kernel NVMe driver for libaio,
io_uring and direct NVMe `uring_cmd`; the other is bound to vfio-pci behind the
emulated Intel IOMMU. Device serials and PCI addresses are checked before binding. The container reuses the
native coverage build and runs each storage adapter under epoll and select.
The ordinary RDMA regressions and RPC model harness use 64 MiB slabs and 256 receive queue entries
so memory registration does not pin production-sized 1 GiB slabs in the guest.
Payload sizes and the production defaults remain unchanged.
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

## HTTP/2 integration coverage

`http2.qnt` models three independent streams sharing a connection. It is
separate from the HTTP/1 text-framing model: nghttp2 owns framing and HPACK,
while these traces test libevpl's request lifecycle, callback mapping and iovec
ownership. Both client and server roles run against a controlled nghttp2 peer,
through the public HTTP API on epoll/select, over h2c and TLS with ALPN.

Mandatory model scenarios supplement seeded walks. They cover multiplexed and
reused stream slots, queued requests, fixed and deferred streaming bodies,
empty messages, trailers, interim responses, fragmented delivery, a zero stream
window followed by resumption or cancellation, resets, GOAWAY and connection
loss. Payload patterns distinguish each stream and direction. The adapter
checks exact body contents, header/trailer mapping, protocol selection and one
terminal callback per request; cancellation must preserve sibling streams.

The model does not duplicate HPACK, enumerate HTTP/2 frame errors or prove
nghttp2's protocol implementation. Allocation failure and exhaustive malformed
frame combinations remain outside this suite. CI requires the codec to be
compiled and the integration's submission, data, trailer and teardown paths to
execute, rather than counting the nghttp2 library itself.
