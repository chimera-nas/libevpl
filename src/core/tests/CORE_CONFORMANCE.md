<!--
SPDX-FileCopyrightText: 2026 Ben Jarvis

SPDX-License-Identifier: LGPL-2.1-only
-->

# Model-based core SDK conformance test

`core_conformance.c` + `quint/core.qnt` form a conformance suite for libevpl's
core API — the event loop, its timers, deferrals and doorbells, and the
connection lifecycle and data plane of a transport. A formal model written in
[Quint](https://quint-lang.org) generates the test programs; a converter turns
them into a C table; the test binary interprets them against a real `evpl`.

It is the same idea as the RPC2 suite in `src/rpc2/tests`, applied to a
different shape of problem — see [Programs, not cases](#programs-not-cases).

Quint and python3 are build dependencies for this test. CMake detects them;
when either is missing the test is not registered and the rest of the suite is
unaffected:

```
-- Core conformance test enabled (quint: /usr/local/bin/quint)
-- Core conformance test disabled (needs quint and python3 on PATH)
```

```
ctest -R libevpl/core/core_conformance --output-on-failure
ctest -R libevpl/core/quint_core_model --output-on-failure   # the model's own tests
```

Nothing generated is checked in. The ITF traces and the program table are build
artifacts under `<build>/src/core/tests/quint/`, regenerated whenever the model,
the converter or the generator script changes. Seeds are fixed, so a given
quint release always yields the same programs.

## Layout

| File | Role |
|---|---|
| `quint/core.qnt` | The model: the core API as a state machine, and what each operation leaves the library owing |
| `quint/itf_to_core_cases.py` | ITF traces → C program table |
| `quint/generate_core_cases.sh` | Build step: model → traces → table |
| `quint/check_core_models.sh` | The `quint_core_model` test: scenario tests + invariants |
| `<build>/…/quint/core_cases.h` | **Generated**, not checked in |
| `core_conformance.c` | The interpreter: object table, event log, obligation checker |

## Programs, not cases

`values.qnt`, `defects.qnt` and `client.qnt` are stateless case enumerators.
Each trace state is an independent test case and the trace is only a sampling
device, which works because an RPC exchange is memoryless.

Nothing about the core API is memoryless. A one-shot fires once and then must
not fire again; a deferral armed twice runs once; a doorbell retired from
inside its own callback must not be called back afterwards; bytes handed to
`evpl_send` before an `evpl_finish` must still arrive. Every one of those is a
statement about a *sequence*.

So here a trace is a **program** — a run of SDK operations against a freshly
created `evpl`, delimited by `OpReset` — and the C driver is an interpreter for
it. Programs are short (twelve operations) and numerous, because a failure at
step 380 of a 400-step program is not debuggable.

## The oracle

An asynchronous API has no return value to check against, so the oracle is the
event log. Each operation registers, arms or retires something; each
`OpQuiesce` runs the loop to the end of a window and holds the callbacks that
arrived against the obligations the model says were owed, in three directions:

1. **Every obligation is discharged.** A missing callback is a caller waiting
   forever — in production a hang, not a crash.
2. **Nothing arrives that was not owed.** This is what makes "the removed timer
   stopped firing" and "the one-shot did not refire" checkable at all: they are
   absences, and an absence is only observed by getting to the end of a window
   without it.
3. **Ordered callbacks arrive in that order**, where the model claims an order.

Rule 2 is why a quiesce always runs its whole window and never stops early at
satisfaction. An early exit observes no absence.

Obligations carry a multiplicity: *exactly* n, or *at least* n. The distinction
is not laziness — how many times a periodic timer fires in a window, and how
many callbacks a repeatedly-rung doorbell coalesces into, are genuinely
unspecified, and demanding a number there would be demanding a guarantee the
API does not make. `EvRecv` counts **bytes** rather than callbacks for the same
reason: how many notifications a stream is delivered in is the transport's
business; how many bytes come out of it is not.

Payload content is checked as well as length. The sender writes a
position-keyed pattern and the receiver checks it against its own stream
offset, so a payload delivered short, duplicated, reordered or at the wrong
offset fails on content — which is how the `evpl_recv` bug below was caught,
since it produced the right length every time.

## The virtual clock

Half of what this model states is about time: a 50ms timer must not fire inside
a 10ms window, and must fire in the window its deadline falls in. Checking that
against wall-clock time makes the test a test of the machine — and this suite
is meant to run in CI, on hosts with indeterminate load.

So it does not use wall-clock time at all. `evpl_global_config_set_virtual_clock()`
takes the library off the machine's clock and puts it on one the application
advances by hand with `evpl_virtual_clock_advance()`; the core wait stops
blocking, since with no way for time to move while the loop is inside it, a
wait for a deadline would be a wait for something that cannot happen.

The driver then advances the clock a millisecond at a time and drives the loop
after each tick. A deadline the model places at 50ms is a deadline the event
loop places at 50ms, exactly, under any load. Both sides reduce to integer
arithmetic: there is no guard band around a window edge, no tolerance for a
descheduled millisecond, and nothing to retry.

Advancing a tick at a time rather than in one jump per window matters. A single
jump would collapse every deadline in the window onto one instant, so two
timers due 40ms apart would come due together and their order would stop
meaning anything, and a periodic timer would fire once for the window instead
of throughout it.

What is left genuinely asynchronous is not time-dependent: `evpl_listener_create()`
runs the accept path on a thread of its own, so a connection's arrival is a
hand-off between threads. The driver waits for obligations that have not
arrived yet by driving the loop, which costs nothing when they are prompt and
weakens nothing — a callback that *must* arrive is waited for, while a callback
that must *not* arrive is still decided by the clock, which does not move.

The result is a suite that runs in about 60ms and gives the same answer every
time. On a real clock the same programs took 14 seconds and disagreed with
themselves about once in five runs.

## Coverage

The transport is a per-program dimension, over four protocols:

| Transport | Lifecycle | Owes |
|---|---|---|
| `EVPL_STREAM_INPROC` | listen / connect | bytes |
| `EVPL_DATAGRAM_INPROC` | listen / connect | messages |
| `EVPL_STREAM_SOCKET_TCP` | listen / connect | bytes |
| `EVPL_STREAM_SOCKET_UNIX` | listen / connect | bytes |
| `EVPL_DATAGRAM_SOCKET_UDP` | bind pair | messages |

The in-process transports came first because they make a whole connection
lifecycle reachable from one thread and one `evpl`: both ends are in this
process, so the model can state what *both* of them are owed, with no port to
collide on and nothing for a crash to leave behind. TCP and AF_UNIX then cost almost nothing, being the same lifecycle with a
different address -- a port for one, a filesystem path for the other. The
driver supplies the path (under `EVPL_TEST_SOCKET_DIR`, falling back rather
than truncating past `sun_path`'s 108 bytes); libevpl owns it from bind
onwards, removing it at teardown and stepping over a stale predecessor.

UDP is the odd one and needs a lifecycle of its own: it is bind-only —
`connected = 0`, no `.listen`, no `.connect` — so there is no handshake, no
CONNECTED, and each end names the other by endpoint on every send. That is
modelled as a single `OpBindPair`, because an unconnected pair has no
observable intermediate state to be in: it exists as soon as both ends do.

The socket transports bind real ports, so the test is registered like the other
networked ones — a network namespace where CAP_NET_ADMIN allows, and the shared
`evpl_net` lock where it does not. That is a change from the inproc-only
version, which ran fully in parallel.

| Area | Operations |
|---|---|
| Timers | one-shot, periodic, one-shot re-armed from its own callback, removal while armed, removal after firing; four slots, so the heap sifts |
| Deferrals | arm, arm twice before the loop runs, re-arm from inside the callback, cancel while armed, cancel while idle |
| Doorbells | add, ring, ring twice, remove, remove from inside the doorbell's own callback |
| Poll mode | add, remove, report activity, pin and unpin; the enter/exit pair bracketing when the loop was spinning |
| Loop hooks | install and clear; each of `iteration_end`, `pre_wait` and `post_wait` running while installed and none after |
| Connections | listen, stop listening, connect, close, finish, slot reuse after teardown, over `EVPL_STREAM_INPROC` and `EVPL_DATAGRAM_INPROC` alike |
| Send notifications | opt in per end, and every byte queued afterwards reported back — the flag being read at flush, not at send |
| Message boundaries | a datagram owes exactly one delivery per send; a stream owes the bytes and says nothing about how they are divided. Coalescing or splitting keeps the byte total and fails the message count |
| Data plane | four payload size classes across five send modes (`evpl_send`, `evpl_sendv` with and without `EVPL_SEND_FLAG_TAKE_REF`, `evpl_iovec_reserve`+`commit`, and `evpl_iovec_alloc_global`) and four drain modes (`evpl_recv`, `evpl_recvv`, `evpl_peek`+`evpl_consume`, `evpl_peekv`+`evpl_consume`), both directions independently |

The send and drain modes are where the iovec ownership rules get exercised:
`evpl_sendv` without `TAKE_REF` clones and the caller must release its own,
with it the references are handed over and releasing them would be a double
free; `evpl_recvv` clones and the receiver must release, while `evpl_peekv`
borrows and the receiver must not. All four are asymmetries the headers do not
state, and `evpl_allocator_destroy`'s leak check fails the run either way
round.

### What that reaches

From `make coverage COVERAGE_TESTS=core_conformance` — this test alone, nothing
else in the suite. Function coverage is the number to watch: lines and branches
say how thoroughly a path is walked, but a function at 0% is an entry point
nothing calls at all.

**Functions: 202 of 238 (84.9%)**, counting everything in the core modules
except the global-config setters for subsystems this test has no business in
(rdmacm, xlio, vfio, libaio, io_uring, tls, http). Lines 73.5%, branches 54.7%
over the same set.

| `doorbell.c` | 100.0% | 66.7% |
| `deferral.c` | 100.0% | 100.0% |
| `timer.c` | 95.1% | 88.0% |
| `protocol.c` | 93.3% | 66.7% |
| `poll.c` | 92.0% | 50.0% |
| `iovec.c` | 91.3% | 81.0% |
| `epoll.c` | 89.7% | 72.2% |
| `send.c` | 89.5% | 68.8% |
| `evpl.c` | 88.7% | 76.5% |
| `address.c` | 87.5% | 75.0% |
| `socket/udp.c` | 78.5% | 51.6% |
| `inproc/inproc.c` | 76.9% | 52.7% |
| `listen.c` | 76.3% | 50.6% |
| `endpoint.c` | 75.8% | 56.7% |
| `select.c` | 75.6% | 64.3% |
| `bind.c` | 74.2% | 43.7% |
| `socket/tcp.c` | 71.5% | 50.0% |
| `recv.c` | 67.4% | 56.0% |
| `socket/unix_stream.c` | 66.0% | 25.9% |
| **Together** | **73.5%** | **54.7%** |

Fourteen modules have every function called, including `endpoint.c`,
`socket/tcp.c`, `iovec.c` and `send.c`. What is left is a short list with no
common theme, and most of it is error handling that needs injection rather
than a new operation:

- **`bind.c`** — `evpl_bind_abort`, reached only when a listen fails after the
  bind has been prepared.
- **`socket/udp.c`** — `evpl_socket_udp_error`, an error path.
- **`socket/unix_stream.c`** — `evpl_socket_unix_clear_stale`, which runs only
  when a socket file is left behind by a crashed predecessor. Reachable by
  creating one deliberately, which is an injection rather than an op.
- **`thread.c`** — `evpl_threadpool_create`/`_destroy`; threads are not
  modelled.
- **`memory.c`**, **`core.c`**, **`allocator.c`** — `evpl_malloc`/`evpl_realloc`,
  `evpl_core_mech_name`, and slab-allocation internals.
- **`config.c`** — tuning knobs this test has no reason to set.
- **`evpl.c`** — the two `evpl_rpc2_queue_depth_*` helpers, which live here but
  belong to rpc2.

Two program shapes exist in the generator purely to keep these numbers honest.
Half the programs open with a prologue that leaves a live connection and sends
on it, and a quarter open by arming three timers — because a uniform random
walk over twenty-eight enabled actions builds neither, and unlike a missing
operation (which fails generation) a heap that never sifts just quietly stops
being tested. Adding the timer prologue moved `evpl_timer_heap_down` from 64%
to 92%; adding the send to the transport prologue took payload bytes verified
from 131 KB to 1.1 MB.

## Divergences found, and fixed

Both were found by the first two runs of the suite, and both are fixed, so any
recurrence fails the test.

| What the API promises | What libevpl did | Fix |
|---|---|---|
| `evpl_add_oneshot_timer` fires "once, `delay_us` from now" | fired **before** its deadline whenever the thread's `wait_ms` was shorter than the time remaining — and a periodic timer in that state re-armed and re-fired without bound inside a single `evpl_continue`, spinning the loop | the timer scan now breaks unconditionally once the head of the heap is not yet due, and only the *wait* is shortened |
| `evpl_recv` fills the caller's buffer with the bytes it reports | copied every buffered iovec to the **start** of the buffer, so a receive spanning more than one landed the last one's bytes at offset zero and returned the correct length | the destination pointer is advanced by each chunk |
| `evpl_thread_config_set_poll_mode()` makes the thread spin | the spin window was measured from process init rather than from thread creation, so any thread created more than `spin_ns` after startup never entered poll mode at all unless something happened to call `evpl_activity()` | `evpl_create` starts the spin window |
| `evpl_iovec_alloc`/`evpl_iovec_reserve` place a request across as many buffers as it takes | when a **fresh** buffer was still too small they discarded it and asked for another of the same size — forever. Any request larger than one buffer was an unbounded loop, and the multi-iovec code below it was unreachable | the discard is now conditional on the buffer having been used; a fresh one that cannot hold the rest is filled and the remainder placed in the next |
| `evpl_get_hf_monotonic_time()` is declared in `evpl_core.h` | missing `SYMBOL_EXPORT`, so with `-fvisibility=hidden` it was not in the library's dynamic symbol table: any consumer calling it failed to link | exported |
| `evpl_config()` is declared in `evpl_core.h` | no such function exists. The implementation is `evpl_get_config(void)` — a different name *and* a different signature (the header promises a per-`evpl` accessor, the code returns the global config) | the declaration is removed; nothing could have been calling it |

The first of those was only reachable at all because this test now configures a
32 KiB buffer rather than the 2 MiB default — which it does precisely so that
payloads span several iovecs. At the default, every allocation fits in one and
the loop never spins. It is also why the buffer is 32 KiB and not smaller:
`evpl_send` bounces through `evpl_iovec_alloc` with room for four iovecs and
aborts if the payload needs more, so a buffer under a quarter of the largest
payload class turns `evpl_send` into an abort. That ceiling is worth removing
separately.

The timer one was invisible to the rest of the suite because the default
`wait_ms` is -1, which takes the one branch that behaved correctly; any bounded
wait took the other. The `evpl_recv` one was invisible because every existing
test compares byte *counts* — `bulk_stream.c` and friends would pass on
arbitrarily corrupt data — and because whether a receive spans two iovecs
depends on how the payload happened to arrive. It reproduced under the `select`
mechanism and not under `epoll`.

## Open, and deliberately constrained

**`evpl_sendtoep`/`evpl_sendtoepv` leak an address reference on every
transport but UDP.** They resolve the endpoint for a +1 reference and hand it
to `evpl_sendto`/`evpl_sendtov`, which keep the bare pointer in the queued
dgram. Whether anyone gives it back is then up to the transport: `udp.c` and
`rdmacm.c` release `dgram->addr` when the send completes, and nothing else
does — not inproc, not the stream sockets.

So the same public call is balanced on one transport and leaks on the others,
and the model has to know which: it generates the endpoint-addressed sends
only where they are the *only* option, which is UDP, and uses the connected
forms everywhere else. That is not a workaround for a test problem — an
unconnected bind genuinely has no peer to send to and a connected one has no
endpoint to name — but it is why the constraint is stated as a precondition
rather than left to chance.

Releasing the reference in the wrapper is *not* the fix, and this suite is how
that was established: with the release added, inproc came clean and the UDP
tests turned into use-after-free, because an INET endpoint's cached address is
re-resolved on `resolve_timeout_ms` and the old one freed while a queued dgram
still points at it. The coherent fix is for `evpl_sendtov` to take a reference
of its own and every transport to release it on completion — a change across
all of them, including the two (rdmacm, xlio) that cannot be exercised here.

**`buffer_size` must be at least `max_datagram_size`, and nothing enforces it.**
A datagram receive buffer is one contiguous iovec, so it cannot be assembled
from several buffers. Configure a buffer smaller than the maximum datagram and
`evpl_iovec_alloc_datagram` quietly hands back a short one; datagrams then stop
arriving, with no error anywhere. Before the `evpl_iovec_alloc` fix above it
did not even do that — it looped forever. This test sets
`max_datagram_size` to half the buffer size for exactly that reason, and
libevpl should reject the combination at `evpl_init` instead.

**Two smaller behaviours are modelled rather than fixed**, because both are
defensible and changing them would be a behaviour change on existing callers:

- An activity reported while no poll is registered is remembered indefinitely
  and brings the loop into poll mode the moment one is added, however long
  afterwards. `evpl_continue` only syncs its activity counter inside the
  `num_poll > 0` guard.
- `evpl_remove_poll` leaves the loop's `poll_mode` flag set, so removing the
  last poll emits no exit callback, and adding one again afterwards emits no
  enter callback. The model never generates a re-add rather than encoding it.

## What the suite does not cover

- **TLS, io_uring, XLIO and RDMA transports**, which need build options or
  hardware. `EVPL_DATAGRAM_TCP_RDMA` is the interesting one, since it needs
  neither and carries the RPC-over-RDMA framing.
- **Abstract-namespace AF_UNIX sockets** (`@name`), which are Linux-only and
  have no filesystem object at all.
- **The segment callback.** `evpl_segment_callback_t` documents three return
  cases including one that must close the connection; none is exercised here.
- **iovec ownership.** `evpl_iovec_alloc`/`clone`/`move`/`release`, the
  LOCAL/SHARED/GLOBAL flags and `EVPL_SEND_FLAG_TAKE_REF` are the other half of
  the core API and are only touched incidentally, through `evpl_recvv`'s
  cloning. A refcount-ledger model with `evpl_allocator_destroy`'s leak check
  and the allocator gauges from `evpl_metrics_scrape()` as its oracles is the
  obvious companion.
- **The loop hooks** (`evpl_set_loop_hooks`), which have no coverage at all.
- **Threads and thread pools**, and doorbells rung from a thread other than the
  one that added them — which is what a doorbell is actually for.
- **Whether a listener may be torn down under live connections.** The model
  deliberately does not generate it: the headers do not say, and a model may
  not invent an answer it would then report libevpl for failing.

## Regenerating

CMake runs `quint/generate_core_cases.sh` as a build step, so nothing needs
doing by hand. To inspect the traces, run it the same way:

```sh
quint/generate_core_cases.sh "$(which quint)" python3 quint /tmp/coreq /tmp/coreq/core_cases.h
```

The converter fails generation if any operation the model declares is never
reached by a generated program. A trace is a sample, so a seed bump or a quint
release that samples differently could otherwise drop an operation entirely and
leave a smaller suite that still looks green.

That check is also what forced the model's program shape: half the programs
open with a three-operation prologue that leaves a live connection, because a
uniform random walk over the operation set almost never builds one — `send`,
`close` and `finish` all need a connection that is up, which takes `listen`,
`connect` and a quiesce to reach, and the odds of drawing that sequence out of
seventeen enabled actions inside a twelve-operation program are negligible.
