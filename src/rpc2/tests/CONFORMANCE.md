<!--
SPDX-FileCopyrightText: 2026 Ben Jarvis

SPDX-License-Identifier: LGPL-2.1-only
-->

# Model-based XDR/RPC2 conformance test

`conformance.x` + `conformance.c` + `quint/` form a conformance suite for
xdrzcc's generated code and libevpl's RPC2 layer. Formal models written in
[Quint](https://quint-lang.org) enumerate the test cases; a generator turns
them into a C table; the test binary replays them against a real RPC2 server.

The cases are generated from the models at build time, so quint and python3
are build dependencies for this test. CMake detects them; when either is
missing the test is simply not registered and the rest of the suite is
unaffected:

```
-- RPC2 conformance test enabled (quint: /usr/local/bin/quint)
-- RPC2 conformance test disabled (needs quint and python3 on PATH)
```

Pass `-DQUINT_EXECUTABLE=OFF` to force it off. The devcontainer installs a
pinned quint, so it is enabled there.

```
ctest -R libevpl/rpc2/conformance --output-on-failure
ctest -R libevpl/rpc2/quint_model --output-on-failure   # the models' own tests
```

Nothing generated is checked in. The ITF traces and the case table are build
artifacts under `<build>/src/rpc2/tests/quint/`, regenerated whenever a model,
the converter or the generator script changes. Seeds are fixed, so a given
quint release always yields the same cases; a different release may sample
differently, which is why the devcontainer pins one.

## Layout

| File | Role |
|---|---|
| `conformance.x` | An RPC program instantiating every XDR construct xdrzcc supports, in every container shape |
| `quint/values.qnt` | Boundary-value classes per type; the positive matrix |
| `quint/defects.qnt` | Wire-defect taxonomy and the outcome each RFC requires |
| `quint/itf_to_cases.py` | ITF trace → C case table |
| `quint/generate_cases.sh` | Build step: models → traces → case table |
| `quint/check_models.sh` | The `quint_model` test: scenario tests + invariants |
| `<build>/…/quint/conformance_cases.h` | **Generated**, not checked in |
| `conformance.c` | The driver: server, round-trip client, raw-socket defect injector |

## The two phases

**Values** call each procedure through the generated libevpl client with
boundary values (`INT32_MIN`, `UINT32_MAX`, NaN, `-0.0`, empty/one/unaligned/
at-bound lengths, absent/present optionals, list depths) and compare the reply
to the request. Every handler echoes, so round-trip identity is the oracle and
no model prediction is needed. Floats are compared bitwise, since NaN is not
equal to itself and `-0.0` must not compare equal to `0.0`.

**Defects** are written straight onto a TCP socket, because libevpl's own
client cannot express them: it hardcodes `rpcvers = 2`, derives the program and
procedure from the program struct, and never emits more than one record
fragment. Each reply is classified and compared against what RFC 5531 / RFC
4506 require.

### Checks that sit outside the two models

Two things the harnesses assert are neither an XDR value class nor a wire
defect, so they are held as small explicit tables in the drivers rather than
being bent into a model that is not about them:

- **Connection notifications** (`conformance.c`). The rpc2 thread's notify
  callback is how an application learns that a connection appeared, and that
  one it holds a pointer to has been freed. The driver registers one and checks
  the notifications are coherent rather than merely present: every connection
  is announced before it is reported gone and only once each, accepts match the
  connections the driver actually dialled, and the connection reported as
  unaccepted is the one `evpl_rpc2_client_connect` returned.
- **Outbound AUTH_SYS credentials** (`conformance_client.c`). The encode
  direction, checked against the RFC's own byte layout rather than against
  libevpl's decoder — sending the credential to a real server and asking what
  it decoded would test the two halves against each other, where a pair of
  mutually consistent bugs passes. The machine names cover all four XDR padding
  residues and the group lists cover both ends of the declared `gids<16>`.

`defects.qnt` deliberately encodes the **specification**, not libevpl's current
behaviour. Encoding the latter would freeze today's bugs into the spec and
guarantee the suite never finds them. Divergences are therefore expected; each
reviewed one is listed in `known_divergences[]` in `conformance.c` with a note,
which keeps the suite green while leaving the gaps visible and counted. An
unlisted divergence fails the test.

## Divergences found, and fixed

The divergences below have all been fixed, so any recurrence fails the test.
The table records what was wrong, since the fixes are spread across three
repositories.  For the ones still outstanding, see "Divergences currently
recorded".

| What the RFC requires | What libevpl did | Fix |
|---|---|---|
| `PROG_MISMATCH` carries the supported version range | 8 bytes of uninitialised stack (observed `[64860, 2820603906]`) | `rpc2.c` now records the exported range on the request and fills `mismatch_info` |
| Unexported program → `PROG_UNAVAIL` | `PROG_MISMATCH` | the program scan now distinguishes "not exported" from "exported at other versions", and reports the real range for the latter |
| Procedure 0 is NULL and always succeeds (RFC 5531 §11.1) | `PROC_UNAVAIL` | xdrzcc generates a NULL procedure unless the `.x` declares proc 0 itself |
| Undecodable credential → `AUTH_ERROR` | connection closed, no reply | the xid and mtype sit at fixed offsets ahead of the credential, so a CALL whose header fails to decode is now answered `AUTH_BADCRED` |
| Oversized record mark → connection closed | stalled, buffering indefinitely | the `length < 0` guard ran after a comparison that promoted it to unsigned; reordered in all four transports, and the framing layer now refuses an oversized mark outright |
| `bool` outside `{0,1}`, enum outside its declared set → `GARBAGE_ARGS` | accepted | the bool decoder rejects values above 1; generated decoders emit a domain check listing the declared enum values |
| A returned Write chunk carries the length actually written (RFC 8166 §4.3.2) | the requester ignored the returned Write list and reported the length it had *advertised*, so every directly-placed result came back exactly `max_rdma_write_chunk` bytes long | the REPLY path now sums the returned segment lengths into `write_chunk.length` before the results are decoded |
| A Responder may leave a Write chunk unused (RFC 8166 §3.4.6) | the requester assumed the decoder had taken the chunk and cleared it unconditionally, so a chunk libevpl had allocated and nobody claimed leaked one buffer reference per call | the chunk is released when it comes back empty, or when the reply carried no results to decode; a caller-supplied (borrowed) buffer is still never touched |
| A Reply chunk too small for the Reply → `RDMA_ERROR` / `ERR_CHUNK` (RFC 8166 §4.5) | the per-segment capping loop silently dropped the overflow and announced a Reply short by exactly that much | the Reply chunk is now left unused and the Reply goes inline when it does not fit; `RDMA_ERROR` is still not implemented, which is the remaining gap |
| A Requester provides a Reply chunk for a Reply that may not fit inline (RFC 8166 §4.3.3) | `evpl_rpc2_call` took `max_rdma_reply_chunk` and ignored it, so no Reply chunk ever reached the wire and the whole `RDMA_NOMSG` half of the protocol was dead on both sides | the call advertises the chunk, and `evpl_rpc2_recv_msg` consumes an `RDMA_NOMSG` reply out of it |

Also addressed:

- **Maximum RPC message size.** A record mark is unauthenticated input, and
  the transport previously buffered whatever it claimed. `rpc2.c` now caps a
  message at 4 MiB across all fragments, refusing an oversized frame at the
  framing layer before anything is allocated for it.
  `evpl_global_config_set_rpc2_max_message_size()` adjusts it. Two cases hold
  that down: `RecordMarkHuge` refuses a single oversized mark on sight, and
  `ReassemblyCapExceeded` walks the running total past the cap using fragments
  that are each individually legal — the only thing that can stop the second
  is a receiver counting across the fragments of one record. Because the
  driver lowers the cap for its own run (`CONF_MAX_MESSAGE_SIZE`, 64 KiB, read
  from the config on every fragment exactly as the default is), that case costs
  tens of kilobytes rather than megabytes.
- **Declared bounds are enforced, on all three shapes.** `opaque<N>` had the
  bound plumbed through the runtime and ignored; counted arrays never checked
  theirs; `string<N>` never even had its bound reach the decoder, because
  codegen tested the string branch before the vector branch and dropped it. All
  three now reject an over-bound length before it is used to alias or size an
  allocation. The over-bound cases in the suite supply the bytes their length
  claims, so the message stays perfectly well formed apart from exceeding the
  bound — otherwise the whole-message length check would reject them anyway and
  the cases would pass whether or not the bound were enforced. Disabling the
  checks makes the suite report `SUCCESS` where `GARBAGE_ARGS` is required,
  which is what an over-bound payload used to do.
- **A 32-bit overflow bypassed the contig bounds check.** `iov_offset + len +
  pad` was computed entirely in 32-bit unsigned arithmetic, so a length near
  `UINT32_MAX` made `len + pad` wrap to a small value, the comparison succeed,
  and the decoder hand back a pointer with a multi-gigabyte length into a
  receive buffer. Reachable straight off the wire, ahead of any
  authentication — an AUTH_SYS `machinename` is enough. The three affected
  checks (string, opaque, fixed-opaque) now compute in 64 bits.
- **`-Wno-switch` is gone.** xdrzcc emits a `default` arm for a union that
  declares none, so generated code is `-Wswitch`-clean; the exemptions in
  libevpl's test macro and in chimera's `nfs_common` were both removed. The
  synthetic arm is deliberately inert rather than a decode failure: NFSv4 must
  answer an unknown operation with `OP_ILLEGAL` rather than rejecting the whole
  COMPOUND, and `nfs_argop4` is exactly such a union. Malformed input is still
  caught, because the arm consumes nothing and the message-length check rejects
  it.
- **A zero-copy send dropped the caller's references.** `__marshall_opaque_zerocopy`
  stopped its move loop on `length`, so a `zcopaque` handed over with no bytes
  left its references stranded — unreachable to the sender, which had given up
  ownership, and unknown to the send path. One buffer reference leaked per
  message. The loop now takes every iovec it was given.

The ownership rules that made that last one hard to see are worth stating,
since neither is documented: for `zcopaque` the marshaller **moves** the
caller's references (`xdr_iovec_move_private`) while the unmarshaller
**clones** (`xdr_iovec_copy_private`). A sender must therefore not release what
it handed over, and a receiver must release what it decoded — on replies as
much as on calls, and even when the payload is empty, since the decoder returns
one iovec regardless. Getting this backwards corrupts the allocator free list
into a cycle, which surfaces as a hang in `evpl_allocator_destroy` at exit
rather than an obvious double free.

`evpl_create()` also takes ownership of the `evpl_thread_config` passed to it
and releases it itself; this is intentional and is noted here only because
releasing it in the caller is a double free.

## Divergences currently recorded

Five, all RPCSEC_GSS, all found by widening the model over the failure exits of
the GSS state machine.  Each is listed in `known_divergences[]` with the RFC
text it contradicts; removing an entry turns its case back into a hard failure,
which is what should happen when the underlying issue is fixed.

| What the RFC requires | What libevpl does |
|---|---|
| `seq_num` above `MAXSEQ` → reject with `RPCSEC_GSS_CTXPROBLEM` (RFC 2203 §5.3.3.3) | discarded in silence, like a replay; the client is never told to refresh and retries until it times out |
| krb5i results that cannot be signed → send no response at all (RFC 2203 §5.3.3.4.1) | the results are returned **unwrapped** under MSG_ACCEPTED/SUCCESS, so an integrity-protected call completes with unauthenticated results |
| an undecodable `rpc_gss_init_arg` is undecodable *arguments* → `GARBAGE_ARGS` (RFC 5531 §9), and §5.2.3.2 rules out both RPCSEC_GSS auth_stat values on a creation response | denied with `RPCSEC_GSS_CTXPROBLEM`, which tells the client to rebuild a context over what is really a malformed request |

The unsigned-reply one is the serious one: `evpl_rpc2_send_reply` treats a
failed `evpl_rpc2_gss_wrap_reply_integrity` as advisory and falls through with
the bare body.  The comment there argues the client will notice, but that makes
correctness depend on the peer, and a client that does notice cannot tell it
apart from an attacker having stripped the wrapping.

Everything else in the matrix matches the model on its own merits.  Getting
there took nine fixes to `rpc2.c`, all of them found by these models and all
confirmed against the RFC before being changed.  The four RPC-over-RDMA ones
are in the table above; the rest are below:

### Server side, RPCSEC_GSS

- **An unauthenticated peer could destroy another client's security context.**
  The `RPCSEC_GSS_DESTROY` arm looked up the handle and retired the context
  before any verification, returning ahead of the header-MIC check that only
  the DATA arm performed -- so neither the verifier nor the sequence number was
  checked, and handles are allocated sequentially and therefore enumerable.
  RFC 2203 sec 5.4 requires both checks.  DESTROY now shares the DATA path and
  is acted on only after the context, the header MIC and the sequence number
  have all been verified.

- **Integrity failures over the call arguments were reported as AUTH_ERROR.**
  RFC 2203 sec 5.3.3.4.2 separates the two cases: a bad *header* verifier means
  the caller is not authenticated (MSG_DENIED), while a bad checksum over the
  *arguments* means the caller is known but its arguments are unusable
  (MSG_ACCEPTED / GARBAGE_ARGS).  Both answered MSG_DENIED with
  RPCSEC_GSS_CTXPROBLEM, which makes a client tear down and re-establish a
  context that was fine.  The argument path now answers GARBAGE_ARGS.

- **A databody `seq_num` mismatch shared that fate**, since it exits through the
  same path (RFC 2203 sec 5.3.2.2); the same fix covers it.

### Client side

- **The client never inspected the reply status, so a refusal arrived as a
  success.**  `evpl_rpc2_recv_msg` switched on `mtype` alone -- `reply_stat` and
  `accept_stat` were read nowhere on the receive path.  A `MSG_DENIED`, a
  non-SUCCESS `accept_stat`, or an undefined `reply_stat` fell through to the
  results decoder, so a refusal with a decodable body attached reached the
  caller as status 0 carrying the refuser's values.  The reply status is now
  inspected first: results are decoded only for MSG_ACCEPTED/SUCCESS, an
  accept_stat is passed through as a positive status, and anything else
  completes the call with `EVPL_RPC2_REPLY_DENIED`.

- **Losing the connection lost the callbacks.**  The
  `EVPL_NOTIFY_DISCONNECTED` arm freed every entry of `conn->pending_calls`
  without invoking one callback, leaving each caller waiting on a completion
  that could no longer arrive.  Pending calls are now completed with
  `EVPL_RPC2_REPLY_CONN_LOST`.

Delivering a status with no body to decode needed one supporting change: the
xdrzcc-generated `recv_reply_dispatch` gained a `status` parameter, so a call
can be completed without unmarshalling results that are not there.  Fixing this
also exposed a latent fault in the client harness itself -- it kept per-call
state on the stack frame of the case that started the call, which is only safe
while abandoned calls never complete.  That state is now heap-allocated.

## Open items parked along the way

Recorded here rather than fixed, so they are not lost.  Nothing in this list
currently makes the suite red.

### Sharp edges (API/documentation, not defects)

- **zcopaque ownership depends on how the payload arrived, and the decoded
  value does not say which.**  Decoded inline, an `xdr_iovecr` holds clones the
  receiver owns and must release (`xdr_iovec_copy_private`).  Decoded from an
  RDMA read chunk, `__unmarshall_opaque_zerocopy_*` short-circuits to
  `v->iov = chunk->iov` (xdr_builtin.c:1142) and the iovecs belong to the
  request, which releases them at teardown.  So the same handler code
  double-frees on one transport and leaks on the other.

  The fix is to call `evpl_rpc2_encoding_take_read_chunk()` unconditionally
  before using the payload: a no-op on a stream transport, an ownership
  transfer on RDMA.  That requirement is currently discoverable only by reading
  `rdma_ddp.c:155` or chimera's `nfs3_proc_write.c:138` -- it is not stated on
  the `xdr_iovecr` type or in `evpl_rpc2_program.h`, and getting it wrong
  presents as a hang in `evpl_allocator_destroy` at exit rather than as an
  obvious fault.  Worth a comment at the definition.

  Receiving a zcopaque *reply* as a client has the mirror-image split, and the
  decoded value does not say which side of it you are on either.  Decoded
  inline the iovecs are clones the client owns and must release.  Decoded out
  of a Write chunk that the client supplied the buffer for (the `write_chunk_iov`
  read-into form), they alias that buffer: no reference was taken anywhere
  along the path, the caller still holds the one it allocated, and releasing
  from the callback as well is a double free.  Where libevpl allocated the
  chunk itself the client owns them again.  So the rule is "release unless you
  supplied the buffer", and `conformance.c`'s `owns_reply_payload` is exactly
  that predicate.

- **A zero-length zcopaque used to hand back an iovec describing no bytes.**
  Fixed here (the decoders now report `niov == 0`), but the same asymmetry is
  what made it hard to see: the reference existed but nothing could reach it.

### Unverified, from reading rather than from a failing test

These came out of tracing rpc2.c and have not been reproduced, so treat them
as leads rather than findings:

- `evpl_rpc2_recv_msg` calls `abort()` when an RDMA chunk list carries too many
  segments (around rpc2.c:2335 and :2350).  Unauthenticated input reaching an
  abort is worth a defect case; the model would state that a malformed chunk
  list must be answered or the connection dropped, never aborted.
- The record-mark peek reads four bytes assuming `iovec[0]` holds them
  contiguously.  Where a record boundary lands within four bytes of a receive
  buffer boundary this would read stale bytes and trip an abort.
- `evpl_iovec_ring_copyv` writes into an `alloca`'d array sized by
  `config->max_num_iovec` with no cap on the incoming count.
- `xdr_string.str` is not NUL-terminated on the vector (multi-iovec)
  unmarshalling path: `xdr_dbuf_alloc_string` allocates exactly `len` bytes.
  `hello_world.c` calls `strcmp` on a decoded string and passes only because
  the contiguous path happens to leave the sender's zero padding in place --
  which means the same handler reads past the end once a string arrives split
  across iovecs.  Either the allocation should reserve the extra byte or the
  field should be documented as counted-not-terminated.

### Top remaining coverage gap in rpc2.c

Every function is now reached.  What is left cold in the chunk paths is either
defensive or needs input the harnesses cannot produce:

- The `evpl_rpc2_abort` arms guarding `evpl_rpc2_iovec_cursor_move` failure.
  Unreachable by construction -- the cursor is initialised over the very iovecs
  it is then asked to walk.
- The zero-length-target `continue` in the reply-chunk write loop, and the
  multi-segment arithmetic generally.  libevpl's requester always advertises a
  single segment per chunk, so a second target never exists.  Reaching it needs
  either a multi-segment requester or a hand-built RPC-over-RDMA peer.
- `evpl_rpc2_take_reply_chunk`'s two rejection arms (unknown xid, a Responder
  claiming more bytes than it was given).  Both need a hostile RDMA peer; the
  raw-socket defect phase cannot express RPC-over-RDMA framing, which is the
  same reason phase 2 is TCP-only.
- The AUTH_SYS branches of the RDMA read-chunk path (`ctx_authsys`).  The value
  phase calls with AUTH_NONE throughout, so a credential-flavour dimension in
  `values.qnt` would be needed to combine AUTH_SYS with direct placement.
- `prometheus_time_histogram_sample` in the reply path and the
  `reply_capture_cb` hook.  Neither is chunk-related.

The RPCSEC_GSS block is worked out: `evpl_rpc2_gss_seq_check`,
`evpl_rpc2_gss_handle_call`, `evpl_rpc2_gss_rd_u32`, `evpl_rpc2_gss_rd_opaque`
and `evpl_rpc2_gss_decode_cred` are at 100% of lines, and the rest sit above
79%.  What remains cold there is not reachable from the wire, and is recorded
here so it is not chased again:

- Allocator and `evpl_iovec_alloc` failure returns in `..._unwrap_integrity`
  and `..._wrap_reply_integrity`, and the `evpl_rpc2_abort` in
  `..._send_init_res`.
- The bounds-check failures in `evpl_rpc2_gss_wr_u32` and `..._wr_opaque`.
  Every caller either passes an `end` exactly the size of what it is about to
  write, or a buffer sized from the same arithmetic, so the checks can only
  fire if that arithmetic is changed.
- The `db_pad > db_len` padding branch in `..._wrap_reply_integrity`.  XDR
  encodings are always a multiple of four, so the databody is too, and the
  padding is always empty.
- `if (evpl_rpc2_gss_rd_u32(&lp, lenbuf + 4, ...))` in `..._handle_init`:
  `lenbuf` is exactly the four bytes being read, so the cursor cannot overrun.
  Likewise the token gather immediately after it, which has already been
  bounds-checked against `request_length`.
- The `!thread->gss_provider` arm of `..._handle_init`.  Its caller,
  `..._handle_call`, makes the same check first and returns, so this one is
  unreachable duplicate defence -- the `GssNoMechanism` cases cover the check
  that does the work.

### Ready to re-enable

### RPC-over-RDMA chunk coverage

`values.qnt`'s `ChunkCls` drives every chunk shape rpc2.c distinguishes:

| Class | What it exercises |
|---|---|
| `ChunkNone` | inline, no direct placement |
| `ChunkDdp` | a Read chunk: the call's payload placed by the Responder |
| `ChunkReply` | a Reply chunk: the whole Reply placed as `RDMA_NOMSG` |
| `ChunkReadInto` | a Write chunk into a caller-owned buffer |
| `ChunkWriteAlloc` | a Write chunk into a buffer libevpl allocates |
| `ChunkWriteExact` | a Write chunk sized exactly to the result |

The last three are confined to `ECHO_ZBYTES` by the
`writeChunkOnlyWhereItApplies` invariant, since a Write chunk is storage for a
DDP-eligible *result* and that is the only reply carrying one -- offered
anywhere else it would go unused and the case would be quietly testing the
inline path.  The split between the three is the ownership question rpc2.c
branches on, and the two directions of getting it wrong are a leak and a double
free.  `ChunkWriteExact` is the at-bound class for chunk sizing: it is the only
one where a segment is consumed to its last byte rather than capped short.

They are inert on the stream transport (rpc2.c gates all of it on
`conn->rdma`), so the one case table is meaningful on both, and the suite runs
it over `STREAM_SOCKET_TCP` and `DATAGRAM_TCP_RDMA` alike.

The oracle for `ECHO_ZBYTES` compares the payload bytes, not just its length.
That matters once placement is by RDMA: the length arrives in the transport
header's Write list while the bytes are written straight into the destination
buffer, so a payload placed at the wrong offset, truncated, or never written at
all still reports the right length.

## What the suite does not cover

- **A defect aimed at the RPC header itself.** The overflow described above is
  fixed, but the suite reaches it only through procedure arguments. A case that
  puts a hostile length in an AUTH_SYS `machinename` would exercise it on the
  header path, which needs no valid program, version or procedure — worth
  adding to `defects.qnt`, and worth running under ASan.
- Concurrency: pipelined calls, out-of-order replies, duplicate xids.
- **Defects aimed at the RPC-over-RDMA framing.** Phase 2 is TCP-only because
  record marking does not exist on the RDMA transports, and the raw-socket
  injector speaks record marks rather than `rdma_msg`. A chunk list with more
  segments than rpc2.c's fixed arrays hold still reaches an `abort()`
  (rpc2.c around the `write_segments` / `reply_segments` bounds checks), and a
  Responder that over-reports what it wrote into a Reply chunk is rejected by
  code no test executes. Both want a hand-built RPC-over-RDMA peer, which is
  the natural next phase.
- **`RDMA_ERROR`.** libevpl neither sends nor decodes it, so the RFC 8166 §4.5
  error path -- a chunk too small, an unsupported version -- has no
  representation. A Reply too large for the offered Reply chunk is answered
  inline instead, which is safe but is not what the RFC asks for.
- **A Reply chunk larger than one segment.** The requester advertises exactly
  one, so the multi-segment distribution loop in the responder runs a single
  iteration whatever the reply size.
- xdrzcc's **frontend**: constructs it mis-compiles rather than rejects cannot
  be tested from here, because the compiler never emits the thing under test.
  Those need compile-time tests in `ext/xdrzcc/tests`. Known cases, documented
  in the header comment of `conformance.x`: `hyper`/`quadruple` unsupported,
  negative constants silently parsed as positive, `case 1:` rejected, `string`
  inside an array silently losing its shape, and a typedef re-decorated at the
  use site silently dropping the modifier (which changes the wire format —
  chimera already works around this in `nfs4.x`).

## Regenerating

```sh
cd quint && ./regen_cases.sh    # needs quint (or npx) and python3
```

The script runs each model's own tests and invariant check first, so a broken
model cannot silently mint a broken-but-green suite. It de-duplicates cases on
the fields each procedure actually reads, so the case count reflects distinct
wire messages rather than distinct model states.
