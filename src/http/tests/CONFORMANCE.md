<!--
SPDX-FileCopyrightText: 2026 Ben Jarvis

SPDX-License-Identifier: LGPL-2.1-only
-->

# Model-based HTTP/1.0 conformance test

`conformance.c` + `quint/` form a conformance suite for libevpl's HTTP/1.x
server. A formal model written in [Quint](https://quint-lang.org) enumerates
the test cases; a generator turns them into a C table; the test binary replays
them against a real libevpl HTTP server over a raw socket.

It is the HTTP twin of the RPC2 suite in `src/rpc2/tests`, and follows the same
rule: **the model encodes the specification, not libevpl's current behaviour.**
Divergences are expected; each reviewed one is listed in `known_divergences[]`
in `conformance.c` with a note, which keeps the suite green while leaving the
gaps visible and counted. An unlisted divergence fails the test.

The cases are generated from the model at build time, so quint and python3 are
build dependencies. CMake detects them; when either is missing the test is
simply not registered and the rest of the suite is unaffected:

```
-- HTTP conformance test enabled (quint: /usr/local/bin/quint)
-- HTTP conformance test disabled (needs quint and python3 on PATH)
```

Pass `-DQUINT_EXECUTABLE=OFF` to force it off. The devcontainer installs a
pinned quint, so it is enabled there.

```
ctest -R libevpl/http/conformance --output-on-failure
ctest -R libevpl/http/quint_model --output-on-failure   # the model's own tests
```

Nothing generated is checked in. The ITF traces and the case table are build
artifacts under `<build>/src/http/tests/quint/`, regenerated whenever the model,
the converter or the generator script changes. Seeds are fixed, so a given
quint release always yields the same cases; a different release may sample
differently, which is why the devcontainer pins one.

## Layout

| File | Role |
|---|---|
| `quint/http10.qnt` | Three modules: the shared prediction vocabulary, the positive request matrix, the defect taxonomy |
| `quint/itf_to_cases.py` | ITF traces → C case table |
| `quint/generate_cases.sh` | Build step: model → traces → case table |
| `quint/check_models.sh` | The `quint_model` test: scenario tests + invariants |
| `<build>/…/quint/http_cases.h` | **Generated**, not checked in |
| `conformance.c` | The driver: echo server, raw-socket client, response classifier |

Three modules in one file rather than two files, because both matrices predict
in the same vocabulary (`Outcome`, `BodyExpect`, `PersistExpect`,
`ProbeExpect`) and the C driver compiles one table generated from all of it. A
class that meant one thing in one file and another in the other would be a
silently wrong test. `quint` picks the module with `--main`, which every
invocation in the scripts passes explicitly.

## Why a raw socket on both sides

libevpl's own HTTP client cannot express any of this.
`evpl_http_client_send_headers` hardcodes `HTTP/1.1` and emits a fixed header
block, so it can send neither an HTTP/1.0 request nor a malformed one. Both
phases therefore drive a socket directly, which also means one set of framing
helpers covers the positive and negative matrices alike.

## The two phases

**Requests** replay legal HTTP/1.0 requests across six dimensions — method,
Request-URI shape, header-block grammar, body length, connection disposition,
and how the bytes are delivered — and check the response. The server behind the
socket runs an echo application that reflects what the parser produced: the
method, the URI, the probe header and its repeat count, and the request body
come back in the response. The oracle is therefore what the server
*understood*, not merely that it answered, which is what makes a case like
"leading LWS is not part of a field value" checkable at all.

**Defects** replay malformed requests and classify the response against the
status RFC 1945 names for it. The model's `Outcome` has three arms:
`Status(n)` where the RFC names a code, `NotSuccess` for the shapes it leaves
open (an incomplete request, where refusing and closing are both defensible),
and `SimpleResponse` for the one HTTP/0.9 case.

Every case is replayed under three delivery modes — one write, two writes, and
one byte at a time with the server's event loop pumping between them. A parser
defect that is only detected because the whole request arrived in one read is
not really detected. A dribble writes at most the first 512 bytes one at a
time: every state transition a byte-at-a-time delivery can expose is inside
that, and dribbling eight kilobytes of body afterwards costs a syscall per byte
and proves nothing further.

### Checks that sit outside the model

Three things the driver asserts are properties of any response to an HTTP/1.0
request rather than of a particular case, so they are held in the driver rather
than bent into the case table:

- The status line carries `HTTP/1.0` or `HTTP/1.1` and a reason phrase.
- No `Transfer-Encoding: chunked` — chunked is an HTTP/1.1 addition (RFC 2616
  §3.6.1) and an HTTP/1.0 client has no way to delimit a response framed with
  it.
- A server may only answer `Connection: keep-alive` to a client that asked for
  it (RFC 2068 §19.7.1.1).

The connection-close check is sampled rather than run on all several hundred
request cases: whether the server closes depends on the request's version and
its `Connection` header and on nothing else, and each check costs a quarter of
a second waiting for a FIN that a conforming server sends immediately. It runs
once per (method, connection) pair.

## Divergences found, and fixed

Every divergence the suite found on its first run has been fixed except one,
which is a decision rather than a gap (see below). A recurrence of any of these
fails the test.

Two are memory-safety faults reachable from an unauthenticated peer:

| What the RFC requires | What libevpl did | Fix |
|---|---|---|
| A Content-Length is a decimal number of octets (RFC 1945 §10.4) | `evpl_recvv` takes an `int` length while `request_left` is a `uint64_t`. `Content-Length: -1` makes it `UINT64_MAX`, which truncates to `-1`; `evpl_recvv` rejects a non-positive length by returning `-1` **without touching the caller's iovec**, and the caller only tested for `0` — so a stale iovec was added to the receive ring, taking a second reference to a buffer it did not own and then freeing it twice. A heap use-after-free from four bytes of a request header | the length is clamped to `INT_MAX` before the call, and both call sites treat any non-positive return as "no data" |
| A malformed header field is a request the server refuses | the header struct was allocated before the field was parsed and dropped on both error returns — and because a dropped header still pointed at the rest of the agent's free list, each one stranded that whole tail too. ~16 KB per malformed header line, repeatable at will by a remote peer | the header is returned to the free list on both paths |

The first is the more serious: it needs no valid method, no valid URI and no
body — a request line and one header are enough, and it is reached before
anything else looks at the request.

One more is a liveness fault of the same character:

- **An over-long request line could wedge the connection.**
  `evpl_http_parse_line` scanned at most eight peeked iovecs
  (`evpl_peekv`'s `maxiovecs`), and a peer that dribbles its request produces
  one iovec per byte — so exhausting the array did not mean the data had not
  arrived, only that the answer lay further along than the array reached.
  Reporting "need more data" there for data already buffered left the
  connection making no further progress, holding its receive buffers until the
  peer gave up. The iovec scan is still the fast path; when the array fills the
  parser falls back to a bounded contiguous `evpl_peek`, which sees the whole
  window however finely it is fragmented.

The rest are conformance gaps, each fixed in its own commit:

### HTTP/1.0 connection semantics

RFC 1945 §1.4: "The connection is closed by the server after sending the
response." HTTP/1.0 has no persistent connections of its own — Keep-Alive is an
extension (RFC 2068 §19.7.1) the client opts into — and libevpl did the
opposite of both halves: it never closed a connection it had answered on, and
it attached `Connection: keep-alive` to every response whether or not anyone
had asked. An HTTP/1.0 client that does not implement the extension was left
waiting on a close that had been explicitly announced as not coming.

`evpl_http_response_keeps_alive` now decides from the request: an explicit
`Connection: close` always wins, HTTP/1.1 is persistent by default (RFC 7230
§6.1), and HTTP/1.0 is persistent only if the client asked. The response says
which it is, and `evpl_http_server_flush` finishes the connection after a
non-persistent one. HTTP/1.1 peers are unaffected.

### A malformed request was answered with silence

`evpl_http_server_handle_data` reached `evpl_close()` for every syntax error in
the request line or the header block, so a client that sent one got a FIN and
no status. RFC 1945 §9.4.1 (400) and §9.5.2 (501) exist so that it learns which
of the two things went wrong; a hang-up is indistinguishable from a crashed
server, a lost route or a middlebox, so the client retries a request that will
be refused the same way forever. This is the `completeRequestsAreAnswered`
invariant in the model, and it was the largest single gap: every one of those
paths now goes through `evpl_http_server_reject`.

### The header grammar of RFC 1945 §4.2

    HTTP-header = field-name ":" [ field-value ] CRLF
    field-name  = token

The brackets are what a `strtok_r` split got wrong. `X-Probe:` — a field
present with an empty value, which client libraries emit without thinking about
it — was a failed request, and so was a continuation line, which has no colon
of its own. Leading LWS was skipped one space at a time so a tab survived into
the value, and trailing LWS was never stripped, leaving an application
comparing a header against a constant with a mismatch it had no way to see
coming. Conversely `X-Probe : v` was accepted, though `X-Probe ` is not a
token; RFC 7230 §3.2.4 later made rejecting that a MUST, because a front end
and a back end that disagree about whether it is a header is how a request
smuggles one past a filter.

`evpl_http_parse_header_line` and `evpl_http_fold_header_line` now do this for
both directions, and a folded field re-runs the special-field handling over its
extended value — `Content-Length:` CRLF SP `5` is a length of five, and reading
only the first line would make it zero.

### Content-Length was taken on trust

The value went through `strtoul`, which accepts a sign, leading whitespace and
trailing junk and reports none of it: `abc` read as zero, so a request with an
entity was served as one without and the entity was left to be parsed as
whatever came next, and `-1` wrapped to a length no peer could satisfy. Two
conflicting lengths were resolved by taking the last, which makes where the
next request starts the sender's choice — the desync a request-smuggling attack
is built on. All three are now 400, as is an HTTP/1.0 POST with no length at
all (RFC 1945 §8.3). Identical duplicates stay legal, and HTTP/1.1 is
unaffected, since there a request with no length simply has no body (RFC 7230
§3.3.3).

### The request line was permissive where RFC 1945 is exact

`Request-Line` is exactly three fields (§5.1), and §19.3 asks for tolerance of
SP and HT *between* them — not before the first, where `strtok_r`'s skipping
made `" /echo HTTP/1.0"` a request whose method was the URI, and not after the
third, where a fourth token was silently discarded. The version was matched
with `strncmp` against the two spellings the server speaks, which both accepted
too much (`HTTP/1.10` matches `HTTP/1.1` in eight characters) and rejected too
much: RFC 2145 §2.3 makes a higher minor version a request to serve at the
highest 1.x the server speaks. `evpl_http_parse_version` now parses the
grammar.

### Bare LF line endings

RFC 1945 §19.3 recommends recognising a single LF as a line terminator. The
parser treated one as a line too long to hold, so a peer that sends bare LFs
anywhere had its request refused. Now accepted — the defence against a front
end that disagrees about where a message ends is refusing messages whose length
is ambiguous, which the Content-Length work above provides.

## Divergences currently recorded

One, and it is a decision rather than a gap.

RFC 1945 §5 makes a request line with no version an HTTP/0.9 Simple-Request,
and §6 pairs it with a Simple-Response: the body alone, with no status line and
no headers. libevpl answers 400.

Supporting it would make the shape of a response depend on how the request was
spelled, which every part of the response path would have to know about, and it
would reintroduce the one message framing in HTTP that carries neither a length
nor a status on a server that has just been taught to refuse messages whose
length is ambiguous. HTTP/1.1 dropped the form entirely (RFC 7230 appendix A.2)
and RFC 9112 §2.1 lets a server answer an unrecognised request line with 400.

The case stays in the model rather than being deleted from it, because what RFC
1945 requires does not change when an implementation decides not to do it. The
entry in `known_divergences[]` is where that decision is recorded.

## What the suite does not cover

- **The client direction.** `conformance.c` drives libevpl's *server*. The
  mirror image — a hostile server driving libevpl's HTTP client with malformed
  status lines, header blocks and bodies — is the natural next phase, and is
  what `conformance_client.c` is to the RPC2 suite. This matters more than it
  looks: the fixes above carried the header grammar, the Content-Length
  validation and the body-length clamp into the response path too, because both
  directions share `evpl_http_handle_body` and now share the field parser — but
  *nothing tests the response path*. Its status-line parse is still the loose
  one (`strncmp` against two spellings, `atoi` for the code), it has no
  equivalent of the request line's trailing-token check, and a response with no
  `Content-Length` and no `Transfer-Encoding` is read as a zero-length body
  rather than one delimited by the close, which HTTP/1.0 requires.
- **HTTP/1.1.** Chunked transfer coding, the required `Host` header, `100
  Continue`, persistent connections and pipelining, `Transfer-Encoding`
  together with `Content-Length`, and the 1.1-only status codes (505, 414,
  411). The 1.0 model is the floor; 1.1 is a superset that mostly adds
  requirements rather than changing them, so it should extend this model rather
  than replace it.
- **HTTP/2.** A different framing layer entirely (`http2.c`, nghttp2), with its
  own conformance surface.
- **TLS.** The transport is orthogonal to the message grammar under test.
- **Concurrency**: pipelined requests on one connection, and a server under
  more than one connection at a time.
- **The response direction of the grammar.** The driver checks the status line,
  the framing headers and the echoed values, but not, say, that a header value
  the application supplies with an embedded CRLF is rejected — response
  splitting is a defect class of its own and wants cases that come from the
  application rather than from the wire.

## Regenerating

```sh
cd quint && ./generate_cases.sh "$(which quint)" python3 . /tmp/httpq /tmp/httpq/http_cases.h
./check_models.sh "$(which quint)" .
```

The build runs the first for you. `check_models.sh` is the `quint_model` ctest
and runs the model's scenario tests plus a random-simulation pass against its
invariants, so a broken specification is a failing test rather than a quietly
wrong case table.
