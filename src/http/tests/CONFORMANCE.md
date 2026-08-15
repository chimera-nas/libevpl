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

Both of these are memory-safety faults reachable from an unauthenticated peer.
They are fixed in `http.c`; a recurrence fails the test.

| What the RFC requires | What libevpl did | Fix |
|---|---|---|
| A Content-Length is a decimal number of octets (RFC 1945 §10.4) | `evpl_recvv` takes an `int` length while `request_left` is a `uint64_t`. `Content-Length: -1` makes it `UINT64_MAX`, which truncates to `-1`; `evpl_recvv` rejects a non-positive length by returning `-1` **without touching the caller's iovec**, and the caller only tested for `0` — so a stale iovec was added to the receive ring, taking a second reference to a buffer it did not own and then freeing it twice. A heap use-after-free from four bytes of a request header | the length is clamped to `INT_MAX` before the call, and both call sites treat any non-positive return as "no data" |
| A malformed header field is a request the server refuses | the header struct was allocated before the field was parsed and dropped on both error returns — and because a dropped header still pointed at the rest of the agent's free list, each one stranded that whole tail too. ~16 KB per malformed header line, repeatable at will by a remote peer | the header is returned to the free list on both paths |

The first is the more serious: it needs no valid method, no valid URI and no
body — a request line and one header are enough, and it is reached before
anything else looks at the request.

## Divergences currently recorded

Twenty-eight, grouped by root cause in `known_divergences[]`. Removing an entry
turns its case back into a hard failure, which is what should happen when the
underlying issue is fixed. Summarised:

### HTTP/1.0 connection semantics are not implemented

RFC 1945 §1.4: "The connection is closed by the server after sending the
response." libevpl's HTTP/1.x server never closes a connection it has answered
on, and `evpl_http_server_dispatch_default` attaches `Connection: keep-alive`
to every response, unsolicited. Together they leave an HTTP/1.0 client that
does not implement the Keep-Alive extension waiting on a close that never
comes, for every request it makes.

Fixing it needs a decision the test cannot make: close on the HTTP/1.0 default,
honour `Connection` on both versions, or keep today's always-persistent
behaviour and document the server as HTTP/1.1-only.

### A malformed request is answered with silence

`evpl_http_server_handle_data` reaches `evpl_close()` for every syntax error it
detects in the request line or the header block, so a client that sends one
gets a FIN and no status. RFC 1945 §9.4.1 (400) and §9.5.2 (501) exist so that
it gets a verdict it can act on; a hang-up is indistinguishable from a crashed
server, a lost route or a middlebox, so a client retries a request that will be
refused the same way forever. This is the `completeRequestsAreAnswered`
invariant in the model, and it is the largest single gap: unknown method,
lowercased method, empty method, a one-token request line, an unparseable
version, an unsupported major version, a header line with no colon and an empty
field-name all exit through the same three or four `close()` calls, so one fix
retires the whole block.

### The header grammar of RFC 1945 §4.2 is only partly implemented

The parser splits a field on the first colon with `strtok_r` and treats a NULL
value token as fatal, so `X-Probe:` — a field present with an empty value,
which the grammar allows — closes the connection. A continuation line fares the
same way: it has no colon of its own, so it parses as a malformed field rather
than as more of the field above it. Both are legal requests a conforming server
must serve, and both are things a client library emits without thinking about
it.

Leading LWS is skipped one space at a time (`while (*token == ' ')`), so a tab
survives into the value, and trailing LWS is never stripped — an application
comparing a header value against a constant gets a mismatch it has no way to
see coming.

The mirror image is accepted where it should not be: a space before the colon
makes the field-name `X-Probe `, which is not a token. RFC 7230 §3.2.4 later
made rejecting it a MUST precisely because a front end and a back end that
disagree about whether it is a header is how a request smuggles one past a
filter.

### Content-Length is taken on trust

The value goes straight through `strtoul` with no check that it is a decimal
number, and a second `Content-Length` overwrites the first. A value that is not
a number reads as zero, so a request *with* an entity is treated as one without
and its body becomes whatever the server parses next; two conflicting values
pick where the next request starts, which is the desync a request-smuggling
attack is built on. RFC 1945 §8.3 also requires a POST to carry a length and
names 400 for one that does not; libevpl serves it as an empty POST.

### The request line is permissive where RFC 1945 is exact

`strtok_r` keeps handing out tokens and only the first three are read, so a
fourth is silently discarded — `Request-Line` is exactly three fields (§5.1).
The version is matched with `strncmp` against exactly `HTTP/1.1` and
`HTTP/1.0`, so `HTTP/1.9` is refused; RFC 2145 §2.3 makes a higher minor
version a request to be served at the version the server does speak, which is
what makes the minor number usable for negotiation.

Two entries in this group are weaker than a MUST and are marked as such: bare
LF line endings are a tolerance RFC 1945 §19.3 *recommends*, and the HTTP/0.9
Simple-Request is obsolete and supporting it would make the response shape
depend on the request.

### An over-long request line can wedge the connection

`evpl_http_parse_line` peeks at most 8 iovecs (`evpl_peekv`'s `maxiovecs`), so
where the request line spans more receive buffers than that it never
accumulates the `maxline` bytes that would make it report the overflow, and
returns "need more data" for data that has already arrived. The connection then
makes no further progress and holds its buffers until the peer gives up.
Reachable from an unauthenticated peer, and only on some delivery patterns,
which is why it shows up on one case in three.

## What the suite does not cover

- **The client direction.** `conformance.c` drives libevpl's *server*. The
  mirror image — a hostile server driving libevpl's HTTP client with malformed
  status lines, header blocks and bodies — is the natural next phase, and is
  what `conformance_client.c` is to the RPC2 suite. Several of the parser
  defects above are in code shared by both directions
  (`evpl_http_handle_body`), so a client-side model would reach them from the
  other side for free.
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
