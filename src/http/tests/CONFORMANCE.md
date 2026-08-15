<!--
SPDX-FileCopyrightText: 2026 Ben Jarvis

SPDX-License-Identifier: LGPL-2.1-only
-->

# Model-based HTTP/1.x conformance test

`conformance.c`, `conformance_client.c` and `quint/` form a conformance suite
for libevpl's HTTP implementation, both ends of it. A formal model written in
[Quint](https://quint-lang.org) enumerates the test cases; a generator turns
them into a C table; the test binaries replay them against a real libevpl HTTP
server and a real libevpl HTTP client, each driven from a raw socket.

It is the HTTP twin of the RPC2 suite in `src/rpc2/tests`, and follows the same
rule: **the model encodes the specification, not libevpl's current behaviour.**
Divergences are expected; each reviewed one is listed in `known_divergences[]`
in the driver with a note, which keeps the suite green while leaving the gaps
visible and counted. An unlisted divergence fails the test.

Scope is HTTP/1.x: RFC 1945 for HTTP/1.0, and RFC 9112 (with RFC 9110 for the
semantics it factored out) for HTTP/1.1. The two are one protocol family rather
than two protocols, which is why the version is a dimension of the matrices
rather than a second model — most of what is worth testing is exactly the
difference between them.

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
ctest -R libevpl/http/conformance --output-on-failure         # both directions
ctest -R libevpl/http/quint_model --output-on-failure         # the model itself
```

Nothing generated is checked in. The ITF traces and the case table are build
artifacts under `<build>/src/http/tests/quint/`, regenerated whenever the model,
the converter or the generator script changes. Seeds are fixed, so a given
quint release always yields the same cases; a different release may sample
differently, which is why the devcontainer pins one.

## Layout

| File | Role |
|---|---|
| `quint/http1x.qnt` | Four modules: the shared vocabulary, the positive request matrix, the request defect taxonomy, the response defect taxonomy |
| `quint/itf_to_cases.py` | ITF traces → C case table |
| `quint/generate_cases.sh` | Build step: model → traces → case table |
| `quint/check_models.sh` | The `quint_model` test: scenario tests + invariants |
| `<build>/…/quint/http_cases.h` | **Generated**, not checked in |
| `conformance.c` | The server driver: echo server, raw-socket client, response classifier |
| `conformance_client.c` | The client driver: raw-socket server, libevpl client, callback classifier |

Four modules in one file rather than four files, because they predict in a
shared vocabulary (`Version`, `Delivery`, `ProbeExpect`, and the expectation
types) and the two C drivers compile one table generated from all of it. A
class that meant one thing in one file and another in the other would be a
silently wrong test. `quint` picks the module with `--main`, which every
invocation in the scripts passes explicitly.

Case counts as of this writing: **1100 request cases, 171 defect cases, 101
status cases** in the server direction, **147 response cases** in the client
direction.

## Why a raw socket at both ends

Neither of libevpl's own HTTP peers can express any of this.
`evpl_http_client_send_headers` emits a fixed header block at a fixed version,
so it can send neither an HTTP/1.0 request nor a malformed one; and the server
emits a well-formed response by construction, so a real client never sees a
defective one. Each direction is therefore driven by a socket, which also means
one set of framing helpers covers every matrix.

`conformance.c` is a raw client against a real server; `conformance_client.c`
is a raw server against a real client. They share the model file and the
generated case table and nothing else.

## The server direction

### Phase 1: the positive matrix

Legal HTTP/1.0 and HTTP/1.1 requests across eight dimensions — version, method,
Request-URI shape, header-block grammar, content framing, connection
disposition, whether an `Expect: 100-continue` is sent, and how the bytes are
delivered. The server behind the socket runs an echo application that reflects
what the parser produced: the method, the URI, the probe header and its repeat
count, and the request content come back in the response. The oracle is
therefore what the server *understood*, not merely that it answered, which is
what makes a case like "leading LWS is not part of a field value" checkable at
all.

The framing dimension covers HTTP/1.0's only option (`Content-Length`, at five
lengths) and HTTP/1.1's addition: the chunked coding, in four shapes — one
chunk, chunk extensions on the size line, a trailer section after the last
chunk, and many chunks spanning read buffers. The last three are the parts a
decoder can produce the right content without ever looking at.

Delivery is one write, two writes, one byte at a time with the server's event
loop pumping between them, and — HTTP/1.1 only — two complete requests in a
single write. A parser defect that is only detected because the whole request
arrived in one read is not really detected. A dribble writes at most the first
512 bytes one at a time: every state transition a byte-at-a-time delivery can
expose is inside that, and dribbling eight kilobytes of content afterwards
costs a syscall per byte and proves nothing further.

### Phase 2: the defect taxonomy

Malformed requests, classified against the status the RFCs name for them. The
model's `Outcome` has three arms: `Status(n)` where an RFC names a code,
`NotSuccess` for the shapes they leave open (an incomplete request, where
refusing and closing are both defensible), and `SimpleResponse` for the one
HTTP/0.9 case.

Each defect is generated at the versions where it *is* a defect. Most grammar
rules are shared, so they run at both — a request-line parser that is right at
one version and wrong at the other is wrong. Three groups are not:

- the defects that *are* a version (malformed, unsupported major, higher minor,
  none at all) carry it in the request line, so running them twice would run
  the same bytes twice;
- the chunked-coding defects need a version that has the chunked coding;
- `HostMissing` and `PostWithoutContentLength` are the two whose answer *is*
  the version and nothing else — a request with no Host is a perfectly good
  HTTP/1.0 request and a refusable HTTP/1.1 one, and a POST with no length is
  the other way round.

### Phase 3: the status line and the response framing

Every status code `evpl_http_response_status_string` names, plus two valid ones
it does not and four values that are not statuses at all, answered through the
echo application at both versions and with both response framings. It sits
outside the model deliberately: the code list is libevpl's own table rather
than anything the RFCs enumerate, and the specification content is a small
number of rules applied to a list of inputs.

The reason phrases are not checked. RFC 9112 §4 makes the reason phrase
advisory ("A client SHOULD ignore the reason-phrase content") and RFC 2616
§6.1.1 said outright that the listed phrases "are only recommendations", so
asserting them would assert something the RFC leaves open.

The phase closes with one case that is not about a status at all: an
application header whose value carries a CRLF, and one whose name is not a
token. Neither can arrive from the wire — the parser splits lines on LF, so a
parsed value never contains one — so the echo application is asked to try, and
the driver checks that nothing was smuggled into the response.

### Checks that sit outside the model

Properties of *any* well-formed response rather than of a particular case, so
they are held in the driver rather than bent into the case table:

- The status line carries `HTTP/1.0` or `HTTP/1.1` and a reason phrase.
- `Transfer-Encoding` only towards an HTTP/1.1 request (RFC 9112 §6.1).
- Never `Content-Length` and `Transfer-Encoding` together (RFC 9110 §8.6).
- Neither on a 1xx or a 204 (RFC 9110 §8.6 and RFC 9112 §6.1).
- A `Date` on every 2xx, 3xx and 4xx (RFC 9110 §6.6.1).
- A server may only answer `Connection: keep-alive` to an HTTP/1.0 client that
  asked for it (RFC 2068 §19.7.1.1).

The connection checks are sampled rather than run on all eleven hundred request
cases, since each costs a wait. Whether the server *closes* depends on the
request's version and its `Connection` header and on nothing else, so that is
sampled per (version, method, connection) triple. Whether a connection the
server *kept* can carry another request depends on something else entirely —
whether the parser consumed exactly the bytes of the request it just answered —
so that is sampled per (version, content framing) pair. It is the only check
that can see an unconsumed trailer section or a miscounted chunk.

## The client direction

`conformance_client.c` inverts the whole arrangement: a raw socket pretending
to be a server, feeding defective responses to a real libevpl client. Its model
(`http1x_client`) has an outcome type with exactly two arms — the response is
delivered, or the request completes as a failure — and deliberately no third
arm for "nothing happens". A caller that dispatched a request is owed exactly
one answer, and a client that frees the request without telling anyone has not
failed it, it has abandoned the caller.

Alongside the response cases, and outside the model because they hold for every
one of them, the hostile server examines the requests it receives: exactly one
`Host` field on each (RFC 9112 §3.2), and where the caller supplied content,
exactly the octets it handed over under a framing that describes them.

## Divergences found, and fixed

Every divergence either suite has found has been fixed except one, which is a
decision rather than a gap (see below). A recurrence of any of these fails the
test.

### Memory safety and liveness

Three faults reachable from an unauthenticated peer, all found by the HTTP/1.0
pass:

| What the RFC requires | What libevpl did | Fix |
|---|---|---|
| A Content-Length is a decimal number of octets (RFC 1945 §10.4) | `evpl_recvv` takes an `int` length while `request_left` is a `uint64_t`. `Content-Length: -1` makes it `UINT64_MAX`, which truncates to `-1`; `evpl_recvv` rejects a non-positive length by returning `-1` **without touching the caller's iovec**, and the caller only tested for `0` — so a stale iovec was added to the receive ring, taking a second reference to a buffer it did not own and then freeing it twice. A heap use-after-free from four bytes of a request header | the length is clamped to `INT_MAX` before the call, and both call sites treat any non-positive return as "no data" |
| A malformed header field is a request the server refuses | the header struct was allocated before the field was parsed and dropped on both error returns — and because a dropped header still pointed at the rest of the agent's free list, each one stranded that whole tail too. ~16 KB per malformed header line, repeatable at will by a remote peer | the header is returned to the free list on both paths |
| A request line longer than the parser will hold is refused | `evpl_http_parse_line` scanned at most eight peeked iovecs, and a peer that dribbles produces one iovec per byte — so exhausting the array did not mean the data had not arrived, only that the answer lay further along than the array reached. Reporting "need more data" for data already buffered left the connection making no progress, holding its receive buffers until the peer gave up | the iovec scan is still the fast path; when the array fills, the parser falls back to a bounded contiguous `evpl_peek` |

Two more came out of the HTTP/1.1 pass, both about object lifetime rather than
the protocol:

- **A client connection handle went stale where its owner could not see it.**
  `evpl_http_client_connect` returns a pointer the application holds, and
  `EVPL_NOTIFY_DISCONNECTED` freed the struct behind it — with no notification
  to tell the application, since notifications are per request. Calling
  `evpl_http_client_close` on it was a use-after-free, which is what the client
  harness did as soon as enough cases left a connection dropped by the peer.
  A dropped client connection is now *retired* rather than freed: the bind is
  cleared, every outstanding request is completed with
  `EVPL_HTTP_NOTIFY_FAILED`, and the struct waits for the close its owner still
  owes it. Dispatching on a retired connection fails immediately rather than
  queueing forever.
- **Nothing disarmed a connection's deferrals when it was torn down.** The
  event loop holds the pointer until the deferral fires, so a connection
  dropped between arming a flush and running it left the callback to run
  against freed memory. `evpl_remove_deferral` existed but had never been
  declared in a public header.

### HTTP/1.0 conformance (the first pass)

- **Connection semantics.** RFC 1945 §1.4 closes the connection after the
  response; Keep-Alive (RFC 2068 §19.7.1) is an extension the client opts into.
  libevpl did the opposite of both halves — it never closed, and it attached
  `Connection: keep-alive` to every response whether or not anyone had asked.
- **A malformed request was answered with silence.** Every syntax error reached
  `evpl_close()`, so the client got a FIN and no status. RFC 1945 §9.4.1 (400)
  and §9.5.2 (501) exist so it learns which of the two went wrong; a hang-up is
  indistinguishable from a crashed server, so the client retries forever. This
  is the `completeRequestsAreAnswered` invariant, and it was the largest single
  gap.
- **The header grammar of §4.2.** `X-Probe:` — a field with an empty value —
  was a failed request, and so was a continuation line. Leading LWS was skipped
  one space at a time so a tab survived into the value; trailing LWS was never
  stripped. Conversely `X-Probe : v` was accepted, though `X-Probe ` is not a
  token, which is how a request smuggles a header past a filter.
- **Content-Length was taken on trust.** `strtoul` read `abc` as zero, so a
  request with content was served as one without and the content was parsed as
  whatever came next; `-1` wrapped; two conflicting lengths were resolved by
  taking the last, which makes where the next request starts the sender's
  choice.
- **The request line was permissive where §5.1 is exact** — leading whitespace,
  a fourth token, and a version matched with `strncmp` (which accepts
  `HTTP/1.10` and rejects `HTTP/1.9`, though RFC 2145 §2.3 makes a higher minor
  a request to serve).
- **Bare LF line endings** (§19.3 recommends accepting them) were treated as a
  line too long to hold.
- **The response status line** was parsed as loosely as the request line used
  to be: `atoi` turned a non-numeric status into `0` and handed it to the
  caller, and a caller testing `status < 400` treated that as success.
- **Close-delimited content was discarded** — the only framing HTTP/1.0 has for
  content of unknown size, which every streamed reply uses.
- **HEAD responses hung**, as did 204 and 304: the client waited for bytes that
  were never coming.
- **A status that is not a status** was formatted straight into the status
  line, so an application asking for `0` or `600` produced a response the peer
  could not parse.

### HTTP/1.1 conformance (this pass)

**Requests the server got wrong:**

- **`Host` was not checked at all.** RFC 9112 §3.2: "A server MUST respond with
  a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a
  Host header field and to any request message that contains more than one Host
  header field." The routing decision depends on it, so a request that leaves
  it ambiguous is one a front end and a back end can route differently.
- **`Transfer-Encoding` together with `Content-Length` was accepted**, with the
  coding silently winning. §6.3 rule 3 calls it a possible request-smuggling
  attempt that "ought to be handled as an error", and RFC 9110 §8.6 makes
  sending the pair a MUST NOT — the same defect as two Content-Lengths that
  disagree.
- **`chunked` not being the final coding drew a 501**, which says the server
  does not implement something rather than that the message has no length.
  §6.3 rule 4 makes it a 400 and a close. A coding it genuinely does not
  implement, with chunked still final, keeps the 501 §6.1 asks for.
- **`Transfer-Encoding` on a request claiming HTTP/1.0 was served.** A front
  end reading the version and a back end reading the coding disagree about
  where the message ends, which is the whole of a smuggling attack.
- **Chunk sizes went through `strtoul`**, which reads a line with no digits as
  zero — and zero is the last-chunk, so a size spelled `zz` ended the content
  early and left everything after it to be read as the next request. The
  chunked spelling of the Content-Length desync. A size too large to represent
  wrapped instead.
- **The trailer section was never consumed.** The decoder went straight to
  COMPLETE on the last-chunk, leaving the trailer fields and the CRLF that ends
  the coding in the stream — to be read as the start of the next message on a
  connection HTTP/1.1 keeps open by default. Caught by the reuse check, which
  is the only thing in the suite that can see it.
- **A chunk whose data was not followed by CRLF closed the connection in
  silence**, rather than answering the 400 the server owes a request it cannot
  find the end of.
- **Pipelined requests were never seen.** Both ends stopped parsing as soon as
  one message was complete, leaving anything already in the buffer for a read
  event that was never going to come. RFC 9112 §9.3.2 lets a client send its
  next request without waiting and requires the responses in order; two
  requests in one write meant the second was answered never. The server's
  read-ahead is bounded, since a request read ahead is a request struct held
  for as long as the peer chooses.
- **A `100 Continue` went to HTTP/1.0 clients.** RFC 9110 §10.1.1 makes
  ignoring the expectation a MUST there: a 1.0 client has no way to tell an
  interim response from the answer, so it reads the 100 as its response and
  everything after it as content.
- **Empty lines before a request line were answered 400.** §2.2 asks a server
  to ignore at least one, because that is what a client leaves behind when it
  miscounts a previous request's content.

**Responses the server got wrong:**

- **No `Date` on anything.** RFC 9110 §6.6.1 makes it a MUST on 2xx, 3xx and
  4xx. Everything downstream that reasons about the age of a response starts
  from it, so a caching proxy in front of this server had to treat every reply
  as having unknown age.
- **`Content-Length: 0` on a 204**, and on a 1xx, which RFC 9110 §8.6 makes a
  MUST NOT: these carry no content, so a length describes something that is
  not there.
- **`Transfer-Encoding: chunked` towards an HTTP/1.0 request**, which RFC 9112
  §6.1 makes a MUST NOT — that client has no chunked coding, so it reads the chunk
  sizes as content. Such a response is now close-delimited, which is the
  framing HTTP/1.0 does have for content of unknown size.
- **A header value carrying a CRLF was emitted verbatim**, which is response
  splitting: RFC 9110 §5.5 calls such a value "invalid and dangerous" and puts
  it outside the field-value grammar, and §5.1 makes a field name a token.

**What the client got wrong:**

- **No `Host` on any request.** §3.2 makes it a MUST on every HTTP/1.1 request,
  and this client writes HTTP/1.1 on the request line whatever the caller does.
  Every existing caller adds one by hand, which is the caller doing the
  library's job — and one that did not was making requests a conforming server
  must refuse.
- **A 1xx was reported as the answer.** RFC 9110 §15.2 requires a client to
  parse interim responses "even if the client does not expect one". Reporting
  one as the result loses the real response, which then arrives on a connection
  the client believes is idle. A server sending `100 Continue` or `103 Early
  Hints` was enough to break every request.
- **`Transfer-Encoding` was compared whole against `chunked`**, so a list
  (`gzip, chunked`) was not recognised as chunked at all — and a response
  carrying both a coding and a length was accepted with the coding silently
  winning.
- **The chunked defects above**, which the two ends share a decoder for.
- **Pipelined responses**, as on the server side.

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

## The failure notification

The first pass's largest finding was that there was nowhere to report a request
that will not complete. `evpl_http_notify_type` had five arms and none of them
meant "this request is over and there is no response", so when the client
refused a malformed response it closed the connection, and
`EVPL_NOTIFY_DISCONNECTED` freed every pending request without invoking one
callback. The caller waited on a completion that could no longer arrive.

`EVPL_HTTP_NOTIFY_FAILED` closes that, the way `EVPL_RPC2_REPLY_CONN_LOST`
closed the same gap in the RPC2 client. Exactly one of `RECEIVE_COMPLETE`,
`RESPONSE_COMPLETE` or `FAILED` reaches a given request, so it is also where an
application releases whatever it attached to one. `evpl_http_request_status()`
carries the reason, negative so it cannot collide with an HTTP status:
`EVPL_HTTP_ERROR_CONN_LOST` when the peer went away,
`EVPL_HTTP_ERROR_BAD_RESPONSE` when it sent something unparseable. The
distinction is the point of having two: one is worth retrying against the same
peer and the other is not. Which code each case must carry is checked in the
driver rather than the model, since the model deliberately leaves the spelling
of a failure open.

It fires in both directions. A server whose peer disconnects mid-response has
the same problem in reverse — the request it was answering is freed and the
application never learns, so per-request state it allocated is leaked. Nothing
in libevpl noticed because libevpl attaches nothing; an application that does
(chimera's S3 server frees its own request struct in `RESPONSE_COMPLETE`) leaks
one per dropped connection until it handles `FAILED`.

## Coverage

`make coverage COVERAGE_TESTS="libevpl/http/conformance"` runs both drivers
against a clang-instrumented build and reports what they reach. Needs
`libclang-rt-<version>-dev` installed, or the Coverage build fails to link.

Over `src/http/http.c` and `src/http/http_internal.h` — the HTTP/1.x
implementation — the two suites reach **100% of functions, 89.4% of lines and
77.9% of branches**. (The HTTP/1.0 pass reached 96.9% / 81.2% / 70.5%.)

The largest remaining blocks are out of scope by construction:

| Where | Missed lines | Why |
|---|---|---|
| `evpl_http_conn_connected`, `evpl_http_client_connect`, and the h2 branches of `dispatch` / `add_datav` / `request_create` | ~50 | TLS/ALPN and HTTP/2 protocol selection |
| `evpl_http_parse_line` | 11 | The `evpl_peek` fallback — see below |
| `evpl_http_request_type_to_string` | 6 | The PUT and DELETE arms; the model covers the three methods RFC 1945 defines |
| `evpl_http_conn_set_host` | 5 | An IPv6 literal, and an endpoint that names no authority |

`src/http/http2.c` is 0% throughout, which an HTTP/1.x model cannot be
otherwise.

### The one piece of dead code the coverage found

`evpl_http_parse_line`'s `evpl_peek` fallback is never executed. It exists
because `evpl_peekv` reports at most 8 iovecs, so a line spread over more of
them than that would otherwise be reported as "not arrived yet" forever.

At the default 2 MiB `buffer_size` that cannot happen:
`evpl_iovec_ring_append` coalesces contiguous appends from the same buffer, so
however finely a peer dribbles a 4 KB request line, it lands in one iovec. The
fallback is therefore defensive code against a small `buffer_size`
configuration rather than a fix for anything this suite reproduces, and
reaching it would need the suite to lower that setting.

## What the suite does not cover

- **Protocol upgrade.** `Upgrade`, `101 Switching Protocols`, and the `h2c`
  path. libevpl selects h2 by ALPN or prior knowledge rather than by upgrade,
  so there is nothing here to model yet.
- **`Expect` values other than `100-continue`.** RFC 9110 §10.1.1 makes
  answering one with 417 a MAY, and ignoring it — which libevpl does — is the
  other conforming choice, so a case would assert a preference rather than a
  requirement.
- **`TE` and `Trailer` request fields**, and surfacing a received trailer
  section: the decoder consumes it, and RFC 9112 §6.5 lets a recipient discard
  the fields, but there is no API to expose them through.
- **Methods beyond GET, HEAD and POST.** PUT and DELETE are accepted by the
  parser and have no framing rules of their own; `OPTIONS *` and `CONNECT` are
  not implemented, which RFC 9110 §9.1 permits.
- **Request semantics** — conditional requests, ranges, content negotiation.
  This is a suite about message framing and syntax, which is RFC 9112; RFC 9110
  semantics are the application's.
- **HTTP/2.** A different framing layer entirely (`http2.c`, nghttp2), with its
  own conformance surface.
- **TLS.** The transport is orthogonal to the message grammar under test.
- **Concurrency**: a server under more than one connection at a time. Both
  drivers are sequential, and pipelining is covered within one connection
  rather than across several.

## Regenerating

```sh
cd quint && ./generate_cases.sh "$(which quint)" python3 . /tmp/httpq /tmp/httpq/http_cases.h
./check_models.sh "$(which quint)" .
```

The build runs the first for you. `check_models.sh` is the `quint_model` ctest
and runs the model's scenario tests plus a random-simulation pass against its
invariants, so a broken specification is a failing test rather than a quietly
wrong case table.
