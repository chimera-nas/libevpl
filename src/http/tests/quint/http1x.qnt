// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * http1x.qnt -- what HTTP/1.0 and HTTP/1.1 require of a peer, both ends.
 *
 * Four modules in one file, because they share a vocabulary that must not
 * drift: `http1x` holds the types the matrices predict in, `http1x_requests`
 * is the positive server matrix, `http1x_defects` the negative one, and
 * `http1x_client` is the whole thing inverted -- a hostile server driving
 * libevpl's client.  The C drivers compile one case table generated from all
 * of it, so a class that means one thing here and another there would be a
 * silently wrong test.
 *
 * IMPORTANT: this models the SPECIFICATION, not libevpl's current behaviour.
 * Where the two disagree the driver records a divergence, which is reviewed as
 * a candidate bug.  Encoding current behaviour instead would freeze today's
 * defects into the spec and guarantee they are never found.  This is the same
 * rule the RPC2 models follow (src/rpc2/tests/quint), and for the same reason.
 *
 * Scope is HTTP/1.x: RFC 1945 for HTTP/1.0 and RFC 9112 (with RFC 9110 for the
 * semantics it factored out) for HTTP/1.1.  The two are one protocol family
 * rather than two protocols, which is why `Version` is a dimension of the
 * matrices rather than a second model: the same request means different things
 * at the two versions, and most of what is worth testing is exactly that
 * difference -- the connection default inverts, Host becomes mandatory, and
 * chunked becomes a framing a message may use.  Where a rule is version
 * specific it is stated as such and the case is generated only at the versions
 * it applies to; where it is not, the case is generated at both, because a
 * parser that gets the request line right at 1.1 and wrong at 1.0 is a parser
 * with a bug either way.
 *
 * Both directions are driven from a raw socket, because libevpl's own HTTP
 * peers cannot express any of this: the client emits a fixed header block at a
 * fixed version, and the server emits a well-formed response by construction.
 * A socket can put an arbitrary HTTP/1.x message on the wire in either
 * direction, and it can also put a well-formed one there, so the positive and
 * negative matrices share one set of framing helpers.
 *
 * The classes are SYMBOLIC.  "UriQuery", not "/echo?a=1&b=2" -- the C driver
 * owns the mapping from class to bytes, which keeps this model about what the
 * RFCs require rather than about how to spell it.
 *
 *   quint test http1x.qnt --main=http1x_requests
 *   quint test http1x.qnt --main=http1x_defects
 *   quint test http1x.qnt --main=http1x_client
 *   quint run  http1x.qnt --main=http1x_defects --invariant=safety
 *   ./check_models.sh $(which quint) .
 */

/* ===================================================================== *
 * Shared vocabulary
 * ===================================================================== */

module http1x {

    /// Which version of HTTP the message claims to speak.
    ///
    /// The dimension HTTP/1.1 adds to everything else.  RFC 9112 is not a
    /// replacement for RFC 1945 on the wire -- a server speaks both, and has
    /// to decide which set of rules applies from the version on the request
    /// line.  Getting that decision wrong in either direction is a defect
    /// class of its own: applying 1.1's persistent-connection default to a 1.0
    /// client leaves it waiting for a close that never comes, and applying
    /// 1.0's rules to a 1.1 client throws away the connection reuse the whole
    /// version exists for.
    type Version =
        | V10
        | V11

    /// How the raw peer puts the message bytes on the wire.  A parser defect
    /// that is only detected because the whole message arrived in one read is
    /// not really detected, so every case is also delivered split.  Dribble is
    /// one byte per write with the event loop pumped between them, which is
    /// what actually forces an incremental parser to hold its state across
    /// reads.
    ///
    /// Pipelined is the HTTP/1.1 addition and a different kind of claim: two
    /// complete messages in one write.  RFC 9112 section 9.3.2 permits a
    /// client to send them that way and requires the server to answer "in the
    /// same order that the requests were received", so this is the delivery
    /// mode that asks whether the receiver keeps parsing after one message is
    /// complete rather than waiting for a read event that has already
    /// happened.
    type Delivery =
        | OneWrite
        | TwoWrites
        | Dribble
        | Pipelined

    /// What the server must put back on the wire.
    ///
    /// Status(n) is the strong form: the RFC names a code for this situation
    /// and nothing else will do.  NotSuccess is for the cases the RFCs leave
    /// open -- an incomplete request, where both answering an error and
    /// closing are defensible -- and asserts only that the server must not
    /// report success.  Which of the two applies is itself a claim about the
    /// RFC, so `completeRequestsAreAnswered` below pins it down.
    type Outcome =
        | Status(int)
        /* an error status (>= 400) or a close; the RFC pins neither */
        | NotSuccess
        /* RFC 1945 section 5: a Simple-Request is answered with a
         * Simple-Response -- the body alone, with no status line and no
         * headers.  The only response shape in HTTP that carries no status. */
        | SimpleResponse

    /// Whether a message-body must accompany the response.
    type BodyExpect =
        /* exactly the bytes the request carried: the test server echoes */
        | BodyEchoed
        /* RFC 1945 section 8.2 / RFC 9110 section 9.3.2: the response to HEAD
         * must not carry a body, whatever its Content-Length says */
        | BodyAbsent
        /* an error body is the server's business */
        | BodyAny

    /// What must become of the connection once the response is complete.
    ///
    /// RFC 1945 section 1.4: "The connection is closed by the server after
    /// sending the response."  HTTP/1.0 has no persistent connections; the
    /// Keep-Alive extension (RFC 2068 section 19.7.1) is opt-in and only the
    /// client may open the subject, which is why MayPersist exists only for a
    /// request that asked for it.
    ///
    /// HTTP/1.1 inverted the default (RFC 9112 section 9.1: "HTTP/1.1 defaults
    /// to the use of persistent connections"), and section 9.6 makes the
    /// escape hatch explicit rather than silent: "A server that does not
    /// support persistent connections MUST send the close connection option in
    /// every response message that does not have a 1xx status code."  So
    /// MustPersist is not "the server may never close" -- it is the pair of
    /// obligations that MUST creates: either the connection survives and can
    /// carry another request, or the response said so.  A server that closes
    /// without saying so races every client that was about to reuse it.
    type PersistExpect =
        | MustClose
        /* the client offered Keep-Alive to an HTTP/1.0 server: it may hold the
         * connection open, but only if it said so in the response */
        | MayPersist
        /* HTTP/1.1: the connection carries another request afterwards, unless
         * the response announced its close */
        | MustPersist

    /// Whether a 1xx interim response may precede the final one.
    ///
    /// RFC 9110 section 10.1.1: "A server that receives a 100-continue
    /// expectation in an HTTP/1.0 request MUST ignore that expectation" --
    /// because an HTTP/1.0 client has no way to know that a 1xx is interim and
    /// will read it as the response.  At HTTP/1.1 the server may answer the
    /// expectation with 100 (Continue) or go straight to a final status, so
    /// both shapes conform and only "a 1xx where none is allowed" is a defect.
    type InterimExpect =
        | InterimNone      /* no 1xx may precede the final response    */
        | InterimAllowed   /* a 100 Continue may, but need not, precede it */

    /// What the reflected probe header must say.  The test server echoes the
    /// request's X-Probe back, which is how the driver sees what the server's
    /// header parser actually produced rather than only whether it survived.
    type ProbeExpect =
        | ProbeAbsent      /* the message carried no probe header      */
        | ProbeValue       /* the probe's value, LWS stripped          */
        | ProbeEmpty       /* present with an empty value -- legal     */
        | ProbeTwice       /* sent twice; both must reach the receiver */
        | ProbeAny         /* parsed, but the RFC does not pin the value */
}

/* ===================================================================== *
 * The positive matrix: requests an HTTP/1.x server must serve
 * ===================================================================== */

module http1x_requests {

    import http1x.*

    /// Methods.  RFC 1945 section 8 and RFC 9110 section 9.1: "the methods GET
    /// and HEAD MUST be supported by all general-purpose servers"; POST is the
    /// third method RFC 1945 defines, and the only one of those three that
    /// carries content.
    ///
    /// PUT and DELETE are RFC 9110 section 9.3.4 and 9.3.5, so they are
    /// generated at HTTP/1.1 alone -- RFC 1945 mentions them only in its list
    /// of methods other specifications might define.  They are here because
    /// libevpl's parser accepts them, and a method the parser accepts but
    /// nothing exercises is a method whose framing nothing has checked: PUT
    /// carries content the way POST does, and DELETE does not.
    type MethodCls =
        | MGet
        | MHead
        | MPost
        | MPut
        | MDelete

    /// Whether the method is one this matrix attaches content to.  RFC 9110
    /// section 9.3 gives PUT and POST content and gives GET, HEAD and DELETE
    /// none -- "A client SHOULD NOT generate content in a DELETE request".
    pure def carriesContent(m: MethodCls): bool =
        m == MPost or m == MPut

    /// Request-URI shapes (RFC 1945 section 5.1.2 / RFC 9112 section 3.2).
    type UriCls =
        | UriRoot          /* "/"                                      */
        | UriPath          /* a normal path                            */
        | UriQuery         /* path plus a query string                 */
        | UriEscaped       /* percent-encoded octets, passed through   */
        | UriLong          /* long, but well within any sane limit     */
        /* RFC 9112 section 3.2.2: "a server MUST accept the absolute-form in
         * requests, even though most HTTP/1.1 clients will only send the
         * absolute-form to a proxy".  Not an HTTP/1.0 shape towards an origin
         * server -- RFC 1945 section 5.1.2 allows absoluteURI only towards a
         * proxy -- so this is generated at HTTP/1.1 alone. */
        | UriAbsolute

    /// Header-block shapes.  Each is a property of RFC 1945 section 4.2 / RFC
    /// 9112 section 5 grammar that a hand-written parser can get wrong
    /// independently.  The headers the framing requires -- Host at HTTP/1.1,
    /// Content-Length or Transfer-Encoding where there is a body -- are added
    /// by the builder rather than being classes here, the same way the model
    /// does not make "sent a request line" a class.
    type HdrCls =
        | HdrNone          /* no header fields beyond the required ones */
        | HdrPlain         /* one ordinary header                      */
        | HdrPadded        /* LWS either side of the value, stripped   */
        | HdrEmpty         /* "X-Probe:" -- an empty value is legal    */
        | HdrMixedCase     /* field names are case-insensitive         */
        | HdrFolded        /* a continuation line (LWS-prefixed)       */
        | HdrDuplicate     /* the same field twice                     */
        | HdrMany          /* a block of many distinct fields          */

    /// Request-body shapes.
    ///
    /// HTTP/1.0 delimits a request body by Content-Length alone.  HTTP/1.1
    /// added the chunked transfer coding (RFC 9112 section 7.1), which is the
    /// framing for a body whose size the sender does not know when it starts
    /// sending -- and which every HTTP/1.1 recipient MUST be able to parse
    /// (section 7.1: "A recipient MUST be able to parse and decode the chunked
    /// transfer coding").  The chunked shapes are therefore generated at
    /// HTTP/1.1 only; a chunked HTTP/1.0 request is a defect, not a case here.
    type BodyCls =
        | BodyNone         /* no length, no body                       */
        | BodyEmpty        /* "Content-Length: 0"                      */
        | BodyOne          /* one byte                                 */
        | BodySmall        /* a few dozen bytes                        */
        | BodyLarge        /* larger than one read buffer              */
        | BodyChunked      /* one chunk, then the last-chunk           */
        /* "chunk-ext" -- RFC 9112 section 7.1.1.  A recipient that does not
         * understand an extension "MUST ignore" it, so a size line carrying
         * one still delimits the same chunk. */
        | BodyChunkedExt
        /* A trailer section after the last chunk (RFC 9112 section 7.1.2).
         * The part of the coding most often left unimplemented, because a
         * parser can produce the right body without ever consuming it -- and
         * then leave the trailer to be read as the start of the next request
         * on a connection HTTP/1.1 keeps open by default. */
        | BodyChunkedTrailer
        | BodyChunkedMany  /* many chunks, spanning read buffers       */

    /// What the client says about the connection.
    type ConnCls =
        | ConnDefault      /* no Connection header: the version decides */
        | ConnKeepAlive    /* "Connection: keep-alive"                 */
        /* "Connection: close" -- RFC 9112 section 9.6.  The HTTP/1.1 way to
         * ask for what HTTP/1.0 did by default, and a peer that has said it is
         * done cannot be argued with at either version. */
        | ConnClose

    /// Whether the client sends an Expect: 100-continue (RFC 9110 section
    /// 10.1.1).  Only meaningful on a request that has a body to withhold.
    type ExpectCls =
        | ExpectNone
        | ExpectContinue

    type Case = {
        ver: Version,
        method: MethodCls,
        uri: UriCls,
        hdr: HdrCls,
        body: BodyCls,
        conn: ConnCls,
        expect: ExpectCls,
        delivery: Delivery
    }

    var current: Case

    /// The response the specification requires for `current`.  State
    /// variables rather than derived expressions so that they travel in the
    /// generated ITF trace: the trace, not the model, is what the C driver
    /// consumes, so the prediction has to be in it.
    var expected: Outcome
    var expectBody: BodyExpect
    var expectProbe: ProbeExpect
    var expectPersist: PersistExpect
    var expectInterim: InterimExpect

    // ------------------------------------------------------------------
    // The specification
    // ------------------------------------------------------------------

    /// RFC 1945 section 8.2 and RFC 9110 section 9.3.2: "The HEAD method is
    /// identical to GET except that the server MUST NOT send content in the
    /// response."  The header fields, Content-Length included, stay exactly as
    /// they would have been for GET -- so this is not "a response with no
    /// content", it is a response whose declared body is deliberately absent
    /// from the wire, and the only component that can suppress it is the one
    /// that knows both the request method and the outbound framing.
    pure def bodyRequired(m: MethodCls): BodyExpect =
        match m {
            | MHead => BodyAbsent
            | _ => BodyEchoed
        }

    /// What the server's header parser must have produced.  Everything here is
    /// RFC 1945 section 4.2 grammar except HdrFolded: both RFCs allow a
    /// recipient to replace the folding LWS with a single SP (RFC 9112 section
    /// 5.2 makes that one of the two conforming answers), so the exact bytes
    /// are not pinned down and only "the header arrived" is required.
    pure def probeRequired(h: HdrCls): ProbeExpect =
        match h {
            | HdrNone => ProbeAbsent
            | HdrPlain => ProbeValue
            /* "field-value ... may be preceded by any amount of LWS, though a
             * single SP is preferred" -- leading and trailing LWS is not part
             * of the value */
            | HdrPadded => ProbeValue
            | HdrEmpty => ProbeEmpty
            /* "Field names are case-insensitive" */
            | HdrMixedCase => ProbeValue
            | HdrFolded => ProbeAny
            /* "Multiple message-header fields with the same field-name may be
             * present in a message" -- neither copy may be dropped */
            | HdrDuplicate => ProbeTwice
            | HdrMany => ProbeValue
        }

    /// Who decides the connection's fate.
    ///
    /// An explicit "close" always wins, at either version.  Otherwise the
    /// version decides: RFC 1945 section 1.4 has an HTTP/1.0 server close
    /// unless the client opened the Keep-Alive subject, and even then the
    /// server has to have agreed in the response -- which the driver checks.
    /// RFC 9112 section 9.1 inverts that, so an HTTP/1.1 request without a
    /// close leaves a connection another request can be sent on.
    pure def persistRequired(v: Version, c: ConnCls): PersistExpect =
        match c {
            | ConnClose => MustClose
            | ConnKeepAlive => if (v == V11) MustPersist else MayPersist
            | ConnDefault => if (v == V11) MustPersist else MustClose
        }

    /// RFC 9110 section 10.1.1, in both directions: an HTTP/1.0 request's
    /// 100-continue expectation MUST be ignored, and an HTTP/1.1 request's may
    /// be answered with the interim response or not at all.
    pure def interimRequired(v: Version, e: ExpectCls): InterimExpect =
        match e {
            | ExpectNone => InterimNone
            | ExpectContinue => if (v == V11) InterimAllowed else InterimNone
        }

    action use(c: Case): bool = all {
        current' = c,
        expected' = Status(200),
        expectBody' = bodyRequired(c.method),
        expectProbe' = probeRequired(c.hdr),
        expectPersist' = persistRequired(c.ver, c.conn),
        expectInterim' = interimRequired(c.ver, c.expect)
    }

    // ------------------------------------------------------------------
    // Case generation
    // ------------------------------------------------------------------

    pure val VERSIONS = Set(V10, V11)

    /// RFC 1945 defines GET, HEAD and POST; PUT and DELETE arrive with RFC
    /// 9110, so an HTTP/1.0 request using one is not a case this matrix
    /// claims a server must serve.
    pure val METHODS_10 = Set(MGet, MHead, MPost)
    pure val METHODS_11 = METHODS_10.union(Set(MPut, MDelete))
    pure val HDRS = Set(HdrNone, HdrPlain, HdrPadded, HdrEmpty, HdrMixedCase,
                        HdrFolded, HdrDuplicate, HdrMany)
    pure val CONNS = Set(ConnDefault, ConnKeepAlive, ConnClose)

    /// The absolute-form request-target is an HTTP/1.1 obligation towards an
    /// origin server; at HTTP/1.0 it is a proxy form and nothing requires an
    /// origin server to take it.
    pure val URIS_10 = Set(UriRoot, UriPath, UriQuery, UriEscaped, UriLong)
    pure val URIS_11 = URIS_10.union(Set(UriAbsolute))

    /// GET and HEAD define no semantics for a request body (RFC 1945 sections
    /// 8.1/8.2, RFC 9110 section 9.3.1), so the matrix does not attach one; a
    /// GET with a body is a request-smuggling question rather than a
    /// conformance one, and belongs in the defect taxonomy if anywhere.
    pure val BODIES_NO_ENTITY = Set(BodyNone, BodyEmpty)

    /// RFC 1945 section 8.3: "A valid Content-Length is required on all
    /// HTTP/1.0 POST requests."  BodyNone is therefore not a legal HTTP/1.0
    /// POST and lives in the defect model as PostWithoutContentLength.
    pure val BODIES_ENTITY_10 = Set(BodyEmpty, BodyOne, BodySmall, BodyLarge)

    /// HTTP/1.1 adds the chunked coding, and a request with neither a length
    /// nor a coding simply has no body (RFC 9112 section 6.3), so BodyNone is
    /// a legal HTTP/1.1 POST as well.
    pure val BODIES_ENTITY_11 =
        BODIES_ENTITY_10.union(Set(BodyNone, BodyChunked, BodyChunkedExt,
                                   BodyChunkedTrailer, BodyChunkedMany))

    /// One byte per write costs a syscall and an event-loop turn per byte, so
    /// it is confined to the bodies where that is cheap.  The larger bodies are
    /// still delivered split, just not a byte at a time.
    pure val BODIES_DRIBBLEABLE = Set(BodyNone, BodyEmpty, BodyOne, BodySmall,
                                      BodyChunked, BodyChunkedExt,
                                      BodyChunkedTrailer)

    pure def urisFor(v: Version): Set[UriCls] =
        if (v == V11) URIS_11 else URIS_10

    pure def methodsFor(v: Version): Set[MethodCls] =
        if (v == V11) METHODS_11 else METHODS_10

    pure def bodiesFor(v: Version, m: MethodCls): Set[BodyCls] =
        if (not(carriesContent(m))) {
            BODIES_NO_ENTITY
        } else if (v == V11) {
            BODIES_ENTITY_11
        } else {
            BODIES_ENTITY_10
        }

    /// An expectation is about a body the client is holding back, so it only
    /// belongs on a request that has one to hold back.
    pure def expectsFor(m: MethodCls): Set[ExpectCls] =
        if (carriesContent(m)) Set(ExpectNone, ExpectContinue)
        else Set(ExpectNone)

    /// Which deliveries a case can be sent by.
    ///
    /// Pipelining needs a connection that survives the first response, so it is
    /// HTTP/1.1 without an explicit close.  RFC 9112 section 9.3.2 also asks a
    /// client not to pipeline non-idempotent methods ("A client MUST NOT
    /// pipeline immediately after connection establishment" and "idempotent
    /// methods ... are significantly less likely to cause problems"), so POST
    /// is left out: what is under test is the server's ordering obligation,
    /// and a method the RFC discourages pipelining does not test it better.
    pure def deliveriesFor(c: Case): Set[Delivery] =
        if (c.ver == V11 and c.conn != ConnClose and not(carriesContent(c.method))) {
            if (BODIES_DRIBBLEABLE.contains(c.body)) {
                Set(OneWrite, TwoWrites, Dribble, Pipelined)
            } else {
                Set(OneWrite, TwoWrites, Pipelined)
            }
        } else if (BODIES_DRIBBLEABLE.contains(c.body)) {
            Set(OneWrite, TwoWrites, Dribble)
        } else {
            Set(OneWrite, TwoWrites)
        }

    action pick = {
        nondet v = VERSIONS.oneOf()
        nondet m = methodsFor(v).oneOf()
        nondet u = urisFor(v).oneOf()
        nondet h = HDRS.oneOf()
        nondet c = CONNS.oneOf()
        nondet b = bodiesFor(v, m).oneOf()
        nondet e = expectsFor(m).oneOf()
        nondet d = deliveriesFor({ ver: v, method: m, uri: u, hdr: h, body: b,
                                   conn: c, expect: e,
                                   delivery: OneWrite }).oneOf()
        use({ ver: v, method: m, uri: u, hdr: h, body: b, conn: c, expect: e,
              delivery: d })
    }

    action init = use({ ver: V10, method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite })

    action step = pick

    // ------------------------------------------------------------------
    // Invariants: every generated case is a legal HTTP/1.x request
    // ------------------------------------------------------------------

    /// The whole point of the positive matrix: none of these is a defect, so
    /// every one of them must be served.  A case that expected anything else
    /// would belong in the other model.
    val everyCaseSucceeds = expected == Status(200)

    /// A POST body must be one the version has a framing for, and a GET/HEAD
    /// must not carry an entity -- otherwise this model would be emitting
    /// requests the RFCs do not require a server to accept while labelling
    /// them legal.
    val bodyMatchesMethod =
        bodiesFor(current.ver, current.method).contains(current.body)

    /// The two shapes HTTP/1.1 introduced are never generated at HTTP/1.0,
    /// where they are not legal requests at all.
    val elevenOnlyShapesAreElevenOnly = and {
        (current.uri == UriAbsolute) implies (current.ver == V11),
        (current.delivery == Pipelined) implies (current.ver == V11),
        methodsFor(current.ver).contains(current.method)
    }

    /// The HEAD rule, stated where it cannot be missed: a body is required on
    /// the wire for exactly the methods that are not HEAD.
    val headCarriesNoBody =
        (current.method == MHead) iff (expectBody == BodyAbsent)

    /// The connection default, both ways round.  An HTTP/1.0 client that did
    /// not ask for Keep-Alive gets a close; an HTTP/1.1 client that did not
    /// ask for a close gets a connection it can reuse.
    val versionDecidesTheDefault = and {
        (current.ver == V10 and current.conn == ConnDefault)
            implies (expectPersist == MustClose),
        (current.ver == V11 and current.conn == ConnDefault)
            implies (expectPersist == MustPersist),
        (current.conn == ConnClose) implies (expectPersist == MustClose)
    }

    /// A pipelined case has to be one whose connection survives the first
    /// response, or the second request in the write has nowhere to be
    /// answered.
    val pipeliningNeedsAPersistentConnection =
        (current.delivery == Pipelined) implies (expectPersist == MustPersist)

    /// RFC 9110 section 10.1.1: only an HTTP/1.1 request may draw an interim
    /// response, and only one that asked for it.
    val interimOnlyWhereItIsUnderstood =
        (expectInterim == InterimAllowed) iff
        (current.ver == V11 and current.expect == ExpectContinue)

    val wellFormed =
        everyCaseSucceeds and bodyMatchesMethod and
        elevenOnlyShapesAreElevenOnly and headCarriesNoBody and
        versionDecidesTheDefault and pipeliningNeedsAPersistentConnection and
        interimOnlyWhereItIsUnderstood

    // ------------------------------------------------------------------
    // Scenario tests
    // ------------------------------------------------------------------

    /// The minimal HTTP/1.0 exchange: a bare GET with no headers at all.
    /// Legal precisely because HTTP/1.0 has no required header -- Host became
    /// mandatory only in HTTP/1.1.
    run bareGetTest =
        init
            .expect(expected == Status(200) and expectProbe == ProbeAbsent
                    and expectPersist == MustClose)

    /// HEAD is GET without the body, at either version.
    run headSuppressesTheBodyTest =
        init
            .then(use({ ver: V10, method: MHead, uri: UriPath, hdr: HdrPlain,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectBody == BodyAbsent and expected == Status(200))
            .then(use({ ver: V11, method: MHead, uri: UriPath, hdr: HdrPlain,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectBody == BodyAbsent)
            .then(use({ ver: V11, method: MGet, uri: UriPath, hdr: HdrPlain,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectBody == BodyEchoed)

    /// The header-grammar cases whose value the driver checks exactly.  These
    /// are the three a parser built on strtok and strcmp gets wrong
    /// independently of one another.
    run headerGrammarTest =
        init
            .then(use({ ver: V11, method: MGet, uri: UriPath, hdr: HdrPadded,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectProbe == ProbeValue)
            .then(use({ ver: V10, method: MGet, uri: UriPath, hdr: HdrEmpty,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: Dribble }))
            .expect(expectProbe == ProbeEmpty and expected == Status(200))
            .then(use({ ver: V11, method: MGet, uri: UriPath, hdr: HdrMixedCase,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: TwoWrites }))
            .expect(expectProbe == ProbeValue)
            .then(use({ ver: V10, method: MGet, uri: UriPath, hdr: HdrDuplicate,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectProbe == ProbeTwice)

    /// A POST is the one method here that carries an entity.  At HTTP/1.0 its
    /// length is carried by Content-Length alone; at HTTP/1.1 the chunked
    /// coding is the other way, and the one that does not need the size known
    /// in advance.
    run postCarriesAnEntityTest =
        init
            .then(use({ ver: V10, method: MPost, uri: UriPath, hdr: HdrPlain,
                        body: BodyLarge, conn: ConnDefault, expect: ExpectNone,
                        delivery: TwoWrites }))
            .expect(expectBody == BodyEchoed and bodyMatchesMethod)
            .then(use({ ver: V11, method: MPost, uri: UriPath, hdr: HdrNone,
                        body: BodyChunked, conn: ConnDefault,
                        expect: ExpectNone, delivery: Dribble }))
            .expect(expectBody == BodyEchoed and bodyMatchesMethod)
            .then(use({ ver: V11, method: MPost, uri: UriPath, hdr: HdrNone,
                        body: BodyChunkedTrailer, conn: ConnDefault,
                        expect: ExpectNone, delivery: OneWrite }))
            .expect(bodyMatchesMethod and wellFormed)

    /// PUT carries content and DELETE does not, and neither is an HTTP/1.0
    /// method as far as this matrix is concerned.
    run putAndDeleteAreElevenOnlyTest =
        init
            .expect(methodsFor(V10).contains(MPut) == false)
            .expect(methodsFor(V11).contains(MPut))
            .expect(carriesContent(MPut) and not(carriesContent(MDelete)))
            .then(use({ ver: V11, method: MPut, uri: UriPath, hdr: HdrPlain,
                        body: BodySmall, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectBody == BodyEchoed and wellFormed)
            .then(use({ ver: V11, method: MDelete, uri: UriPath, hdr: HdrNone,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: Pipelined }))
            .expect(expectBody == BodyEchoed and wellFormed)

    /// The chunked coding is HTTP/1.1's and nothing else's: an HTTP/1.0 POST
    /// has no framing for it, so the model never generates one.
    run chunkedIsElevenOnlyTest =
        init
            .expect(bodiesFor(V10, MPost).contains(BodyChunked) == false)
            .expect(bodiesFor(V11, MPost).contains(BodyChunked))

    /// The connection default inverts with the version, which is the single
    /// most consequential difference between the two.
    run persistenceInvertsWithVersionTest =
        init
            .then(use({ ver: V10, method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectPersist == MustClose)
            .then(use({ ver: V11, method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectPersist == MustPersist)
            .then(use({ ver: V11, method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnClose, expect: ExpectNone,
                        delivery: OneWrite }))
            .expect(expectPersist == MustClose)
            .then(use({ ver: V10, method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnKeepAlive,
                        expect: ExpectNone, delivery: OneWrite }))
            .expect(expectPersist == MayPersist)

    /// Pipelining is the delivery mode that asks whether the server keeps
    /// parsing once a request is complete, and it needs a connection that
    /// outlives the first response.
    run pipeliningNeedsPersistenceTest =
        init
            .then(use({ ver: V11, method: MGet, uri: UriPath, hdr: HdrNone,
                        body: BodyNone, conn: ConnDefault, expect: ExpectNone,
                        delivery: Pipelined }))
            .expect(expectPersist == MustPersist and wellFormed)

    /// An HTTP/1.0 client cannot be sent an interim response, because it has
    /// no way to tell one from the answer.
    run interimIsElevenOnlyTest =
        init
            .then(use({ ver: V10, method: MPost, uri: UriPath, hdr: HdrNone,
                        body: BodySmall, conn: ConnDefault,
                        expect: ExpectContinue, delivery: OneWrite }))
            .expect(expectInterim == InterimNone)
            .then(use({ ver: V11, method: MPost, uri: UriPath, hdr: HdrNone,
                        body: BodySmall, conn: ConnDefault,
                        expect: ExpectContinue, delivery: OneWrite }))
            .expect(expectInterim == InterimAllowed)

    run everyGeneratedCaseIsLegalTest =
        init
            .then(pick)
            .expect(wellFormed)
            .then(pick)
            .expect(wellFormed)
            .then(pick)
            .expect(wellFormed)
}

/* ===================================================================== *
 * The negative matrix: requests an HTTP/1.x server must refuse, and how
 * ===================================================================== */

module http1x_defects {

    import http1x.*

    /// Mirrors of libevpl's limits, which the driver must exceed to reach the
    /// two overflow cases.  They are the defaults
    /// evpl_global_config_set_http_max_header_size() adjusts and the size of
    /// the parser's line buffer; the driver asserts they still hold.
    pure val MaxHeaderSize = 8192
    pure val MaxHeaderLine = 4096

    type Defect =
        /* --- baseline: proves the injector can build a VALID request ---- */
        | NoDefect

        /* --- the Request-Line (RFC 1945 section 5.1 / RFC 9112 s3) ------ */
        /* "The server should respond with 501 (Not Implemented) if the
         * method is unrecognized or not implemented" -- an answer, not a
         * hang-up: a client that gets silence cannot tell an unsupported
         * method from a broken server, and will retry. */
        | MethodUnknown
        /* Method is a token and tokens are case-sensitive (section 5.1.1),
         * so "get" is not GET.  Same treatment as any other unknown method,
         * which is the point: a server that lowercases before comparing
         * accepts a request the grammar does not describe. */
        | MethodLowercase
        | MethodEmpty                  /* the line starts with SP           */
        | RequestLineOneToken          /* a method and nothing else         */
        | RequestLineExtraToken        /* a fourth token after the version  */
        /* RFC 1945 section 5: a request line with no version is an HTTP/0.9
         * Simple-Request, and section 6 pairs it with a Simple-Response --
         * the body alone.  The one situation in which a status line is not
         * merely unnecessary but wrong, since an HTTP/0.9 client would read
         * it as the start of the entity.  Obsolete -- RFC 9112 dropped the
         * form entirely -- which is why the driver records this one rather
         * than treating it as urgent. */
        | RequestLineNoVersion
        /* RFC 9112 section 2.2: "In the interest of robustness, a server that
         * is expecting to receive and parse a request-line SHOULD ignore at
         * least one empty line (CRLF) received prior to the request-line."
         * The CRLF a buggy client leaves behind after a previous request's
         * body; a server that does not skip it answers 400 to a request that
         * is otherwise perfectly good. */
        | LeadingCrlfBeforeRequestLine
        /* The same tolerance asked to run forever.  "Ignore at least one empty
         * line" is not an offer to read empty lines from this peer
         * indefinitely, so there has to be a point at which the server stops
         * -- otherwise a rule about robustness is a way to hold a connection
         * open at no cost to the peer. */
        | LeadingCrlfFlood

        /* --- the version (RFC 1945 section 3.1 / RFC 9112 section 2.3) --- */
        | VersionMalformed             /* "HTTP/1", "HTTP/x.y"              */
        | VersionMajorUnsupported      /* "HTTP/2.0" on a text request line */
        /* "HTTP/1.1 is upward compatible with HTTP/1.0" and section 3.1
         * makes minor numbers forward-compatible: a higher minor is a
         * request the server must serve at the version it does speak, not
         * one it may refuse.  RFC 2145 section 2.3 and RFC 9112 section 2.3
         * state the rule explicitly. */
        | VersionMinorUnknown          /* "HTTP/1.9"                        */

        /* --- the Request-URI -------------------------------------------- */
        /* A URI past whatever the server is willing to hold.  RFC 1945 names
         * no code for it (414 is an HTTP/1.1 addition), so only "not a
         * success" is required -- but silently serving a TRUNCATED URI is a
         * different resource than the one asked for, which is why this is
         * here at all. */
        | UriTooLong

        /* --- header fields (RFC 1945 section 4.2 / RFC 9112 section 5) --- */
        | HeaderNoColon                /* not a field at all                */
        | HeaderNameEmpty              /* ": value"                         */
        /* "field-name ':' [ field-value ]" with field-name a token: a space
         * before the colon is not a field name.  RFC 9112 section 5.1 makes
         * refusing it a MUST, and names the reason -- accepting it is how a
         * request smuggles a header past a front end that rejects it. */
        | HeaderSpaceBeforeColon
        | HeaderLineOverlong           /* one field longer than the buffer  */
        | HeaderBlockOverlong          /* the block past max_header_size    */
        /* A continuation line as the FIRST line of the block: LWS says it
         * continues the field above, and there is no field above.  The one
         * shape of fold that is not a fold, and the one a parser reaching for
         * "the last header on the list" dereferences NULL on. */
        | HeaderFoldedFirst
        /* The client stops mid-block and half-closes.  The request never
         * became a request, so there is nothing to answer: this is the one
         * shape where silence is a legitimate response. */
        | HeaderBlockUnterminated

        /* --- Host (RFC 9112 section 3.2) -------------------------------- */
        /* "A server MUST respond with a 400 (Bad Request) status code to any
         * HTTP/1.1 request message that lacks a Host header field and to any
         * request message that contains more than one Host header field or a
         * Host header field with an invalid field value."  Not an HTTP/1.0
         * rule at all -- RFC 1945 has no Host -- so the same request is a
         * perfectly good HTTP/1.0 one, which is what makes this pair worth
         * generating at both versions rather than one. */
        | HostMissing
        | HostDuplicate

        /* --- line endings ----------------------------------------------- */
        /* RFC 1945 section 19.3 and RFC 9112 section 2.2: "Although the line
         * terminator for the start-line and fields is the sequence CRLF, a
         * recipient MAY recognize a single LF as a line terminator and ignore
         * any preceding CR."  RECOMMENDED, not required -- recorded here
         * because a server that rejects it is interoperating worse than the
         * RFC asks, not because it is violating a MUST. */
        | BareLfLineEndings

        /* --- the entity (RFC 1945 sections 7.2/10.4, RFC 9112 s6) -------- */
        /* Content-Length is "the length of the message-body ... expressed as
         * a decimal number of octets".  Neither of the first two is one, and
         * a server that runs them through strtoul reads 0 and treats a
         * request with an entity as one without -- the classic desync. */
        | ContentLengthNotNumeric
        | ContentLengthNegative
        /* A length with digits and then something else.  Reads as the digits
         * alone to a parser that stops at the first non-digit, which is a
         * different length from the one the sender wrote -- and the difference
         * is where the next message starts. */
        | ContentLengthTrailingJunk
        /* RFC 9110 section 8.6: "a recipient MUST anticipate potentially large
         * decimal numerals and prevent parsing errors due to integer
         * conversion overflows".  A length past what the receiver can
         * represent wraps to a smaller one: the same desync arrived at by
         * arithmetic rather than by syntax. */
        | ContentLengthOverflow
        /* Two lengths that disagree: the message has no single length, so it
         * cannot be parsed at all.  Picking either one is picking where the
         * next request starts, which is the peer's decision to make and not
         * the server's. */
        | ContentLengthDuplicateConflicting
        /* Content-Length promises more than the client sends before it
         * half-closes: an incomplete entity, so no success. */
        | BodyShortOfContentLength
        /* RFC 1945 section 8.3: "A valid Content-Length is required on all
         * HTTP/1.0 POST requests.  An HTTP/1.0 server should respond with a
         * 400 (bad request) message if it cannot determine the length of the
         * request message's content."  HTTP/1.1 gave the same request a
         * defined meaning instead -- no content at all (RFC 9112 section
         * 6.3) -- so this is the other pair whose answer depends on the
         * version and on nothing else. */
        | PostWithoutContentLength

        /* --- transfer codings (RFC 9112 sections 6.1 and 6.3) ----------- */
        /* Section 6.3, rule 3: "If a message is received with both a
         * Transfer-Encoding and a Content-Length header field, the
         * Transfer-Encoding overrides the Content-Length.  Such a message
         * might indicate an attempt to perform request smuggling ... or
         * response splitting ... and ought to be handled as an error" -- and
         * RFC 9110 section 8.6 makes sending the pair a MUST NOT.  Two
         * framings that disagree leave the message boundary to the sender,
         * which is the same defect as two Content-Lengths and gets the same
         * answer. */
        | TransferEncodingWithContentLength
        /* Section 6.3, rule 4: "If a Transfer-Encoding header field is present
         * in a request and the chunked transfer coding is not the final
         * encoding, the message body length cannot be determined reliably;
         * the server MUST respond with the 400 (Bad Request) status code and
         * then close the connection." */
        | TransferEncodingChunkedNotFinal
        /* Chunked IS final, so the message is delimited -- but an inner
         * coding the server does not implement leaves it unable to do
         * anything with the content.  "A server that receives a request
         * message with a transfer coding it does not understand SHOULD
         * respond with 501 (Not Implemented)." */
        | TransferEncodingUnknownCoding
        /* Section 6.1: "A client MUST NOT send a request containing
         * Transfer-Encoding unless it knows the server will handle HTTP/1.1
         * (or later) requests."  That is a rule for the client; what a server
         * should do with such a request is not stated, so the 400 below is
         * this model's reading rather than a quoted requirement.  The reading:
         * a request that claims HTTP/1.0 and then uses a coding HTTP/1.0 does
         * not have is a message whose framing the two ends cannot agree on,
         * and a front end that reads the version while a back end reads the
         * coding disagree about where it ends -- the smuggling primitive
         * again.  Refusing is the only answer that cannot be got wrong. */
        | TransferEncodingOnHttp10
        /* A Transfer-Encoding field that names no coding at all.  The field is
         * present, so the message says a coding delimits it; the list is
         * empty, so none does.  Chunked is not the final coding, because there
         * is no final coding. */
        | TransferEncodingEmpty

        /* --- the chunked coding itself (RFC 9112 section 7.1) ----------- */
        /*     chunk-size = 1*HEXDIG
         * and nothing else.  A size run through strtoul reads "zz" as zero,
         * which is the last-chunk -- so the body ends early and everything
         * after it is parsed as the next request.  The chunked spelling of
         * the Content-Length desync, and the reason both need a real parser
         * rather than a library call that reports no errors. */
        | ChunkSizeNotHex
        | ChunkSizeNegative
        /* Hex digits and then something that is not a chunk extension.  RFC
         * 9112 section 7.1 allows only a chunk-ext after the size, introduced
         * by a semicolon; anything else means the line is not a chunk-size
         * line, and reading the digits while ignoring the rest is how a
         * decoder and its peer end up at different offsets. */
        | ChunkSizeTrailingJunk
        /* A size larger than the receiver can represent.  Wrapping it is how
         * a declared length becomes a much smaller one. */
        | ChunkSizeOverflow
        /* The CRLF that must follow a chunk's data is something else, so the
         * next size line is read from the middle of the body. */
        | ChunkBadTerminator
        /* The client half-closes having sent chunks but never the last-chunk:
         * the content is incomplete, so no success. */
        | ChunkNoLastChunk
        /* A chunk that declares more octets than the client sends. */
        | ChunkTruncated

    type Case = { defect: Defect, ver: Version, delivery: Delivery }

    var current: Case
    var expected: Outcome
    var expectPersist: PersistExpect

    // ------------------------------------------------------------------
    // The specification: (defect, version) -> required response
    // ------------------------------------------------------------------

    pure def required(d: Defect, v: Version): Outcome =
        match d {
            | NoDefect => Status(200)

            /* RFC 1945 section 9.5.2 / RFC 9110 section 15.6.2 */
            | MethodUnknown => Status(501)
            | MethodLowercase => Status(501)

            /* RFC 1945 section 9.4.1 / RFC 9110 section 15.5.1: "the server
             * cannot or will not process the request due to something that is
             * perceived to be a client error".  Every one of these is a
             * request line, a field or a chunk that does not match the
             * grammar, and every one of them is a complete request: the server
             * has all the bytes it will ever get and owes the client a
             * verdict. */
            | MethodEmpty => Status(400)
            | RequestLineOneToken => Status(400)
            | RequestLineExtraToken => Status(400)
            | VersionMalformed => Status(400)
            | VersionMajorUnsupported => Status(400)
            | HeaderNoColon => Status(400)
            | HeaderNameEmpty => Status(400)
            | HeaderSpaceBeforeColon => Status(400)
            | HeaderLineOverlong => Status(400)
            | HeaderBlockOverlong => Status(400)
            | ContentLengthNotNumeric => Status(400)
            | ContentLengthNegative => Status(400)
            | ContentLengthDuplicateConflicting => Status(400)
            | ContentLengthTrailingJunk => Status(400)
            | ContentLengthOverflow => Status(400)
            | HeaderFoldedFirst => Status(400)
            | HostDuplicate => Status(400)
            | TransferEncodingWithContentLength => Status(400)
            | TransferEncodingChunkedNotFinal => Status(400)
            | TransferEncodingOnHttp10 => Status(400)
            | ChunkSizeNotHex => Status(400)
            | ChunkSizeNegative => Status(400)
            | ChunkSizeOverflow => Status(400)
            | ChunkSizeTrailingJunk => Status(400)
            | TransferEncodingEmpty => Status(400)
            | ChunkBadTerminator => Status(400)

            /* A coding the server does not implement, on a message it can
             * still find the end of. */
            | TransferEncodingUnknownCoding => Status(501)

            /* The two whose answer is the version and nothing else. */
            | PostWithoutContentLength =>
                if (v == V10) Status(400) else Status(200)
            | HostMissing =>
                if (v == V11) Status(400) else Status(200)

            | RequestLineNoVersion => SimpleResponse

            /* Forward-compatible: served, not refused. */
            | VersionMinorUnknown => Status(200)

            /* Tolerances.  A server that takes them serves the request. */
            | BareLfLineEndings => Status(200)
            | LeadingCrlfBeforeRequestLine => Status(200)

            /* The tolerance's limit: past it the server owes the same answer
             * it owes any other header block it will not hold. */
            | LeadingCrlfFlood => Status(400)

            /* No code is specified and the request never completed, so an
             * error status and a close are both defensible; what is not is
             * answering 200 to a request the server never fully received. */
            | UriTooLong => NotSuccess
            | HeaderBlockUnterminated => NotSuccess
            | BodyShortOfContentLength => NotSuccess
            | ChunkNoLastChunk => NotSuccess
            | ChunkTruncated => NotSuccess
        }

    /// Which version a served request is served AT, which is not always the
    /// version on its request line: RFC 2145 section 2.3 has a higher minor
    /// served at the highest 1.x the server speaks.  It matters here because
    /// the connection default follows the version the response is written at.
    pure def servedVersion(d: Defect, v: Version): Version =
        match d {
            | VersionMinorUnknown => V11
            | _ => v
        }

    /// What must become of the connection.
    ///
    /// A refusal closes, at either version.  RFC 9112 section 6.3 says so in
    /// as many words for the framing defects ("MUST respond with the 400 (Bad
    /// Request) status code and then close the connection"), and the reason
    /// generalises to every other refusal here: the server has just said it
    /// cannot tell where this message ends, so it cannot tell where the next
    /// one starts either, and anything it reads after this point is the
    /// sender's choice rather than the receiver's.
    ///
    /// A request that IS served follows the ordinary rule for its version.
    pure def persistRequired(d: Defect, v: Version): PersistExpect =
        match required(d, v) {
            | Status(s) =>
                if (s == 200 and servedVersion(d, v) == V11) {
                    MayPersist
                } else {
                    MustClose
                }
            | _ => MustClose
        }

    action use(d: Defect, v: Version, t: Delivery): bool = all {
        current' = { defect: d, ver: v, delivery: t },
        expected' = required(d, v),
        expectPersist' = persistRequired(d, v)
    }

    // ------------------------------------------------------------------
    // Case generation
    // ------------------------------------------------------------------

    pure val DELIVERIES = Set(OneWrite, TwoWrites, Dribble)

    pure val DEFECTS = Set(
        NoDefect,
        MethodUnknown,
        MethodLowercase,
        MethodEmpty,
        RequestLineOneToken,
        RequestLineExtraToken,
        RequestLineNoVersion,
        LeadingCrlfBeforeRequestLine,
        VersionMalformed,
        VersionMajorUnsupported,
        VersionMinorUnknown,
        UriTooLong,
        HeaderNoColon,
        HeaderNameEmpty,
        HeaderSpaceBeforeColon,
        HeaderLineOverlong,
        HeaderBlockOverlong,
        HeaderBlockUnterminated,
        HeaderFoldedFirst,
        LeadingCrlfFlood,
        HostMissing,
        HostDuplicate,
        BareLfLineEndings,
        ContentLengthNotNumeric,
        ContentLengthNegative,
        ContentLengthDuplicateConflicting,
        ContentLengthTrailingJunk,
        ContentLengthOverflow,
        BodyShortOfContentLength,
        PostWithoutContentLength,
        TransferEncodingWithContentLength,
        TransferEncodingChunkedNotFinal,
        TransferEncodingUnknownCoding,
        TransferEncodingOnHttp10,
        TransferEncodingEmpty,
        ChunkSizeNotHex,
        ChunkSizeTrailingJunk,
        ChunkSizeNegative,
        ChunkSizeOverflow,
        ChunkBadTerminator,
        ChunkNoLastChunk,
        ChunkTruncated
    )

    /// At which versions a defect is a case at all.
    ///
    /// Three groups.  The defects that ARE a version -- a malformed one, an
    /// unsupported major, a higher minor, or none at all -- carry their
    /// version in the request line, so generating them twice would run the
    /// same bytes twice.  The chunked-coding defects need a version that has
    /// the chunked coding, and the one HTTP/1.0 defect about it needs the
    /// version that does not.  Everything else is a grammar rule both versions
    /// share, and is generated at both: a request line parser that is right at
    /// one version and wrong at the other is wrong.
    pure def versionsOf(d: Defect): Set[Version] =
        match d {
            | RequestLineNoVersion => Set(V10)
            | VersionMalformed => Set(V10)
            | VersionMajorUnsupported => Set(V10)
            | VersionMinorUnknown => Set(V10)
            | TransferEncodingOnHttp10 => Set(V10)
            | HostDuplicate => Set(V11)
            | TransferEncodingWithContentLength => Set(V11)
            | TransferEncodingChunkedNotFinal => Set(V11)
            | TransferEncodingUnknownCoding => Set(V11)
            | TransferEncodingEmpty => Set(V11)
            | ChunkSizeNotHex => Set(V11)
            | ChunkSizeNegative => Set(V11)
            | ChunkSizeTrailingJunk => Set(V11)
            | ChunkSizeOverflow => Set(V11)
            | ChunkBadTerminator => Set(V11)
            | ChunkNoLastChunk => Set(V11)
            | ChunkTruncated => Set(V11)
            | _ => Set(V10, V11)
        }

    action pick = {
        nondet d = DEFECTS.oneOf()
        nondet v = versionsOf(d).oneOf()
        nondet t = DELIVERIES.oneOf()
        use(d, v, t)
    }

    action init = use(NoDefect, V10, OneWrite)
    action step = pick

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    /// Totality check on `required`.  Quint's match is exhaustive, so a new
    /// Defect without a rule fails to typecheck rather than defaulting
    /// silently; this catches the reverse mistake, an Outcome the C driver
    /// would have no arm for.
    val outcomeIsSpecified =
        match expected {
            | Status(s) => s >= 100 and s <= 599
            | NotSuccess => true
            | SimpleResponse => true
        }

    /// The requirement that carries most of the weight here.  A request the
    /// server has received in full is a request it can judge, and the RFCs
    /// give it the vocabulary to say so -- 400 for syntax it cannot parse,
    /// 501 for a method or a coding it does not implement.  Hanging up instead
    /// tells the client nothing it can act on: it cannot distinguish a
    /// rejected request from a crashed server, a lost connection, or a
    /// middlebox, so it retries, and the same request is refused the same way
    /// forever.
    ///
    /// Only the shapes where the request genuinely never completed are exempt,
    /// and they are named individually so that adding a defect silently to the
    /// exempt set is not possible.
    val completeRequestsAreAnswered =
        match current.defect {
            | UriTooLong => expected == NotSuccess
            | HeaderBlockUnterminated => expected == NotSuccess
            | BodyShortOfContentLength => expected == NotSuccess
            | ChunkNoLastChunk => expected == NotSuccess
            | ChunkTruncated => expected == NotSuccess
            | _ =>
                match expected {
                    | NotSuccess => false
                    | _ => true
                }
        }

    /// A defect is not a reason to invent a new status class: everything the
    /// server refuses here has a code in RFC 9110 section 15, and a refusal
    /// must use it rather than, say, closing after a 200.
    val refusalsUseAnErrorStatus =
        match expected {
            | Status(s) => (s == 200) or (s >= 400 and s <= 599)
            | _ => true
        }

    /// Nothing the server refuses may leave the connection open, and a request
    /// it serves follows its version's default.  Stated as a consequence of
    /// the outcome rather than as a list, so a new defect cannot acquire a
    /// connection disposition that contradicts its status.
    val refusalsCloseTheConnection =
        match expected {
            | Status(s) =>
                if (s == 200 and servedVersion(current.defect, current.ver)
                    == V11) {
                    expectPersist == MayPersist
                } else {
                    expectPersist == MustClose
                }
            | _ => expectPersist == MustClose
        }

    /// A defect is only generated at a version where it is one.  The chunked
    /// cases in particular must never be emitted at HTTP/1.0, where the
    /// coding does not exist and the defect under test would be the version
    /// rather than the chunk.
    val defectsAreGeneratedWhereTheyApply =
        versionsOf(current.defect).contains(current.ver)

    val safety =
        outcomeIsSpecified and completeRequestsAreAnswered and
        refusalsUseAnErrorStatus and refusalsCloseTheConnection and
        defectsAreGeneratedWhereTheyApply

    // ------------------------------------------------------------------
    // Scenario tests: the outcomes most likely to be got wrong
    // ------------------------------------------------------------------

    /// The baseline.  If this one does not pass, nothing else the injector
    /// says about the server means anything.
    run injectorCanBuildAValidRequestTest =
        init
            .expect(expected == Status(200))

    /// An unimplemented method is answered, not hung up on -- and answered
    /// with the code that says which of the two things went wrong.
    run unknownMethodIsAnsweredTest =
        init
            .then(use(MethodUnknown, V11, OneWrite))
            .expect(expected == Status(501))
            .then(use(MethodLowercase, V10, Dribble))
            .expect(expected == Status(501))

    /// Malformed syntax is a 400, whichever part of the message it is in, and
    /// it is a 400 rather than a silent close.
    run malformedSyntaxIsFourHundredTest =
        init
            .then(use(HeaderNoColon, V11, OneWrite))
            .expect(expected == Status(400))
            .then(use(HeaderSpaceBeforeColon, V10, TwoWrites))
            .expect(expected == Status(400))
            .then(use(RequestLineExtraToken, V11, Dribble))
            .expect(expected == Status(400))
            .then(use(VersionMalformed, V10, OneWrite))
            .expect(expected == Status(400))

    /// A length that is not a length must not be read as zero: that turns a
    /// request with an entity into one without, and the entity into whatever
    /// the server reads next.
    run contentLengthMustParseTest =
        init
            .then(use(ContentLengthNotNumeric, V11, OneWrite))
            .expect(expected == Status(400))
            .then(use(ContentLengthNegative, V10, OneWrite))
            .expect(expected == Status(400))
            .then(use(ContentLengthDuplicateConflicting, V11, TwoWrites))
            .expect(expected == Status(400))

    /// The same rule one layer down: a chunk size that is not a size cannot
    /// delimit a chunk, and reading it as zero ends the content early and
    /// leaves the rest to be parsed as the next request.
    run chunkSizeMustParseTest =
        init
            .then(use(ChunkSizeNotHex, V11, OneWrite))
            .expect(expected == Status(400))
            .then(use(ChunkSizeNegative, V11, TwoWrites))
            .expect(expected == Status(400))
            .then(use(ChunkSizeOverflow, V11, OneWrite))
            .expect(expected == Status(400))
            .then(use(ChunkBadTerminator, V11, Dribble))
            .expect(expected == Status(400))

    /// Two framings that disagree are the same defect as two lengths that
    /// disagree, and a coding the server cannot apply is a different one.
    run conflictingFramingIsRefusedTest =
        init
            .then(use(TransferEncodingWithContentLength, V11, OneWrite))
            .expect(expected == Status(400))
            .then(use(TransferEncodingChunkedNotFinal, V11, OneWrite))
            .expect(expected == Status(400))
            .then(use(TransferEncodingUnknownCoding, V11, OneWrite))
            .expect(expected == Status(501))
            .then(use(TransferEncodingOnHttp10, V10, OneWrite))
            .expect(expected == Status(400))

    /// The two defects whose answer is the version and nothing else.  A
    /// request with no Host is a perfectly good HTTP/1.0 request and a
    /// refusable HTTP/1.1 one; a POST with no length is the other way round.
    run theVersionDecidesTest =
        init
            .then(use(HostMissing, V10, OneWrite))
            .expect(expected == Status(200))
            .then(use(HostMissing, V11, OneWrite))
            .expect(expected == Status(400))
            .then(use(PostWithoutContentLength, V10, OneWrite))
            .expect(expected == Status(400))
            .then(use(PostWithoutContentLength, V11, OneWrite))
            .expect(expected == Status(200) and expectPersist == MayPersist)

    /// A higher minor version is served, not refused: that is what makes the
    /// version number usable for negotiation at all.
    run higherMinorVersionIsServedTest =
        init
            .then(use(VersionMinorUnknown, V10, OneWrite))
            .expect(expected == Status(200) and expectPersist == MayPersist)
            .then(use(VersionMajorUnsupported, V10, OneWrite))
            .expect(expected == Status(400))

    /// An incomplete request is the one shape a server may answer with
    /// silence -- and the only one.
    run incompleteRequestsMayGoUnansweredTest =
        init
            .then(use(HeaderBlockUnterminated, V11, OneWrite))
            .expect(expected == NotSuccess and completeRequestsAreAnswered)
            .then(use(BodyShortOfContentLength, V10, TwoWrites))
            .expect(expected == NotSuccess and completeRequestsAreAnswered)
            .then(use(ChunkNoLastChunk, V11, OneWrite))
            .expect(expected == NotSuccess and completeRequestsAreAnswered)

    run everyDefectHasAnOutcomeTest =
        init
            .then(pick)
            .expect(safety)
            .then(pick)
            .expect(safety)
            .then(pick)
            .expect(safety)
}

/* ===================================================================== *
 * The client direction: responses an HTTP/1.x client must cope with
 * ===================================================================== */

module http1x_client {

    import http1x.*

    /// What the client must do with the response.
    ///
    /// The two arms are the whole point.  A request that was dispatched has a
    /// caller waiting on it, and that caller is owed exactly one answer --
    /// the response, or the news that there will not be one.  There is
    /// deliberately no third arm for "nothing happens": a client that frees a
    /// request without telling anyone has not failed the request, it has
    /// abandoned the caller, and no amount of correct behaviour elsewhere
    /// makes up for it.
    type ClientOutcome =
        /* the response is delivered: its status is reported, and the body
         * that belongs to it arrives complete */
        | CbComplete(int)
        /* the request completes as a failure.  Which way is left open --
         * libevpl's notify callback carries no status, so requiring a
         * particular spelling would be requiring an API change rather than
         * stating an obligation.  What is not open is that the caller is
         * told. */
        | CbFailed

    /// What the caller must end up holding.
    type ClientBody =
        | BodyDelivered    /* exactly the bytes the response carried    */
        | BodyNone         /* the response has none, and none may be reported */
        | BodyUnchecked    /* a failed request says nothing about a body */

    /// Which method the request used.  The HEAD rule needs it because it
    /// changes what the response means; POST because it is the one method of
    /// the three that carries a request body, and a request body is the
    /// client's own outbound framing rather than anything the peer chose.
    type ClientMethod =
        | CGet
        | CHead
        | CPost

    /// How the caller hands the request body to the library.
    ///
    /// The first two are invisible on the wire -- the same octets under the
    /// same Content-Length either way -- so they are not protocol statements.
    /// They are here because the two shapes are different code: handing the
    /// whole body over at once completes the request in one pass, while
    /// handing it over in pieces leaves the library asking for the rest, and
    /// an application streaming a file of unknown size can only do the second.
    ///
    /// SupplyChunked is a protocol statement: an application that does not
    /// know the size in advance cannot declare a Content-Length at all, and
    /// the chunked coding (RFC 9112 section 7.1) is what HTTP/1.1 gives it
    /// instead.  What reaches the peer is a different message, so the peer
    /// checks it as one.
    type ClientSupply =
        | SupplyNone
        | SupplyWhole
        | SupplyStreamed
        | SupplyChunked

    /// How many requests the case dispatches on one connection.
    ///
    /// HTTP/1.1's reason for existing, seen from the client end (RFC 9112
    /// section 9.1).  Two requests dispatched before the first response
    /// arrives is also the client-side mirror of the server's pipelining
    /// obligation: the responses come back in one write, and a client that
    /// stops parsing after the first has stranded the second caller.
    type ClientRequests =
        | OneRequest
        | TwoPipelined

    type Defect =
        /* --- baseline: proves the hostile server can build a VALID reply -- */
        | RspWellFormed

        /* --- header grammar, inbound (RFC 1945 s4.2 / RFC 9112 s5) ------- */
        /* The mirror of the request-side cases.  The parser is now shared, so
         * these are here to keep it shared: a future change that fixes one
         * direction and not the other fails here. */
        | RspHeaderEmptyValue
        | RspHeaderFolded
        | RspHeaderPadded
        | RspHeaderNoColon
        | RspHeaderNameEmpty
        | RspHeaderSpaceBeforeColon
        | RspHeaderBlockOverlong
        /* One field line longer than the receiver will hold.  The block-level
         * limit above cannot produce this: a block can be refused for its
         * total while every line in it is short, and a line can be refused for
         * its own length while the block is small.  Two limits, two paths. */
        | RspHeaderLineOverlong
        /* A continuation line as the first line of the block, which continues
         * nothing -- the mirror of the request-side case, and the one a parser
         * reaching for "the last header on the list" dereferences NULL on. */
        | RspHeaderFoldedFirst

        /* --- the status line (RFC 1945 s6.1 / RFC 9112 s4) --------------- */
        /*     status-line = HTTP-version SP status-code SP [ reason-phrase ]
         * The reason phrase is the one field a client may ignore: "The client
         * is not required to examine or display the Reason-Phrase."  A
         * response that omits it is understood. */
        | RspNoReasonPhrase
        /* RFC 2145 section 2.3 / RFC 9112 section 2.3, the mirror of the
         * request-side rule. */
        | RspMinorVersionUnknown
        | RspVersionMalformed
        | RspMajorVersionUnsupported
        | RspStatusNotNumeric
        | RspStatusOutOfRange(int)
        | RspStatusMissing
        /* A status line longer than the receiver will hold. */
        | RspStatusLineOverlong
        /* Leading whitespace on the status line.  RFC 9112 section 4 puts the
         * version first and nothing before it, and a tokenizer that skips
         * leading separators reads the version out of whatever follows. */
        | RspStatusLineLeadingWhitespace
        /* A status line with nothing on it at all. */
        | RspStatusLineEmpty
        /* Not an HTTP-version: the name is wrong rather than the numbers. */
        | RspVersionNotHttp
        /* "HTTP/1.x" -- the separator is there and the minor number is not. */
        | RspVersionMinorNotNumeric
        /* A version number past what the receiver will hold.  RFC 9112 section
         * 2.3 makes HTTP-version a single DIGIT either side of the dot, so
         * this is outside the grammar as well as outside the range. */
        | RspVersionNumberTooLarge
        /* A response that does not begin with "HTTP/" is an HTTP/0.9
         * Simple-Response, which RFC 1945 section 6.1 would have the client
         * read as a body.  RFC 9112 section 2.1 lets a recipient reject a
         * message that does not start with a valid status line instead, and
         * that is what the server side of this suite decided to do with the
         * request-line form, so the two ends agree: HTTP/0.9 is not spoken
         * here, and the request fails rather than silently acquiring a body
         * of unknown provenance. */
        | RspNoStatusLine

        /* --- interim responses (RFC 9110 section 15.2) ------------------- */
        /* "A client MUST be able to parse one or more 1xx responses received
         * prior to a final response, even if the client does not expect one."
         * A 1xx is not the answer -- it is a note that the answer is still
         * coming -- so a client that reports one as the result has reported a
         * status the server never meant as one, and then has a real response
         * arriving on a connection it believes is idle. */
        | RspInterimContinue
        | RspInterimRepeated
        /* 103 Early Hints (RFC 8297), the 1xx a client is most likely to meet
         * in the wild without having asked for anything. */
        | RspInterimEarlyHints

        /* --- statuses that are answers, not failures --------------------- */
        /* A 404 or a 500 is a complete, well-formed response.  A client that
         * treats a non-2xx as a transport failure loses the status, which is
         * the only thing the response was carrying. */
        | RspStatus(int)
        /* RFC 1945 sections 9.2.5/9.3.5, RFC 9112 section 6.3: a 204 or 304
         * response is "always terminated by the first empty line after the
         * header fields, regardless of the header fields present".  The
         * absence of Content-Length on these does NOT mean the body runs to
         * the close -- the message is complete at the end of the header block,
         * and a client that waits for a close hangs on a conforming server. */
        | RspStatusNoBody(int)

        /* --- body framing (RFC 1945 s7.2.2 / RFC 9112 s6.3) ------------- */
        /* "the length of that body is determined by ... the server closing
         * the connection."  With no Content-Length and no transfer coding, a
         * response body is exactly what arrives before the FIN.  Still true at
         * HTTP/1.1 (RFC 9112 section 6.3 item 7), which is why both versions
         * are here: a client that reads the rule as HTTP/1.0-only silently
         * drops every streamed HTTP/1.1 reply it is sent. */
        | RspBodyCloseDelimited
        | RspCloseDelimitedHttp11
        | RspContentLengthNotNumeric
        | RspContentLengthNegative
        | RspContentLengthDuplicateConflicting
        /* Digits and then something else, and a value past what the receiver
         * can represent -- the response-side spellings of the two the request
         * side already refuses. */
        | RspContentLengthTrailingJunk
        | RspContentLengthOverflow
        /* Declares more than it sends, then closes: the body is truncated, so
         * there is no complete response to deliver. */
        | RspBodyShortOfContentLength
        /* Declares less than it sends: the surplus is not part of this
         * response and must not reach the caller. */
        | RspBodyLongerThanContentLength
        /* RFC 1945 section 8.2: the response to HEAD carries the headers a GET
         * would have, Content-Length included, and no body.  A client that
         * waits for the bytes that length promises waits forever. */
        | RspHeadWithContentLength
        /* Both framings at once, from the other end.  RFC 9112 section 6.3
         * calls it a possible response-splitting attempt and says it "ought to
         * be handled as an error"; the client has no status to answer with, so
         * the error is the request's. */
        | RspTransferEncodingWithContentLength

        /* --- the chunked coding, inbound (RFC 9112 section 7.1) ---------- */
        /* "A recipient MUST be able to parse and decode the chunked transfer
         * coding."  The framing an HTTP/1.1 server uses for a reply whose size
         * it does not know when it starts writing, which is most of them. */
        | RspChunked
        | RspChunkedExtension
        | RspChunkedTrailer
        | RspChunkedManyChunks
        /* The mirrors of the request-side chunk defects, and for the same
         * reason: a size that is not a size cannot delimit a chunk. */
        | RspChunkSizeNotHex
        | RspChunkSizeNegative
        | RspChunkSizeTrailingJunk
        | RspChunkBadTerminator
        /* A chunk-size line longer than the receiver will hold. */
        | RspChunkLineOverlong
        /* Chunks, then a close, and never a last-chunk: the content is
         * incomplete, so it is not a result. */
        | RspChunkedTruncated

        /* A Transfer-Encoding field naming no coding at all.  RFC 9112 section
         * 6.3 rule 5 covers it without treating it as an error: where the
         * final coding is not chunked, "the message body length is determined
         * by reading the connection until it is closed" -- so this is a
         * response the client must still deliver, by the framing of last
         * resort rather than by the one the field claimed. */
        | RspTransferEncodingNoCoding

        /* --- connection management (RFC 9112 section 9.6) ---------------- */
        /* "A server that does not support persistent connections MUST send the
         * close connection option in every response."  The client's half of
         * that bargain is to believe it. */
        | RspConnectionClose
        /* Two requests dispatched before either is answered, both answered in
         * one write.  The client-side mirror of the server's ordering
         * obligation, and the case that asks whether the client keeps parsing
         * after one response is complete. */
        | RspPipelined

        /* --- the client's own outbound framing --------------------------- */
        /* A POST carrying a body, answered normally.  The response is not the
         * subject here: what is under test is that the request the peer
         * receives is the one the caller asked for, which is the half of the
         * exchange every other case takes on trust. */
        | RspToPostWithBody
        /* The same request, handed to the library a piece at a time. */
        | RspToStreamedPost
        /* And the same request with no length declared at all, which at
         * HTTP/1.1 means the chunked coding: the client is now the one that
         * has to produce a valid chunked body rather than parse one. */
        | RspToChunkedPost

        /* --- the transport ---------------------------------------------- */
        | RspPeerClosesWithoutResponse
        | RspPeerClosesMidStatusLine
        | RspPeerClosesMidHeaders

    type Case = { defect: Defect, delivery: Delivery }

    var current: Case
    var expected: ClientOutcome
    var expectBody: ClientBody
    var expectProbe: ProbeExpect
    var expectMethod: ClientMethod
    var expectSupply: ClientSupply
    var expectRequests: ClientRequests

    // ------------------------------------------------------------------
    // The specification: defect -> required client behaviour
    // ------------------------------------------------------------------

    pure def required(d: Defect): ClientOutcome =
        match d {
            | RspWellFormed => CbComplete(200)

            /* Legal header grammar, so the response is delivered. */
            | RspHeaderEmptyValue => CbComplete(200)
            | RspHeaderFolded => CbComplete(200)
            | RspHeaderPadded => CbComplete(200)

            /* Not header fields at all -- see the request-side model, which
             * refuses the same three shapes. */
            | RspHeaderNoColon => CbFailed
            | RspHeaderNameEmpty => CbFailed
            | RspHeaderSpaceBeforeColon => CbFailed
            | RspHeaderBlockOverlong => CbFailed
            | RspHeaderLineOverlong => CbFailed
            | RspHeaderFoldedFirst => CbFailed

            | RspNoReasonPhrase => CbComplete(200)
            | RspMinorVersionUnknown => CbComplete(200)

            | RspVersionMalformed => CbFailed
            | RspMajorVersionUnsupported => CbFailed
            | RspStatusNotNumeric => CbFailed
            | RspStatusOutOfRange(_) => CbFailed
            | RspStatusMissing => CbFailed
            | RspStatusLineOverlong => CbFailed
            | RspStatusLineLeadingWhitespace => CbFailed
            | RspStatusLineEmpty => CbFailed
            | RspVersionNotHttp => CbFailed
            | RspVersionMinorNotNumeric => CbFailed
            | RspVersionNumberTooLarge => CbFailed
            | RspNoStatusLine => CbFailed

            /* An interim response is not the answer, so the answer is what
             * arrives after it. */
            | RspInterimContinue => CbComplete(200)
            | RspInterimRepeated => CbComplete(200)
            | RspInterimEarlyHints => CbComplete(200)

            | RspStatus(s) => CbComplete(s)
            | RspStatusNoBody(s) => CbComplete(s)

            | RspBodyCloseDelimited => CbComplete(200)
            | RspCloseDelimitedHttp11 => CbComplete(200)
            | RspBodyLongerThanContentLength => CbComplete(200)
            | RspHeadWithContentLength => CbComplete(200)
            | RspToPostWithBody => CbComplete(200)
            | RspToStreamedPost => CbComplete(200)
            | RspToChunkedPost => CbComplete(200)

            | RspChunked => CbComplete(200)
            | RspChunkedExtension => CbComplete(200)
            | RspChunkedTrailer => CbComplete(200)
            | RspChunkedManyChunks => CbComplete(200)

            | RspTransferEncodingNoCoding => CbComplete(200)
            | RspConnectionClose => CbComplete(200)
            | RspPipelined => CbComplete(200)

            | RspContentLengthNotNumeric => CbFailed
            | RspContentLengthNegative => CbFailed
            | RspContentLengthDuplicateConflicting => CbFailed
            | RspContentLengthTrailingJunk => CbFailed
            | RspContentLengthOverflow => CbFailed
            | RspBodyShortOfContentLength => CbFailed
            | RspTransferEncodingWithContentLength => CbFailed

            | RspChunkSizeNotHex => CbFailed
            | RspChunkSizeNegative => CbFailed
            | RspChunkSizeTrailingJunk => CbFailed
            | RspChunkBadTerminator => CbFailed
            | RspChunkLineOverlong => CbFailed
            | RspChunkedTruncated => CbFailed

            | RspPeerClosesWithoutResponse => CbFailed
            | RspPeerClosesMidStatusLine => CbFailed
            | RspPeerClosesMidHeaders => CbFailed
        }

    pure def bodyRequired(d: Defect): ClientBody =
        match d {
            | RspStatusNoBody(_) => BodyNone
            | RspHeadWithContentLength => BodyNone
            | _ =>
                match required(d) {
                    | CbFailed => BodyUnchecked
                    | CbComplete(_) => BodyDelivered
                }
        }

    /// The probe header the hostile server reflects, where the case is about
    /// the header grammar at all.
    pure def probeRequired(d: Defect): ProbeExpect =
        match d {
            | RspHeaderEmptyValue => ProbeEmpty
            | RspHeaderFolded => ProbeAny
            | RspHeaderPadded => ProbeValue
            | RspWellFormed => ProbeValue
            | _ => ProbeAbsent
        }

    pure def methodRequired(d: Defect): ClientMethod =
        match d {
            | RspHeadWithContentLength => CHead
            | RspToPostWithBody => CPost
            | RspToStreamedPost => CPost
            | RspToChunkedPost => CPost
            | _ => CGet
        }

    pure def supplyRequired(d: Defect): ClientSupply =
        match d {
            | RspToPostWithBody => SupplyWhole
            | RspToStreamedPost => SupplyStreamed
            | RspToChunkedPost => SupplyChunked
            | _ => SupplyNone
        }

    pure def requestsRequired(d: Defect): ClientRequests =
        match d {
            | RspPipelined => TwoPipelined
            | _ => OneRequest
        }

    action use(d: Defect, v: Delivery): bool = all {
        current' = { defect: d, delivery: v },
        expected' = required(d),
        expectBody' = bodyRequired(d),
        expectProbe' = probeRequired(d),
        expectMethod' = methodRequired(d),
        expectSupply' = supplyRequired(d),
        expectRequests' = requestsRequired(d)
    }

    // ------------------------------------------------------------------
    // Case generation
    // ------------------------------------------------------------------

    pure val DELIVERIES = Set(OneWrite, TwoWrites, Dribble)

    pure val DEFECTS = Set(
        RspWellFormed,
        RspHeaderEmptyValue,
        RspHeaderFolded,
        RspHeaderPadded,
        RspHeaderNoColon,
        RspHeaderNameEmpty,
        RspHeaderSpaceBeforeColon,
        RspHeaderBlockOverlong,
        RspHeaderLineOverlong,
        RspHeaderFoldedFirst,
        RspNoReasonPhrase,
        RspMinorVersionUnknown,
        RspVersionMalformed,
        RspMajorVersionUnsupported,
        RspStatusNotNumeric,
        RspStatusOutOfRange(99), RspStatusOutOfRange(700),
        RspStatusMissing,
        RspStatusLineOverlong,
        RspStatusLineLeadingWhitespace,
        RspStatusLineEmpty,
        RspVersionNotHttp,
        RspVersionMinorNotNumeric,
        RspVersionNumberTooLarge,
        RspNoStatusLine,
        RspInterimContinue,
        RspInterimRepeated,
        RspInterimEarlyHints,
        RspStatus(404), RspStatus(500),
        RspStatusNoBody(204), RspStatusNoBody(304),
        RspBodyCloseDelimited,
        RspCloseDelimitedHttp11,
        RspContentLengthNotNumeric,
        RspContentLengthNegative,
        RspContentLengthDuplicateConflicting,
        RspContentLengthTrailingJunk,
        RspContentLengthOverflow,
        RspBodyShortOfContentLength,
        RspBodyLongerThanContentLength,
        RspHeadWithContentLength,
        RspTransferEncodingWithContentLength,
        RspChunked,
        RspChunkedExtension,
        RspChunkedTrailer,
        RspChunkedManyChunks,
        RspChunkSizeNotHex,
        RspChunkSizeNegative,
        RspChunkSizeTrailingJunk,
        RspChunkBadTerminator,
        RspChunkLineOverlong,
        RspChunkedTruncated,
        RspTransferEncodingNoCoding,
        RspConnectionClose,
        RspPipelined,
        RspToPostWithBody,
        RspToStreamedPost,
        RspToChunkedPost,
        RspPeerClosesWithoutResponse,
        RspPeerClosesMidStatusLine,
        RspPeerClosesMidHeaders
    )

    action pick = {
        nondet d = DEFECTS.oneOf()
        nondet v = DELIVERIES.oneOf()
        use(d, v)
    }

    action init = use(RspWellFormed, OneWrite)
    action step = pick

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    /// Totality, and a sanity bound on the statuses the model asks for.
    val outcomeIsSpecified =
        match expected {
            | CbComplete(s) => s >= 100 and s <= 599
            | CbFailed => true
        }

    /// Requirement 1, and the reason this model exists.  Every defect,
    /// including the ones where the peer simply hangs up, resolves to a
    /// completion the caller can observe.  The type has no arm for silence,
    /// so this is checking that no arm was quietly added.
    val noRequestIsAbandoned =
        match expected {
            | CbComplete(_) => true
            | CbFailed => true
        }

    /// Requirement 2.  A response whose framing is broken or whose body is
    /// short is not a result: reporting it as one hands the caller a value
    /// the peer never sent, which is worse than reporting nothing.
    val truncatedResponsesAreNotResults =
        match current.defect {
            | RspBodyShortOfContentLength => expected == CbFailed
            | RspContentLengthNotNumeric => expected == CbFailed
            | RspContentLengthNegative => expected == CbFailed
            | RspContentLengthDuplicateConflicting => expected == CbFailed
            | RspContentLengthTrailingJunk => expected == CbFailed
            | RspContentLengthOverflow => expected == CbFailed
            | RspTransferEncodingWithContentLength => expected == CbFailed
            | RspChunkSizeNotHex => expected == CbFailed
            | RspChunkSizeNegative => expected == CbFailed
            | RspChunkSizeTrailingJunk => expected == CbFailed
            | RspChunkBadTerminator => expected == CbFailed
            | RspChunkLineOverlong => expected == CbFailed
            | RspChunkedTruncated => expected == CbFailed
            | _ => true
        }

    /// Requirement 3, which the interim cases exist for: a 1xx is never the
    /// answer.  Whatever the client reports as the result, it is not the
    /// interim status the peer sent first.
    val interimIsNotTheAnswer =
        match current.defect {
            | RspInterimContinue => expected == CbComplete(200)
            | RspInterimRepeated => expected == CbComplete(200)
            | RspInterimEarlyHints => expected == CbComplete(200)
            | _ =>
                match expected {
                    | CbComplete(s) => s < 100 or s >= 200
                    | CbFailed => true
                }
        }

    /// A body may only be expected where the response has one to give: not on
    /// HEAD, not on the statuses the RFCs say carry none, and not on a
    /// request that failed.
    val bodyOnlyWhereTheResponseHasOne =
        match expectBody {
            | BodyNone =>
                match current.defect {
                    | RspStatusNoBody(_) => true
                    | RspHeadWithContentLength => true
                    | _ => false
                }
            | BodyUnchecked => expected == CbFailed
            | BodyDelivered => expected != CbFailed
        }

    /// A request body belongs to POST and to nothing else: the RFCs define no
    /// semantics for one on GET or HEAD.
    val requestBodyOnlyOnPost =
        (expectSupply == SupplyNone) iff (expectMethod != CPost)

    val safety =
        outcomeIsSpecified and noRequestIsAbandoned and
        truncatedResponsesAreNotResults and interimIsNotTheAnswer and
        bodyOnlyWhereTheResponseHasOne and requestBodyOnlyOnPost

    // ------------------------------------------------------------------
    // Scenario tests: the outcomes most likely to be got wrong
    // ------------------------------------------------------------------

    /// The baseline.  If the hostile server cannot build a response the
    /// client accepts, nothing else it says about the client means anything.
    run peerCanBuildAValidResponseTest =
        init
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)

    /// Losing the transport is still a completion.  This is the requirement
    /// that catches "frees the pending request without telling the caller",
    /// which leaves an application waiting on a callback that can no longer
    /// arrive.
    run transportLossCompletesTheRequestTest =
        init
            .then(use(RspPeerClosesWithoutResponse, OneWrite))
            .expect(expected == CbFailed)
            .then(use(RspPeerClosesMidHeaders, TwoWrites))
            .expect(expected == CbFailed)
            .then(use(RspPeerClosesMidStatusLine, Dribble))
            .expect(expected == CbFailed)

    /// A body with no declared length and no coding runs to the close, at
    /// either version.  A client that reads the rule as HTTP/1.0-only
    /// silently loses every streamed HTTP/1.1 reply it is ever sent.
    run closeDelimitedBodiesArriveTest =
        init
            .then(use(RspBodyCloseDelimited, OneWrite))
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)
            .then(use(RspCloseDelimitedHttp11, TwoWrites))
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)

    /// ... except where the status says there is no body, which is what keeps
    /// the previous rule from turning a 204 into a wait for a close.
    run noBodyStatusesAreCompleteTest =
        init
            .then(use(RspStatusNoBody(204), OneWrite))
            .expect(expected == CbComplete(204) and expectBody == BodyNone)
            .then(use(RspStatusNoBody(304), TwoWrites))
            .expect(expected == CbComplete(304) and expectBody == BodyNone)
            .then(use(RspHeadWithContentLength, OneWrite))
            .expect(expectBody == BodyNone and expectMethod == CHead)

    /// A refused request is still an answer: the status is the whole of what
    /// the response carries, and losing it loses everything.
    run errorStatusesAreDeliveredTest =
        init
            .then(use(RspStatus(404), OneWrite))
            .expect(expected == CbComplete(404))
            .then(use(RspStatus(500), Dribble))
            .expect(expected == CbComplete(500))

    /// An interim response is not one.  The client has to read past it and
    /// report the status that follows, or it reports a result the server never
    /// meant as one and then meets the real response on a connection it
    /// believes is idle.
    run interimResponsesAreNotResultsTest =
        init
            .then(use(RspInterimContinue, OneWrite))
            .expect(expected == CbComplete(200) and interimIsNotTheAnswer)
            .then(use(RspInterimRepeated, TwoWrites))
            .expect(expected == CbComplete(200) and interimIsNotTheAnswer)
            .then(use(RspInterimEarlyHints, Dribble))
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)

    /// A truncated body is not a short body.
    run truncatedBodiesFailTest =
        init
            .then(use(RspBodyShortOfContentLength, OneWrite))
            .expect(expected == CbFailed and truncatedResponsesAreNotResults)
            .then(use(RspBodyLongerThanContentLength, OneWrite))
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)

    /// The chunked coding, which every HTTP/1.1 recipient must be able to
    /// decode -- including the parts of it a decoder can produce the right
    /// body without ever looking at.
    run chunkedResponsesAreDecodedTest =
        init
            .then(use(RspChunked, OneWrite))
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)
            .then(use(RspChunkedExtension, TwoWrites))
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)
            .then(use(RspChunkedTrailer, Dribble))
            .expect(expected == CbComplete(200) and expectBody == BodyDelivered)
            .then(use(RspChunkSizeNotHex, OneWrite))
            .expect(expected == CbFailed and truncatedResponsesAreNotResults)
            .then(use(RspChunkedTruncated, OneWrite))
            .expect(expected == CbFailed and truncatedResponsesAreNotResults)

    /// The client's own outbound framing, which every other case takes on
    /// trust: the peer must receive the request the caller asked for,
    /// whichever way the caller handed the body over -- including the way that
    /// does not declare a length at all.
    run requestBodiesArriveTest =
        init
            .then(use(RspToPostWithBody, OneWrite))
            .expect(expectMethod == CPost and expectSupply == SupplyWhole
                    and expected == CbComplete(200))
            .then(use(RspToStreamedPost, TwoWrites))
            .expect(expectMethod == CPost and expectSupply == SupplyStreamed
                    and requestBodyOnlyOnPost)
            .then(use(RspToChunkedPost, OneWrite))
            .expect(expectMethod == CPost and expectSupply == SupplyChunked
                    and requestBodyOnlyOnPost)
            .then(use(RspWellFormed, OneWrite))
            .expect(expectSupply == SupplyNone and requestBodyOnlyOnPost)

    /// Two requests on one connection, answered in one write.  The client's
    /// half of HTTP/1.1's reason for existing, and the case that asks whether
    /// it keeps parsing once a response is complete.
    run pipelinedResponsesBothArriveTest =
        init
            .then(use(RspPipelined, OneWrite))
            .expect(expectRequests == TwoPipelined
                    and expected == CbComplete(200))
            .then(use(RspWellFormed, OneWrite))
            .expect(expectRequests == OneRequest)

    run everyDefectHasAnOutcomeTest =
        init
            .then(pick)
            .expect(safety)
            .then(pick)
            .expect(safety)
            .then(pick)
            .expect(safety)
}
