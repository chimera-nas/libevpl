// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * http10.qnt -- what RFC 1945 requires of an HTTP/1.0 origin server.
 *
 * Three modules in one file, because they share a vocabulary that must not
 * drift: `http10` holds the types both matrices predict in, `http10_requests`
 * is the positive matrix and `http10_defects` the negative one.  The C driver
 * compiles one case table generated from all of it, so a class that means one
 * thing here and another there would be a silently wrong test.
 *
 * IMPORTANT: this models the SPECIFICATION, not libevpl's current behaviour.
 * Where the two disagree the driver records a divergence, which is reviewed as
 * a candidate bug.  Encoding current behaviour instead would freeze today's
 * defects into the spec and guarantee they are never found.  This is the same
 * rule the RPC2 models follow (src/rpc2/tests/quint), and for the same reason.
 *
 * Scope is deliberately HTTP/1.0 and the server direction only:
 *
 *   - HTTP/1.0 because it is the smaller, fully-specified protocol: no
 *     chunked encoding, no required Host, no persistent connections, no 1xx.
 *     Everything below is either RFC 1945 text or, where marked, one of the
 *     tolerances RFC 1945 section 19.3 / RFC 2616 section 4.1 recommend.
 *   - The server direction because libevpl's own HTTP client cannot express
 *     any of this: evpl_http_client_send_headers hardcodes "HTTP/1.1" and
 *     emits a fixed header block.  A raw socket is the only peer that can put
 *     an arbitrary HTTP/1.0 request on the wire, and it can also put a
 *     well-formed one there, so the positive matrix is driven the same way.
 *
 * The classes are SYMBOLIC.  "UriQuery", not "/echo?a=1&b=2" -- the C driver
 * owns the mapping from class to bytes, which keeps this model about what the
 * RFC requires rather than about how to spell it.
 *
 *   quint test http10.qnt --main=http10_requests
 *   quint test http10.qnt --main=http10_defects
 *   quint run  http10.qnt --main=http10_defects --invariant=safety
 *   ./check_models.sh $(which quint) .
 */

/* ===================================================================== *
 * Shared vocabulary
 * ===================================================================== */

module http10 {

    /// How the raw client puts the request bytes on the wire.  A parser
    /// defect that is only detected because the whole request arrived in one
    /// read is not really detected, so every case is also delivered split.
    /// Dribble is one byte per write with the server's event loop pumped
    /// between them, which is what actually forces an incremental parser to
    /// hold its state across reads.
    type Delivery =
        | OneWrite
        | TwoWrites
        | Dribble

    /// What the server must put back on the wire.
    ///
    /// Status(n) is the strong form: RFC 1945 names a code for this
    /// situation and nothing else will do.  NotSuccess is for the cases the
    /// RFC leaves open -- an incomplete request, where both answering an
    /// error and closing are defensible -- and asserts only that the server
    /// must not report success.  Which of the two applies is itself a claim
    /// about the RFC, so `completeRequestsAreAnswered` below pins it down.
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
        /* RFC 1945 section 8.2: the response to HEAD must not carry a body,
         * whatever its Content-Length says */
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
    type PersistExpect =
        | MustClose
        /* the client offered Keep-Alive: the server may hold the connection
         * open, but only if it said so in the response */
        | MayPersist

    /// What the reflected probe header must say.  The test server echoes the
    /// request's X-Probe back, which is how the driver sees what the server's
    /// header parser actually produced rather than only whether it survived.
    type ProbeExpect =
        | ProbeAbsent      /* the request carried no probe header      */
        | ProbeValue       /* the probe's value, LWS stripped          */
        | ProbeEmpty       /* present with an empty value -- legal     */
        | ProbeTwice       /* sent twice; both must reach the server   */
        | ProbeAny         /* parsed, but the RFC does not pin the value */
}

/* ===================================================================== *
 * The positive matrix: requests an HTTP/1.0 server must serve
 * ===================================================================== */

module http10_requests {

    import http10.*

    /// Methods.  RFC 1945 section 8: "The methods GET and HEAD must be
    /// supported by all general-purpose servers"; POST is the third method
    /// RFC 1945 defines and the only one that carries a request body.
    type MethodCls =
        | MGet
        | MHead
        | MPost

    /// Request-URI shapes (RFC 1945 section 5.1.2, abs_path form).  The
    /// absoluteURI form is not here: RFC 1945 allows it only towards a proxy,
    /// and requiring it of an origin server is an HTTP/1.1 rule.
    type UriCls =
        | UriRoot          /* "/"                                      */
        | UriPath          /* a normal path                            */
        | UriQuery         /* path plus a query string                 */
        | UriEscaped       /* percent-encoded octets, passed through   */
        | UriLong          /* long, but well within any sane limit     */

    /// Header-block shapes.  Each is a property of RFC 1945 section 4.2's
    /// grammar that a hand-written parser can get wrong independently.
    type HdrCls =
        /* No header fields of its own -- with the default connection
         * disposition and no body that is a request with no header block at
         * all, which HTTP/1.0 allows: Host became mandatory in HTTP/1.1. */
        | HdrNone
        | HdrPlain         /* one ordinary header                      */
        | HdrPadded        /* LWS either side of the value, stripped   */
        | HdrEmpty         /* "X-Probe:" -- an empty value is legal    */
        | HdrMixedCase     /* field names are case-insensitive         */
        | HdrFolded        /* a continuation line (LWS-prefixed)       */
        | HdrDuplicate     /* the same field twice                     */
        | HdrMany          /* a block of many distinct fields          */

    /// Request-body shapes.  HTTP/1.0 delimits a request body by
    /// Content-Length alone -- there is no chunked encoding to fall back on.
    type BodyCls =
        | BodyNone         /* no Content-Length, no body               */
        | BodyEmpty        /* "Content-Length: 0"                      */
        | BodyOne          /* one byte                                 */
        | BodySmall        /* a few dozen bytes                        */
        | BodyLarge        /* larger than one read buffer              */

    /// Whether the client opens the Keep-Alive subject.
    type ConnCls =
        | ConnDefault      /* no Connection header: the server must close */
        | ConnKeepAlive    /* "Connection: keep-alive"                 */

    type Case = {
        method: MethodCls,
        uri: UriCls,
        hdr: HdrCls,
        body: BodyCls,
        conn: ConnCls,
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

    // ------------------------------------------------------------------
    // The specification
    // ------------------------------------------------------------------

    /// RFC 1945 section 8.2: "The HEAD method is identical to GET except that
    /// the server must not return a message-body in the response."  The
    /// header fields, Content-Length included, stay exactly as they would
    /// have been for GET -- so this is not "a response with no content", it
    /// is a response whose declared body is deliberately absent from the
    /// wire, and the only component that can suppress it is the one that
    /// knows both the request method and the outbound framing.
    pure def bodyRequired(m: MethodCls): BodyExpect =
        match m {
            | MHead => BodyAbsent
            | _ => BodyEchoed
        }

    /// What the server's header parser must have produced.  Everything here
    /// is RFC 1945 section 4.2 grammar except HdrFolded: the RFC allows a
    /// recipient to replace the folding LWS with a single SP, so the exact
    /// bytes are not pinned down and only "the header arrived" is required.
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

    /// RFC 1945 section 1.4.  Only a client that asked for Keep-Alive can
    /// release the server from closing, and even then the server has to have
    /// agreed in the response -- which the driver checks.
    pure def persistRequired(c: ConnCls): PersistExpect =
        match c {
            | ConnDefault => MustClose
            | ConnKeepAlive => MayPersist
        }

    action use(c: Case): bool = all {
        current' = c,
        expected' = Status(200),
        expectBody' = bodyRequired(c.method),
        expectProbe' = probeRequired(c.hdr),
        expectPersist' = persistRequired(c.conn)
    }

    // ------------------------------------------------------------------
    // Case generation
    // ------------------------------------------------------------------

    pure val METHODS = Set(MGet, MHead, MPost)
    pure val URIS = Set(UriRoot, UriPath, UriQuery, UriEscaped, UriLong)
    pure val HDRS = Set(HdrNone, HdrPlain, HdrPadded, HdrEmpty, HdrMixedCase,
                        HdrFolded, HdrDuplicate, HdrMany)
    pure val CONNS = Set(ConnDefault, ConnKeepAlive)
    pure val DELIVERIES = Set(OneWrite, TwoWrites, Dribble)

    /// GET and HEAD define no semantics for a request body (RFC 1945 section
    /// 8.1/8.2), so the matrix does not attach one; a GET with a body is a
    /// request-smuggling question rather than a conformance one, and belongs
    /// in the defect taxonomy if anywhere.
    pure val BODIES_NO_ENTITY = Set(BodyNone, BodyEmpty)

    /// RFC 1945 section 8.3: "A valid Content-Length is required on all
    /// HTTP/1.0 POST requests."  BodyNone is therefore not a legal POST and
    /// lives in the defect model as PostWithoutContentLength.
    pure val BODIES_ENTITY = Set(BodyEmpty, BodyOne, BodySmall, BodyLarge)

    /// One byte per write costs a syscall and an event-loop turn per byte, so
    /// it is confined to the bodies where that is cheap.  The large body is
    /// still delivered split, just not a byte at a time.
    pure val BODIES_DRIBBLEABLE = Set(BodyNone, BodyEmpty, BodyOne, BodySmall)

    action pick = {
        nondet m = METHODS.oneOf()
        nondet u = URIS.oneOf()
        nondet h = HDRS.oneOf()
        nondet c = CONNS.oneOf()
        nondet b = (if (m == MPost) BODIES_ENTITY else BODIES_NO_ENTITY).oneOf()
        nondet d = (if (BODIES_DRIBBLEABLE.contains(b)) DELIVERIES
                    else Set(OneWrite, TwoWrites)).oneOf()
        use({ method: m, uri: u, hdr: h, body: b, conn: c, delivery: d })
    }

    action init = use({ method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnDefault, delivery: OneWrite })

    action step = pick

    // ------------------------------------------------------------------
    // Invariants: every generated case is a legal HTTP/1.0 request
    // ------------------------------------------------------------------

    /// The whole point of the positive matrix: none of these is a defect, so
    /// every one of them must be served.  A case that expected anything else
    /// would belong in the other model.
    val everyCaseSucceeds = expected == Status(200)

    /// A POST must declare its length and a GET/HEAD must not carry an
    /// entity -- otherwise this model would be emitting requests that RFC
    /// 1945 does not require a server to accept while labelling them legal.
    val bodyMatchesMethod =
        if (current.method == MPost) {
            BODIES_ENTITY.contains(current.body)
        } else {
            BODIES_NO_ENTITY.contains(current.body)
        }

    /// The HEAD rule, stated where it cannot be missed: a body is required on
    /// the wire for exactly the methods that are not HEAD.
    val headCarriesNoBody =
        (current.method == MHead) iff (expectBody == BodyAbsent)

    /// A client that did not ask for Keep-Alive gets the RFC 1945 default,
    /// and the default is that the server closes.
    val defaultConnectionCloses =
        (current.conn == ConnDefault) implies (expectPersist == MustClose)

    val wellFormed =
        everyCaseSucceeds and bodyMatchesMethod and headCarriesNoBody and
        defaultConnectionCloses

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

    /// HEAD is GET without the body, on every URI shape.
    run headSuppressesTheBodyTest =
        init
            .then(use({ method: MHead, uri: UriPath, hdr: HdrPlain,
                        body: BodyNone, conn: ConnDefault, delivery: OneWrite }))
            .expect(expectBody == BodyAbsent and expected == Status(200))
            .then(use({ method: MGet, uri: UriPath, hdr: HdrPlain,
                        body: BodyNone, conn: ConnDefault, delivery: OneWrite }))
            .expect(expectBody == BodyEchoed)

    /// The header-grammar cases whose value the driver checks exactly.  These
    /// are the three a parser built on strtok and strcmp gets wrong
    /// independently of one another.
    run headerGrammarTest =
        init
            .then(use({ method: MGet, uri: UriPath, hdr: HdrPadded,
                        body: BodyNone, conn: ConnDefault, delivery: OneWrite }))
            .expect(expectProbe == ProbeValue)
            .then(use({ method: MGet, uri: UriPath, hdr: HdrEmpty,
                        body: BodyNone, conn: ConnDefault, delivery: Dribble }))
            .expect(expectProbe == ProbeEmpty and expected == Status(200))
            .then(use({ method: MGet, uri: UriPath, hdr: HdrMixedCase,
                        body: BodyNone, conn: ConnDefault, delivery: TwoWrites }))
            .expect(expectProbe == ProbeValue)
            .then(use({ method: MGet, uri: UriPath, hdr: HdrDuplicate,
                        body: BodyNone, conn: ConnDefault, delivery: OneWrite }))
            .expect(expectProbe == ProbeTwice)

    /// A POST is the one method that carries an entity, and its length is
    /// carried by Content-Length alone.
    run postCarriesAnEntityTest =
        init
            .then(use({ method: MPost, uri: UriPath, hdr: HdrPlain,
                        body: BodyLarge, conn: ConnDefault, delivery: TwoWrites }))
            .expect(expectBody == BodyEchoed and bodyMatchesMethod)
            .then(use({ method: MPost, uri: UriPath, hdr: HdrNone,
                        body: BodyEmpty, conn: ConnDefault, delivery: Dribble }))
            .expect(expectBody == BodyEchoed and bodyMatchesMethod)

    /// Keep-Alive is the only thing that can hold an HTTP/1.0 connection open,
    /// and the client has to ask.
    run keepAliveIsOptInTest =
        init
            .then(use({ method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnKeepAlive, delivery: OneWrite }))
            .expect(expectPersist == MayPersist)
            .then(use({ method: MGet, uri: UriRoot, hdr: HdrNone,
                        body: BodyNone, conn: ConnDefault, delivery: OneWrite }))
            .expect(expectPersist == MustClose)

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
 * The negative matrix: requests an HTTP/1.0 server must refuse, and how
 * ===================================================================== */

module http10_defects {

    import http10.*

    /// Mirrors of libevpl's limits, which the driver must exceed to reach the
    /// two overflow cases.  They are the defaults
    /// evpl_global_config_set_http_max_header_size() adjusts and the size of
    /// the parser's line buffer; the driver asserts they still hold.
    pure val MaxHeaderSize = 8192
    pure val MaxHeaderLine = 4096

    type Defect =
        /* --- baseline: proves the injector can build a VALID request ---- */
        | NoDefect

        /* --- the Request-Line (RFC 1945 section 5.1) -------------------- */
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
         * it as the start of the entity.  Obsolete, and supporting it makes
         * the response shape depend on the request, which is why the driver
         * records this one rather than treating it as urgent. */
        | RequestLineNoVersion

        /* --- the version (RFC 1945 section 3.1) ------------------------- */
        | VersionMalformed             /* "HTTP/1", "HTTP/x.y"              */
        | VersionMajorUnsupported      /* "HTTP/2.0" on a text request line */
        /* "HTTP/1.1 is upward compatible with HTTP/1.0" and section 3.1
         * makes minor numbers forward-compatible: a higher minor is a
         * request the server must serve at the version it does speak, not
         * one it may refuse.  RFC 2145 section 2.3 states the rule
         * explicitly. */
        | VersionMinorUnknown          /* "HTTP/1.9"                        */

        /* --- the Request-URI -------------------------------------------- */
        /* A URI past whatever the server is willing to hold.  RFC 1945 names
         * no code for it (414 is an HTTP/1.1 addition), so only "not a
         * success" is required -- but silently serving a TRUNCATED URI is a
         * different resource than the one asked for, which is why this is
         * here at all. */
        | UriTooLong

        /* --- header fields (RFC 1945 section 4.2) ----------------------- */
        | HeaderNoColon                /* not a field at all                */
        | HeaderNameEmpty              /* ": value"                         */
        /* "field-name ':' [ field-value ]" with field-name a token: a space
         * before the colon is not a field name.  Accepting it is how a
         * request smuggles a header past a front end that rejects it. */
        | HeaderSpaceBeforeColon
        | HeaderLineOverlong           /* one field longer than the buffer  */
        | HeaderBlockOverlong          /* the block past max_header_size    */
        /* The client stops mid-block and half-closes.  The request never
         * became a request, so there is nothing to answer: this is the one
         * shape where silence is a legitimate response. */
        | HeaderBlockUnterminated

        /* --- line endings ----------------------------------------------- */
        /* RFC 1945 section 19.3: "we recommend that applications, when
         * parsing such headers, recognize a single LF as a line terminator
         * and ignore the leading CR".  RECOMMENDED, not required -- recorded
         * here because a server that rejects it is interoperating worse than
         * the RFC asks, not because it is violating a MUST. */
        | BareLfLineEndings

        /* --- the entity (RFC 1945 sections 7.2 and 10.4) ---------------- */
        /* Content-Length is "the length of the message-body ... expressed as
         * a decimal number of octets".  Neither of the first two is one, and
         * a server that runs them through strtoul reads 0 and treats a
         * request with an entity as one without -- the classic desync. */
        | ContentLengthNotNumeric
        | ContentLengthNegative
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
         * request message's content." */
        | PostWithoutContentLength

    type Case = { defect: Defect, delivery: Delivery }

    var current: Case
    var expected: Outcome
    var expectPersist: PersistExpect

    // ------------------------------------------------------------------
    // The specification: defect -> required response
    // ------------------------------------------------------------------

    pure def required(d: Defect): Outcome =
        match d {
            | NoDefect => Status(200)

            /* RFC 1945 section 9.5.2 */
            | MethodUnknown => Status(501)
            | MethodLowercase => Status(501)

            /* RFC 1945 section 9.4.1: "400 Bad Request -- The request could
             * not be understood by the server due to malformed syntax."
             * Every one of these is a Request-Line or a field that does not
             * match the grammar, and every one of them is a complete
             * request: the server has all the bytes it will ever get and
             * owes the client a verdict. */
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
            | PostWithoutContentLength => Status(400)

            | RequestLineNoVersion => SimpleResponse

            /* Forward-compatible: served, not refused. */
            | VersionMinorUnknown => Status(200)

            /* The tolerance.  A server that takes it serves the request. */
            | BareLfLineEndings => Status(200)

            /* No code is specified and the request never completed, so an
             * error status and a close are both defensible; what is not is
             * answering 200 to a request the server never fully received. */
            | UriTooLong => NotSuccess
            | HeaderBlockUnterminated => NotSuccess
            | BodyShortOfContentLength => NotSuccess
        }

    /// RFC 1945 section 1.4 again: whatever the response is, an HTTP/1.0
    /// connection ends with it.  None of these requests asks for Keep-Alive,
    /// and an error response is exactly where holding the connection open is
    /// least defensible -- the server has already decided it cannot parse
    /// what the peer is sending.
    ///
    /// VersionMinorUnknown is the one exception, and it is not an exception
    /// to the rule so much as a request the rule does not cover: RFC 2145
    /// section 2.3 has it served as HTTP/1.1, where a persistent connection
    /// is the default rather than an extension the client must ask for.  A
    /// server that closes anyway is still conforming, so this is the weaker
    /// MayPersist rather than a requirement to hold the connection.
    pure def persistRequired(d: Defect): PersistExpect =
        match d {
            | VersionMinorUnknown => MayPersist
            | _ => MustClose
        }

    action use(d: Defect, v: Delivery): bool = all {
        current' = { defect: d, delivery: v },
        expected' = required(d),
        expectPersist' = persistRequired(d)
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
        BareLfLineEndings,
        ContentLengthNotNumeric,
        ContentLengthNegative,
        ContentLengthDuplicateConflicting,
        BodyShortOfContentLength,
        PostWithoutContentLength
    )

    action pick = {
        nondet d = DEFECTS.oneOf()
        nondet v = DELIVERIES.oneOf()
        use(d, v)
    }

    action init = use(NoDefect, OneWrite)
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
    /// server has received in full is a request it can judge, and RFC 1945
    /// gives it the vocabulary to say so -- 400 for syntax it cannot parse,
    /// 501 for a method it does not implement.  Hanging up instead tells the
    /// client nothing it can act on: it cannot distinguish a rejected request
    /// from a crashed server, a lost connection, or a middlebox, so it
    /// retries, and the same request is refused the same way forever.
    ///
    /// Only the three shapes where the request genuinely never completed are
    /// exempt, and they are named individually so that adding a defect
    /// silently to the exempt set is not possible.
    val completeRequestsAreAnswered =
        match current.defect {
            | UriTooLong => expected == NotSuccess
            | HeaderBlockUnterminated => expected == NotSuccess
            | BodyShortOfContentLength => expected == NotSuccess
            | _ =>
                match expected {
                    | NotSuccess => false
                    | _ => true
                }
        }

    /// A defect is not a reason to invent a new status class: everything the
    /// server refuses here has a code in RFC 1945 section 9, and a refusal
    /// must use it rather than, say, closing after a 200.
    val refusalsUseAnErrorStatus =
        match expected {
            | Status(s) => (s == 200) or (s >= 400 and s <= 599)
            | _ => true
        }

    /// HTTP/1.0 has no persistent connections without Keep-Alive, and none of
    /// these requests asks for it -- except the one that is not an HTTP/1.0
    /// request at all, which is named rather than folded into a default so
    /// that a second such case cannot appear by accident.
    val everyDefectClosesTheConnection =
        match current.defect {
            | VersionMinorUnknown => expectPersist == MayPersist
            | _ => expectPersist == MustClose
        }

    val safety =
        outcomeIsSpecified and completeRequestsAreAnswered and
        refusalsUseAnErrorStatus and everyDefectClosesTheConnection

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
            .then(use(MethodUnknown, OneWrite))
            .expect(expected == Status(501))
            .then(use(MethodLowercase, Dribble))
            .expect(expected == Status(501))

    /// Malformed syntax is a 400, whichever part of the message it is in, and
    /// it is a 400 rather than a silent close.
    run malformedSyntaxIsFourHundredTest =
        init
            .then(use(HeaderNoColon, OneWrite))
            .expect(expected == Status(400))
            .then(use(HeaderSpaceBeforeColon, TwoWrites))
            .expect(expected == Status(400))
            .then(use(RequestLineExtraToken, Dribble))
            .expect(expected == Status(400))
            .then(use(VersionMalformed, OneWrite))
            .expect(expected == Status(400))

    /// A length that is not a length must not be read as zero: that turns a
    /// request with an entity into one without, and the entity into whatever
    /// the server reads next.
    run contentLengthMustParseTest =
        init
            .then(use(ContentLengthNotNumeric, OneWrite))
            .expect(expected == Status(400))
            .then(use(ContentLengthNegative, OneWrite))
            .expect(expected == Status(400))
            .then(use(ContentLengthDuplicateConflicting, TwoWrites))
            .expect(expected == Status(400))
            .then(use(PostWithoutContentLength, OneWrite))
            .expect(expected == Status(400))

    /// A higher minor version is served, not refused: that is what makes the
    /// version number usable for negotiation at all.
    run higherMinorVersionIsServedTest =
        init
            .then(use(VersionMinorUnknown, OneWrite))
            .expect(expected == Status(200))
            .then(use(VersionMajorUnsupported, OneWrite))
            .expect(expected == Status(400))

    /// An incomplete request is the one shape a server may answer with
    /// silence -- and the only one.
    run incompleteRequestsMayGoUnansweredTest =
        init
            .then(use(HeaderBlockUnterminated, OneWrite))
            .expect(expected == NotSuccess and completeRequestsAreAnswered)
            .then(use(BodyShortOfContentLength, TwoWrites))
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
