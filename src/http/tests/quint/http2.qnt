// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
// HTTP/2 integration contract, not an HPACK or frame-parser specification.
// Three independent streams share a connection. The adapter spells bodies,
// headers and frames; the model decides legal operations and terminal outcomes.
module http2 {
  type Stream = { phase: int, shape: int, streaming: bool, trailers: bool, interim: bool }
  pure val empty = { phase: 0, shape: 0, streaming: false, trailers: false, interim: false }
  var s: { connected: bool, client: bool, blocked: bool, fragmented: bool, streams: List[Stream] }
  var op: str
  var slot: int
  action init = all {
    s' = { connected: false, client: false, blocked: false, fragmented: false,
           streams: [empty, empty, empty] }, op' = "Reset", slot' = 0 }
  pure def active(st: Stream, blocked: bool): bool = st.phase > 0 and st.phase != 6 and (st.phase != 5 or (blocked and st.shape > 0))
  action connect(client: bool, blocked: bool, fragmented: bool): bool = all {
    not(s.connected), not(client and blocked),
    s' = { connected: true, client: client, blocked: blocked, fragmented: fragmented,
           streams: [empty, empty, empty] }, op' = "Connect", slot' = 0 }
  action open(k: int, shape: int, streaming: bool, trailers: bool): bool = all {
    s.connected, not(active(s.streams[k], s.blocked)),
    s' = s.with("streams", s.streams.replaceAt(k,
      { phase: 1, shape: shape, streaming: streaming, trailers: trailers, interim: false })),
    op' = "Open", slot' = k }
  action upload(k: int): bool = all { s.connected, s.streams[k].phase == 1,
    s' = s.with("streams", s.streams.replaceAt(k, s.streams[k].with("phase", 2))), op' = "Upload", slot' = k }
  action interim(k: int): bool = all { s.connected, s.client, s.streams[k].phase == 2, not(s.streams[k].interim),
    s' = s.with("streams", s.streams.replaceAt(k, s.streams[k].with("interim", true))), op' = "Interim", slot' = k }
  action respond(k: int): bool = all { s.connected, s.streams[k].phase == 2,
    s' = s.with("streams", s.streams.replaceAt(k, s.streams[k].with("phase", 3))), op' = "Respond", slot' = k }
  action partial(k: int): bool = all { s.connected, s.streams[k].phase == 3, s.streams[k].shape > 0,
    s' = s.with("streams", s.streams.replaceAt(k, s.streams[k].with("phase", 4))), op' = "Partial", slot' = k }
  action finish(k: int): bool = all { s.connected, Set(3, 4).contains(s.streams[k].phase),
    s' = s.with("streams", s.streams.replaceAt(k, s.streams[k].with("phase", 5))), op' = "Finish", slot' = k }
  action cancel(k: int): bool = all { s.connected, s.streams[k].phase >= 2, active(s.streams[k], s.blocked),
    s' = s.with("streams", s.streams.replaceAt(k, s.streams[k].with("phase", 6))), op' = "Cancel", slot' = k }
  action release = all { s.connected, s.blocked,
    s' = s.with("blocked", false), op' = "Release", slot' = 0 }
  action close = all { s.connected,
    s' = s.with("connected", false).with("streams", s.streams.foldl([], (xs, st) =>
      xs.append(if (active(st, s.blocked)) st.with("phase", 6) else st))), op' = "Close", slot' = 0 }
  action goaway = all { s.connected, s.client,
    Set(0, 1, 2).forall(k => s.streams[k].phase != 1),
    s' = s.with("connected", false).with("streams", s.streams.foldl([], (xs, st) =>
      xs.append(if (active(st, s.blocked)) st.with("phase", 6) else st))), op' = "Goaway", slot' = 0 }
  action step = {
    nondet k = Set(0, 1, 2).oneOf()
    nondet shape = Set(0, 1, 2).oneOf()
    nondet streaming = Set(false, true).oneOf()
    nondet trailers = Set(false, true).oneOf()
    nondet client = Set(false, true).oneOf()
    nondet blocked = Set(false, true).oneOf()
    nondet fragmented = Set(false, true).oneOf()
    any { connect(client, blocked, fragmented), open(k, shape, streaming, trailers),
          upload(k), interim(k), respond(k), partial(k), finish(k), cancel(k), release, close, goaway }
  }
  val inv = s.streams.length() == 3 and not(s.client and s.blocked) and
    Set(0, 1, 2).forall(k => s.streams[k].phase >= 0 and s.streams[k].phase <= 6 and s.streams[k].shape >= 0 and s.streams[k].shape <= 2) and
    (not(s.connected) implies Set(0, 1, 2).forall(k => not(active(s.streams[k], s.blocked))))

  run serverMultiplexTest = init.then(connect(false, false, true))
    .then(open(0, 2, true, true)).then(open(1, 1, false, false)).then(open(2, 0, true, true))
    .then(upload(0)).then(upload(1)).then(upload(2))
    .then(respond(2)).then(finish(2)).then(respond(0)).then(partial(0)).then(cancel(1)).then(finish(0))
    .then(open(1, 1, true, false)).then(upload(1)).then(respond(1)).then(partial(1)).then(close)
    .expect(s.streams[0].phase == 5 and s.streams[1].phase == 6 and s.streams[2].phase == 5)
  run clientMultiplexTest = init.then(connect(true, false, true))
    .then(open(0, 2, true, true)).then(open(1, 1, false, false)).then(open(2, 0, true, true))
    .then(upload(0)).then(upload(1)).then(upload(2)).then(interim(0))
    .then(respond(2)).then(finish(2)).then(respond(0)).then(partial(0)).then(cancel(1)).then(finish(0))
    .then(open(1, 1, true, false)).then(upload(1)).then(respond(1)).then(partial(1)).then(close)
    .expect(s.streams[0].phase == 5 and s.streams[1].phase == 6 and s.streams[2].phase == 5)
  run windowResumeTest = init.then(connect(false, true, false)).then(open(0, 2, false, true))
    .then(upload(0)).then(respond(0)).then(partial(0)).then(finish(0))
    .expect(active(s.streams[0], s.blocked)).then(release).expect(not(active(s.streams[0], s.blocked))).then(close)
  run windowCancelTest = init.then(connect(false, true, true)).then(open(0, 2, true, false))
    .then(upload(0)).then(respond(0)).then(partial(0)).then(cancel(0)).then(release).then(close)
  run goawayTest = init.then(connect(true, false, false)).then(open(0, 1, false, true))
    .then(open(1, 2, true, false)).then(upload(0)).then(upload(1)).then(respond(0)).then(partial(0))
    .then(goaway).expect(s.streams[0].phase == 6 and s.streams[1].phase == 6)
  run queuedCloseTest = init.then(connect(true, false, false)).then(open(0, 2, false, true))
    .then(open(1, 0, true, true)).then(close).expect(s.streams[0].phase == 6 and s.streams[1].phase == 6)
  run emptyFixedServerTest = init.then(connect(false, false, false)).then(open(0, 0, false, false))
    .then(upload(0)).then(respond(0)).then(finish(0)).then(close)
  run emptyFixedClientTest = init.then(connect(true, false, false)).then(open(0, 0, false, true))
    .then(upload(0)).then(respond(0)).then(finish(0)).then(close)
}
