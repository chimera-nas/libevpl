// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
module rdma {
  // The adapter freezes the peer until Drain/PartialClose, or closes it
  // before dispatch. PartialClose drives callbacks through a chosen prefix.
  // Each burst accesses the same region with identical writes, so neither
  // callback order nor ordering between independent reads is assumed.
  var s: { connected: bool, pending: int, count: int, kind: int, access: int,
           take: bool, value: int, memory: int, completions: int, errors: int, prefix: int }
  var op: str
  action init = all { s' = { connected: false, pending: 0, count: 0, kind: 0,
    access: 0, take: false, value: 0, memory: 0, completions: 0, errors: 0, prefix: 0 }, op' = "Reset" }
  action connect = all { not(s.connected), s.pending == 0,
    s' = s.with("connected", true), op' = "Connect" }
  // kind: read/write; access: valid/reserved key/unknown key/below/overflow.
  action queue(n: int, kind: int, access: int, take: bool): bool = all {
    s.connected, s.pending == 0,
    s' = s.with("pending", n).with("count", n).with("kind", kind)
      .with("access", access).with("take", take).with("value", 1 - s.memory).with("prefix", 0), op' = "Queue"
  }
  action burst = {
    nondet n = Set(1, 15, 16, 17, 33).oneOf()
    nondet kind = Set(0, 1).oneOf()
    nondet access = Set(0, 1, 2, 3, 4).oneOf()
    nondet take = Set(false, true).oneOf()
    queue(n, kind, access, take)
  }
  action drain = all { s.connected, s.pending > 0,
    s' = s.with("pending", 0).with("completions", s.completions + s.pending)
      .with("errors", s.errors + (if (s.access == 0) 0 else s.pending))
      .with("memory", if (s.access == 0 and s.kind == 1) s.value else s.memory), op' = "Drain" }
  action disconnect(peer: bool): bool = all { s.connected,
    s' = s.with("connected", false).with("pending", 0)
      .with("completions", s.completions + s.pending).with("errors", s.errors + s.pending),
    op' = if (peer) "PeerClose" else "Close" }
  // Cancellation is requested inside the nth operation callback. Earlier
  // outcomes survive; the suffix must complete once with ECONNRESET. A write
  // can already have affected remote memory even if its ACK is cancelled.
  action partialClose(n: int): bool = all { s.connected, n > 0, n < s.pending,
    s' = s.with("connected", false).with("pending", 0).with("prefix", n)
      .with("completions", s.completions + s.pending)
      .with("errors", s.errors + s.pending - (if (s.access == 0) n else 0))
      .with("memory", if (s.access == 0 and s.kind == 1) s.value else s.memory), op' = "PartialClose" }
  action partial = {
    nondet n = Set(1, s.pending / 2, s.pending - 1).oneOf()
    partialClose(n)
  }
  action inspect = all { s' = s, op' = "Inspect" }
  action step = any { connect, burst, drain, disconnect(false), disconnect(true), partial, inspect }
  val inv = s.pending >= 0 and s.pending <= 33 and (s.pending > 0 implies s.connected)
    and s.errors <= s.completions and Set(0, 1).contains(s.memory)
    and (op == "PartialClose" implies (not(s.connected) and s.prefix > 0 and s.prefix < s.count))
  run wrappedGrowthTest = init.then(connect).then(queue(15, 0, 0, false)).then(drain)
    .then(queue(16, 1, 0, true)).then(drain).then(queue(17, 0, 0, false)).then(drain)
    .then(queue(33, 1, 0, false)).then(drain).then(disconnect(false))
    .expect(s.completions == 81 and s.errors == 0)
  run invalidThenValidTest = init.then(connect).then(queue(17, 0, 1, false)).then(drain)
    .then(queue(16, 1, 2, true)).then(drain).then(queue(1, 0, 3, false)).then(drain)
    .then(queue(1, 1, 4, false)).then(drain).then(queue(1, 0, 4, false)).then(drain)
    .then(queue(1, 1, 3, true)).then(drain).then(queue(1, 0, 2, false)).then(drain)
    .then(queue(1, 1, 1, false)).then(drain).then(queue(1, 1, 0, true)).then(drain)
    .then(queue(1, 0, 0, false)).then(drain).expect(s.errors == 39 and s.memory == 1)
  run cancelReadTest = init.then(connect).then(queue(17, 0, 0, false)).then(disconnect(false))
    .expect(s.completions == 17 and s.errors == 17).then(connect)
    .then(queue(1, 0, 0, false)).then(drain).expect(s.completions == 18 and s.errors == 17)
  run cancelWriteTest = init.then(connect).then(queue(17, 1, 0, true)).then(disconnect(true))
    .expect(s.completions == 17 and s.errors == 17 and s.memory == 0)
  run cancelPeerReadTest = init.then(connect).then(queue(16, 0, 0, false)).then(disconnect(true))
    .expect(s.completions == 16 and s.errors == 16)
  run cancelLocalWriteTest = init.then(connect).then(queue(15, 1, 0, false)).then(disconnect(false))
    .expect(s.completions == 15 and s.errors == 15 and s.memory == 0)
  run partialWrappedReadTest = init.then(connect).then(queue(1, 0, 0, false)).then(drain)
    .then(queue(15, 0, 0, false)).then(partialClose(14))
    .expect(s.completions == 16 and s.errors == 1).then(connect)
    .then(queue(17, 0, 0, false)).then(partialClose(1)).expect(s.errors == 17)
  run partialGrownReadTest = init.then(connect).then(queue(15, 0, 0, false)).then(drain)
    .then(queue(33, 0, 0, false)).then(partialClose(16)).expect(s.completions == 48 and s.errors == 17)
  run partialBorrowedWriteTest = init.then(connect).then(queue(16, 1, 0, false)).then(partialClose(1))
    .expect(s.errors == 15 and s.memory == 1).then(connect)
    .then(queue(1, 0, 0, false)).then(drain).expect(s.completions == 17 and s.errors == 15)
  run partialTransferredWriteTest = init.then(connect).then(queue(33, 1, 0, true)).then(partialClose(32))
    .expect(s.errors == 1 and s.memory == 1)
  run partialReadErrorsTest = init.then(connect).then(queue(17, 0, 1, false)).then(partialClose(8))
    .expect(s.completions == 17 and s.errors == 17 and s.memory == 0)
  run partialBorrowedWriteErrorsTest = init.then(connect).then(queue(16, 1, 2, false)).then(partialClose(15))
    .expect(s.completions == 16 and s.errors == 16 and s.memory == 0)
  run partialTransferredWriteErrorsTest = init.then(connect).then(queue(33, 1, 3, true)).then(partialClose(1))
    .expect(s.completions == 33 and s.errors == 33 and s.memory == 0)
}
