// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
module datagram_boundary {
  var s: { live: bool, queued: int, drained: bool, fragments: int, take: bool, prefix: int }
  var op: str
  action init = all { s' = { live: false, queued: 0, drained: true, fragments: 1, take: false, prefix: 0 }, op' = "Reset" }
  action connect = all { not(s.live), s' = { live: true, queued: 0, drained: true, fragments: 1, take: false, prefix: 0 }, op' = "Connect" }
  action queue(fragments: int, take: bool): bool = all { s.live, s.queued < 3,
    s' = s.with("queued", s.queued + 1).with("drained", false).with("fragments", fragments).with("take", take), op' = "Queue" }
  action hold = all { s.live, not(s.drained), s' = s, op' = "Hold" }
  action drain = all { s.live, not(s.drained), s' = s.with("drained", true), op' = "Drain" }
  action close(peer: bool): bool = all { s.live, s' = s.with("live", false), op' = if (peer) "PeerClose" else "Close" }
  // Close from the Nth receive callback. Later messages have no delivery
  // obligation, but all application-owned views must survive cancellation.
  action cancel(prefix: int): bool = all { s.live, not(s.drained), s.queued == 1, s.fragments == 65,
    s' = s.with("live", false).with("prefix", prefix), op' = "CancelPrefix" }
  action step = any { connect, queue(1, false), queue(4, true), queue(5, false), queue(65, true),
    hold, drain, close(false), close(true), cancel(1), cancel(7) }
  val inv = s.queued >= 0 and s.queued <= 3 and s.prefix >= 0 and s.prefix <= 7
  run boundariesTest = init.then(connect).then(queue(1, false)).then(drain)
    .then(queue(4, true)).then(drain).then(queue(5, false)).then(drain).then(close(false))
  run coalescingTest = init.then(connect).then(queue(65, false)).then(hold).then(drain)
    .then(queue(65, true)).then(drain).then(close(true))
  run pendingLocalTest = init.then(connect).then(queue(65, true)).then(hold).then(close(false))
    .then(connect).then(queue(5, false)).then(drain).then(close(false))
  run pendingPeerTest = init.then(connect).then(queue(65, false)).then(hold).then(close(true))
    .then(connect).then(queue(65, true)).then(drain).then(close(false))
  run firstCancelTest = init.then(connect).then(queue(65, false)).then(hold).then(cancel(1))
  run middleCancelTest = init.then(connect).then(queue(65, true)).then(hold).then(cancel(7))
}
