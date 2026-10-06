// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
// Sent callbacks may coalesce and precede peer delivery. Only observed prefixes
// and drained connections have exact obligations; Close cancels the suffix.
module backpressure {
  var s: { live: bool, finishing: bool, take: bool, queued: int, read: int, drained: bool }
  var op: str
  action init = all { s' = { live: false, finishing: false, take: false, queued: 0, read: 0, drained: true }, op' = "Reset" }
  action connect(take: bool): bool = all { not(s.live),
    s' = { live: true, finishing: false, take: take, queued: 0, read: 0, drained: true }, op' = "Connect" }
  action queue = all { s.live, not(s.finishing), s.queued < 2,
    s' = s.with("queued", s.queued + 1).with("drained", false), op' = "Queue" }
  action hold = all { s.live, not(s.drained), s.read < s.queued * 4 - 1,
    s' = s, op' = "Hold" }
  action prefix = all { s.live, not(s.drained), s.read < s.queued * 4 - 1,
    s' = s.with("read", s.read + 1), op' = "Prefix" }
  action drain = all { s.live, s.queued > 0, not(s.drained),
    s' = s.with("read", s.queued * 4).with("drained", true).with("live", not(s.finishing)), op' = "Drain" }
  action finish = all { s.live, not(s.finishing), not(s.drained),
    s' = s.with("finishing", true), op' = "Finish" }
  action close(peer: bool): bool = all { s.live,
    s' = s.with("live", false), op' = if (peer) "PeerClose" else "Close" }
  action step = any { connect(false), connect(true), queue, hold, prefix, drain, finish, close(false), close(true) }
  val inv = s.queued >= 0 and s.queued <= 2 and s.read >= 0 and s.read <= s.queued * 4
    and (s.drained implies s.read == s.queued * 4)
  run resumeBorrowedTest = init.then(connect(false)).then(queue).then(hold).then(prefix).then(hold).then(drain)
    .then(queue).then(hold).then(finish).then(drain).expect(not(s.live) and s.read == 8)
  run resumeTransferredTest = init.then(connect(true)).then(queue).then(hold).then(prefix).then(hold).then(drain)
    .then(close(false))
  run localCancelTest = init.then(connect(true)).then(queue).then(hold).then(prefix).then(hold).then(close(false))
    .then(connect(false)).then(queue).then(drain).then(close(false))
  run peerCancelTest = init.then(connect(false)).then(queue).then(hold).then(prefix).then(hold).then(close(true))
    .then(connect(true)).then(queue).then(drain).then(close(false))
  run finishThenResetTest = init.then(connect(true)).then(queue).then(hold).then(finish).then(prefix).then(hold).then(close(true))
  run queuedCancelTest = init.then(connect(false)).then(queue).then(hold).then(queue).then(close(false))
}
