// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
module listener {
  var s: { listening: bool, attached: bool, pending: bool, accepts: int, disconnects: int }
  var op: str
  action init = all { s' = { listening: false, attached: false, pending: false, accepts: 0, disconnects: 0 }, op' = "Reset" }
  action start = all { not(s.listening), s' = s.with("listening", true), op' = "Start" }
  action attach = all { s.listening, not(s.attached), not(s.pending), s' = s.with("attached", true), op' = "Attach" }
  action detach = all { s.attached, s' = s.with("attached", false), op' = "Detach" }
  action connect = all { s.attached, not(s.pending), s' = s.with("pending", true), op' = "Connect" }
  action stop = all { s.listening, not(s.attached), not(s.pending), s' = s.with("listening", false), op' = "Stop" }
  action quiesce = all {
    s' = s.with("pending", false)
      .with("accepts", s.accepts + (if (s.pending and s.attached) 1 else 0))
      .with("disconnects", s.disconnects + (if (s.pending) 1 else 0)), op' = "Quiesce" }
  action step = any { start, attach, detach, connect, stop, quiesce }
  val inv = s.accepts <= s.disconnects and (s.attached implies s.listening)
  run discardQueuedAcceptTest = init.then(start).then(attach).then(connect).then(detach)
    .then(quiesce).expect(s.accepts == 0 and s.disconnects == 1).then(stop)
}
