// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
module fd {
  var s: { attached: bool, interest: bool, writeInterest: bool,
           pending: int, forced: bool, retire: bool, bytes: int, reads: int, writes: int }
  var op: str
  action init = all {
    s' = { attached: false, interest: false, writeInterest: false,
           pending: 0, forced: false, retire: false, bytes: 0, reads: 0, writes: 0 },
    op' = "Reset"
  }
  action attach = all { not(s.attached),
    s' = s.with("attached", true).with("interest", false).with("writeInterest", false)
          .with("pending", 0).with("forced", false).with("retire", false), op' = "Attach" }
  action remove = all { s.attached, s' = s.with("attached", false), op' = "Remove" }
  action interest = all { s.attached, not(s.interest),
    s' = s.with("interest", true), op' = "Interest" }
  action pause = all { s.attached, s.interest,
    s' = s.with("interest", false), op' = "Pause" }
  action writeInterest = all { s.attached, not(s.writeInterest), not(s.retire),
    s' = s.with("writeInterest", true), op' = "WriteInterest" }
  action writePause = all { s.attached, s.writeInterest,
    s' = s.with("writeInterest", false), op' = "WritePause" }
  action produce = all { s.attached, s.pending < 16,
    s' = s.with("pending", s.pending + 1), op' = "Put" }
  action force = all { s.attached,
    s' = s.with("forced", true), op' = "Force" }
  action retire = all { s.attached, not(s.writeInterest),
    s' = s.with("retire", true), op' = "Retire" }
  action quiesce = {
    val read = s.attached and s.interest and (s.pending > 0 or s.forced)
    val write = s.attached and s.writeInterest
    all {
      s' = s.with("attached", s.attached and not(read and s.retire))
        .with("pending", if (read) 0 else s.pending)
        .with("forced", if (read) false else s.forced)
        .with("bytes", s.bytes + (if (read) s.pending else 0))
        .with("reads", s.reads + (if (read) 1 else 0))
        .with("writes", s.writes + (if (write) 1 else 0))
        .with("writeInterest", false),
      op' = "Quiesce"
    }
  }
  action step = any { attach, remove, interest, pause, writeInterest,
                      writePause, produce, force, retire, quiesce }
  val inv = s.bytes >= 0 and s.reads >= 0 and s.writes >= 0 and s.pending >= 0
  run retirementTest = init.then(attach).then(interest).then(produce).then(retire)
    .then(quiesce).expect(not(s.attached) and s.reads == 1 and s.bytes == 1)
    .then(quiesce).expect(s.reads == 1)
  run disinterestTest = init.then(attach).then(interest).then(produce).then(pause)
    .then(quiesce).expect(s.reads == 0).then(interest).then(quiesce)
    .expect(s.reads == 1 and s.bytes == 1)
}
