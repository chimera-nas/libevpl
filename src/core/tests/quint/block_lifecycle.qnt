// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
module block_lifecycle {
  var s: { opened: bool, online: bool, blocks: int, resizes: int, removes: int }
  var op: str
  action init = all { s' = { opened: false, online: true, blocks: 16, resizes: 0, removes: 0 }, op' = "Reset" }
  action openDevice = all { not(s.opened), s.online, s' = s.with("opened", true), op' = "Open" }
  action closeDevice = all { s.opened, s' = s.with("opened", false), op' = "Close" }
  action resize = all { s.opened, s.online, s.blocks < 64,
    s' = s.with("blocks", s.blocks + 16).with("resizes", s.resizes + 1), op' = "Resize" }
  action removeDevice = all { s.opened, s.online,
    s' = s.with("online", false).with("removes", s.removes + 1), op' = "Remove" }
  action readDevice = all { s.opened, s' = s, op' = if (s.online) "Read" else "ReadRemoved" }
  action inspect = all { s' = s, op' = "Inspect" }
  action step = if (not(s.opened) and not(s.online)) init
    else any { openDevice, closeDevice, resize, removeDevice, readDevice, inspect }
  val inv = s.blocks >= 16 and s.blocks <= 64 and s.removes <= 1
  run resizeThenRemoveTest = init.then(openDevice).then(resize)
    .expect(s.blocks == 32 and s.resizes == 1).then(removeDevice).then(readDevice)
    .expect(op == "ReadRemoved" and s.removes == 1).then(closeDevice)
    .expect(not(s.opened))
}
