// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
module block_retry {
  var s: { opened: bool, online: bool, closing: bool, waiting: bool, kind: int,
           value: int, completions: int, errors: int, closes: int, retries: int }
  var op: str
  action init = all { s' = { opened: false, online: true, closing: false, waiting: false,
    kind: 0, value: 0, completions: 0, errors: 0, closes: 0, retries: 0 }, op' = "Reset" }
  action openDevice = all { not(s.opened), s.online, s' = s.with("opened", true), op' = "Open" }
  action readDevice = all { s.opened, s.online, not(s.closing), not(s.waiting),
    s' = s.with("waiting", true).with("kind", 0), op' = "Read" }
  action writeDevice = all { s.opened, s.online, not(s.closing), not(s.waiting),
    s' = s.with("waiting", true).with("kind", 1), op' = "Write" }
  action closeDevice = all { s.opened, not(s.closing),
    s' = s.with("closing", s.waiting).with("opened", s.waiting)
          .with("closes", s.closes + (if (s.waiting) 0 else 1)), op' = "Close" }
  action removeDevice = all { s.opened, s.online, s' = s.with("online", false), op' = "Remove" }
  action retryAgain = all { s.waiting, s.online, s' = s.with("retries", s.retries + 1), op' = "RetryAgain" }
  action retry = all { s.waiting,
    s' = s.with("waiting", false).with("completions", s.completions + 1)
          .with("errors", s.errors + (if (s.online) 0 else 1))
          .with("value", if (s.online and s.kind == 1) 1 - s.value else s.value)
          .with("opened", not(s.closing)).with("closing", false)
          .with("closes", s.closes + (if (s.closing) 1 else 0))
          .with("retries", s.retries + 1), op' = "Retry" }
  action inspect = all { s' = s, op' = "Inspect" }
  action step = if (not(s.opened) and (not(s.online) or s.closes > 0)) init
    else any { openDevice, readDevice, writeDevice, closeDevice, removeDevice, retryAgain, retry, inspect }
  val inv = (s.waiting implies s.opened) and (s.closing implies s.waiting)
    and s.errors <= s.completions and s.value >= 0 and s.value <= 1
  run closeWhileWaitingTest = init.then(openDevice).then(writeDevice).then(closeDevice)
    .expect(s.closes == 0 and s.waiting).then(retryAgain).then(retry)
    .expect(s.closes == 1 and s.completions == 1 and s.value == 1)
  run removeWhileWaitingTest = init.then(openDevice).then(readDevice).then(removeDevice)
    .then(closeDevice).then(retry).expect(s.closes == 1 and s.errors == 1)
  run readWrittenBytesTest = init.then(openDevice).then(writeDevice).then(retry)
    .then(readDevice).then(retryAgain).then(retry)
    .expect(s.value == 1 and s.completions == 2 and s.errors == 0)
}
