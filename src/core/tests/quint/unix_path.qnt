// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
module unix_path {
  // 0 absent, 1 stale socket, 2 foreign live socket, 3 regular file,
  // 4 our listener. Listen never displaces another live owner or a file.
  var s: { path: int, success: bool }
  var op: str
  action init = all { s' = { path: 0, success: false }, op' = "Reset" }
  action create(kind: int): bool = all { s.path == 0, s' = s.with("path", kind),
    op' = if (kind == 1) "Stale" else if (kind == 2) "Live" else "File" }
  action listen = all { s.path != 4,
    s' = s.with("success", s.path < 2).with("path", if (s.path < 2) 4 else s.path), op' = "Listen" }
  action stop = all { s.path == 4, s' = s.with("path", 0), op' = "Stop" }
  action crash = all { s.path == 2, s' = s.with("path", 1), op' = "Crash" }
  action remove = all { s.path == 1 or s.path == 3, s' = s.with("path", 0), op' = "Remove" }
  action inspect = all { s' = s, op' = "Inspect" }
  action step = any { create(1), create(2), create(3), listen, stop, crash, remove, inspect }
  val inv = s.path >= 0 and s.path <= 4
  run recoveryTest = init.then(create(2)).then(listen).expect(not(s.success) and s.path == 2)
    .then(crash).then(listen).expect(s.success and s.path == 4).then(stop)
    .then(listen).expect(s.success).then(stop)
  run preserveFileTest = init.then(create(3)).then(listen).expect(not(s.success) and s.path == 3)
    .then(remove).then(listen).expect(s.success).then(stop)
}
