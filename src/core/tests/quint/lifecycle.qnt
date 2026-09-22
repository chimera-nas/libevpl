// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
module lifecycle {
  // Handles are consumed by destroy. Stop completion is observed only at a
  // barrier; readiness must precede shutdown for every created worker.
  var s: { live: int, kind: int, stopping: bool, created: int,
           ready: int, stopped: int, completions: int, pending: int }
  var op: str
  action init = all {
    s' = { live: 0, kind: 0, stopping: false, created: 0,
           ready: 0, stopped: 0, completions: 0, pending: 0 }, op' = "Reset" }
  action create(n: int, k: int, name: str): bool = all {
    s.kind == 0, not(s.stopping),
    s' = s.with("live", n).with("kind", k).with("created", s.created + n), op' = name }
  action stop(async: bool): bool = all {
    s.kind != 0,
    s' = s.with("kind", 0).with("live", 0).with("stopping", true)
      .with("pending", if (async) 1 else 0),
    op' = if (async) "StopAsync" else "Stop"
  }
  action quiesce = all {
    s' = s.with("ready", s.created).with("stopped", s.created - s.live)
      .with("completions", s.completions + s.pending).with("pending", 0)
      .with("stopping", false), op' = "Quiesce" }
  action step = any {
    create(1, 1, "Thread"), create(1, 1, "ThreadAsync"),
    create(0, 2, "EmptyPool"), create(2, 2, "Pool"),
    stop(false), stop(true), quiesce }
  val inv = s.stopped <= s.ready and s.ready <= s.created and s.live >= 0
  run stopBeforeReadyTest = init.then(create(1, 1, "ThreadAsync")).then(stop(true))
    .then(quiesce).expect(s.ready == 1 and s.stopped == 1 and s.completions == 1)
  run emptyPoolTest = init.then(create(0, 2, "EmptyPool")).then(stop(true))
    .then(quiesce).expect(s.ready == 0 and s.stopped == 0 and s.completions == 1)
}
