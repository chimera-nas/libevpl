// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
module ownership {
  var s: { a: bool, b: bool, c: bool, request: bool, r: bool, offset: int, length: int, refs: int }
  var op: str
  action init = all { s' = { a: false, b: false, c: false, request: false, r: false,
                            offset: 0, length: 64, refs: 0 }, op' = "Reset" }
  action allocate = all { s.refs == 0, not(s.request), s' = s.with("a", true).with("refs", 1), op' = "Allocate" }
  action clone = all { s.a, not(s.b), s' = s.with("b", true).with("refs", s.refs + 1), op' = "Clone" }
  action move = all { s.a, not(s.c), s' = s.with("a", false).with("c", true).with("offset", 0).with("length", 64), op' = "Move" }
  action moveSlice = {
    nondet offset = Set(0, 8, 48).oneOf()
    all { s.a, not(s.c), s' = s.with("a", false).with("c", true).with("offset", offset).with("length", 16), op' = "Slice" }
  }
  action releaseA = all { s.a, s' = s.with("a", false).with("refs", s.refs - 1), op' = "ReleaseA" }
  action releaseB = all { s.b, s' = s.with("b", false).with("refs", s.refs - 1), op' = "ReleaseB" }
  action releaseC = all { s.c, s' = s.with("c", false).with("refs", s.refs - 1), op' = "ReleaseC" }
  action request = all { s.a, not(s.request), s' = s.with("a", false).with("r", true).with("request", true), op' = "Request" }
  action take = all { s.request, s.r, s' = s.with("r", false).with("a", true), op' = "Take" }
  action takeEmpty = all { s.request, not(s.r), s' = s, op' = "TakeEmpty" }
  action destroy = all { s.request, s' = s.with("request", false).with("r", false).with("refs", s.refs - (if (s.r) 1 else 0)), op' = "Destroy" }
  action inspect = all { s' = s, op' = "Inspect" }
  action step = if (s.refs == 0 and not(s.request)) allocate
    else any { clone, move, moveSlice, releaseA, releaseB, releaseC, request, take, takeEmpty, destroy, inspect }
  val inv = s.refs == (if (s.a) 1 else 0) + (if (s.b) 1 else 0) + (if (s.c) 1 else 0) + (if (s.r) 1 else 0)
    and (s.r implies s.request) and s.offset + s.length <= 64
  run transferSurvivesRequestTest = init.then(allocate).then(clone).then(request).then(take).then(takeEmpty)
    .then(destroy).expect(s.a and s.b and s.refs == 2).then(releaseA).then(releaseB).expect(s.refs == 0)
  run unclaimedRequestTest = init.then(allocate).then(request).then(destroy).expect(s.refs == 0)
  run movedViewTest = init.then(allocate).then(clone).then(moveSlice).then(releaseB)
    .expect(s.c and s.refs == 1).then(releaseC).expect(s.refs == 0)
}
