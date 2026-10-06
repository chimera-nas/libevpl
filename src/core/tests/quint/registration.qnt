// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
module registration {
  var s: { a: bool, b: bool, slot: int, offset: int, length: int, valid: bool, issued: int }
  var op: str
  action init = all { s' = { a: false, b: false, slot: 0, offset: 0, length: 0, valid: false, issued: 0 }, op' = "Reset" }
  pure def live(state, slot) = if (slot == 0) state.a else state.b
  action register(slot: int): bool = all { not(live(s, slot)),
    s' = s.with("a", s.a or slot == 0).with("b", s.b or slot == 1)
      .with("slot", slot).with("issued", s.issued + 1), op' = "Register" }
  action unregister(slot: int): bool = all { live(s, slot),
    s' = s.with("a", s.a and slot != 0).with("b", s.b and slot != 1).with("slot", slot), op' = "Unregister" }
  action reuse(slot: int): bool = all { live(s, slot), s' = s.with("slot", slot), op' = "Reuse" }
  action validate(slot: int, offset: int, nbytes: int): bool = all {
    s' = s.with("slot", slot).with("offset", offset).with("length", nbytes)
      .with("valid", live(s, slot) and offset >= 0 and offset <= 64 and nbytes <= 64 - offset), op' = "Validate" }
  // Retain the two observed registrations while issuing/revoking enough
  // small temporary regions to cross the implementation's growth boundary.
  action churn = all { s' = s.with("issued", s.issued + 1024), op' = "Churn" }
  action step = {
    nondet slot = Set(0, 1).oneOf()
    nondet offset = Set(-1, 0, 1, 63, 64, 65).oneOf()
    nondet nbytes = Set(0, 1, 2, 64, 65).oneOf()
    any { register(slot), unregister(slot), reuse(slot), validate(slot, offset, nbytes), churn }
  }
  val inv = s.issued >= (if (s.a) 1 else 0) + (if (s.b) 1 else 0)
    and (op == "Validate" implies (s.valid implies live(s, s.slot)))
  run revokedAcrossGrowthTest = init.then(register(0)).then(register(1)).then(unregister(1))
    .then(churn).then(validate(0, 0, 64)).expect(s.valid)
    .then(validate(1, 0, 1)).expect(not(s.valid)).then(register(1)).then(reuse(1))
    .then(validate(1, 63, 2)).expect(not(s.valid))
    .then(validate(1, 64, 0)).expect(s.valid).then(validate(1, 65, 0)).expect(not(s.valid))
}
