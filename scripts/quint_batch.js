#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: Unlicense
//
// Run several quint checks against ONE elaboration of a model.
//
// WHY: `quint test` and `quint run` handle one --main per process, and nearly
// all of a quint invocation is load+parse+typecheck.  Measured with the pinned
// quint 0.32.0: elaborating core.qnt costs 3.35s and http1x.qnt 3.53s, against
// ~4s to actually simulate.  check_models.sh ran six sequential invocations of
// http1x.qnt, so five of its six elaborations were pure waste.
//
// quint's CLI cannot share an elaboration; its library can.  cliCommands
// exposes the pipeline as stages -- load, parse, typecheck, then runTests or
// runSimulator -- and both consumers read main, invariant, maxSamples and
// maxSteps from stage.args at call time, while the only expensive artifact they
// need is stage.resolver.table.
//
// This is used ONLY by the check scripts.  The generate_*.sh scripts keep one
// process per group on purpose: their simulation cost is high enough that
// running the groups concurrently beats sharing an elaboration between them.
//
// CAVEAT: cliCommands is not part of the quint package's public exports, so
// this reaches into dist/src directly.  That is safe only because the images
// pin the quint version; a quint bump is a code change here, not just a version
// bump.  If quint grows a real batch mode, delete this in favour of it.
//
// Usage: quint_batch.js <quint-cli-path> < spec.json
//   { "model": "...", "backend": "rust",
//     "tests": [ { "main": "..." } ],
//     "runs":  [ { "main": "...", "invariant": "...",
//                  "maxSamples": N, "maxSteps": N } ] }

const fs = require('fs')
const os = require('os')
const path = require('path')

const die = m => { console.error(`quint_batch: ${m}`); process.exit(1) }

const cliPath = process.argv[2]
if (!cliPath) die('usage: quint_batch.js <quint-cli-path> < spec.json')
const spec = JSON.parse(fs.readFileSync(0, 'utf8'))

// Resolve quint's library from the CLI the caller found, not from NODE_PATH:
// the images install quint under /opt/quint and a plain require() would not see
// it from here.  realpath because the bin entry is a symlink into dist/src.
let cmds
try {
  cmds = require(path.join(path.dirname(fs.realpathSync(cliPath)), 'cliCommands'))
} catch (err) {
  die(`could not load quint's cliCommands from ${cliPath}: ${err.message}`)
}
for (const fn of ['load', 'parse', 'typecheck', 'runTests', 'runSimulator']) {
  if (typeof cmds[fn] !== 'function') die(`quint's cliCommands has no ${fn}()`)
}

// The defaults `quint test` / `quint run` apply, so each entry here is the
// invocation the CLI would have made.  No seed: neither check was seeded before
// -- they are randomised checks, and fixing a seed would quietly turn them into
// a single fixed sample.
const argsFor = o => ({
  input: spec.model,
  main: o.main,
  init: 'init',
  step: 'step',
  invariant: o.invariant ?? 'true',
  invariants: [],
  witnesses: [],
  hide: [],
  maxSamples: o.maxSamples ?? 10000,
  maxSteps: o.maxSteps ?? 20,
  nTraces: 1,
  nThreads: os.cpus().length,
  seed: undefined,
  backend: spec.backend ?? 'rust',
  mbt: false,
  verbosity: 0,
  quiet: true,
  out: undefined,
  outItf: undefined,
})

;(async () => {
  const t0 = Date.now()
  const loaded = await cmds.load(argsFor({ main: undefined }))
  if (loaded.isLeft()) die(`load ${spec.model}: ${JSON.stringify(loaded.value.errors)}`)
  const parsed = await cmds.parse(loaded.value)
  if (parsed.isLeft()) die(`parse ${spec.model}: ${JSON.stringify(parsed.value.errors)}`)
  const checked = await cmds.typecheck(parsed.value)
  if (checked.isLeft()) die(`typecheck ${spec.model}: ${JSON.stringify(checked.value.errors)}`)
  const stage = checked.value
  const name = path.basename(spec.model)
  console.log(`${name}: elaborated in ${((Date.now() - t0) / 1000).toFixed(1)}s ` +
              `(${(spec.tests ?? []).length} test(s), ${(spec.runs ?? []).length} invariant run(s))`)

  for (const t of spec.tests ?? []) {
    stage.args = argsFor(t)
    const r = await cmds.runTests(stage)
    if (r.isLeft() || (r.value.status && r.value.status !== 'passed')) {
      die(`quint test failed: ${name} --main=${t.main}`)
    }
    console.log(`  test  ${t.main ?? '(default module)'}: ok`)
  }

  for (const r of spec.runs ?? []) {
    stage.args = argsFor(r)
    const res = await cmds.runSimulator(stage)
    if (res.isLeft()) die(`invariant violated: ${name} --main=${r.main} --invariant=${r.invariant}`)
    console.log(`  run   ${r.main ?? '(default module)'} (${r.invariant}): ok`)
  }
  console.log(`${name}: all checks passed in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
})().catch(e => die(e.stack || String(e)))
