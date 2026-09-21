// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
// Execute the exact trusted workflow script with mocked GitHub and artifact I/O.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const workflow = fs.readFileSync(path.join(__dirname, '../../.github/workflows/pr-coverage-comment.yml'), 'utf8');
const script = workflow.split('          script: |\n')[1].split('\n').map(l => l.slice(12)).join('\n');
const execute = new (Object.getPrototypeOf(async function() {}).constructor)('require', 'context', 'github', 'core', script);
const marker = '<!-- mbt-coverage-report -->';

async function run(overrides = {}) {
  const calls = [];
  const files = {'coverage/pr-number.txt': '123\n', 'coverage/coverage-report.md': marker + '\nreport', ...overrides.files};
  const context = {repo: {owner: 'chimera-nas', repo: 'libevpl'}, payload: {workflow_run: {
    id: 20, run_attempt: 2, head_sha: 'abc123', head_branch: 'topic', html_url: 'https://github.com/run/20',
    head_repository: {id: 200}, repository: {id: 100}, ...overrides.workflow_run}}};
  const rest = {
    pulls: {get: async () => ({data: {state: 'open', head: {sha: 'abc123', ref: 'topic', repo: {id: 200}},
      base: {repo: {id: 100}}, ...overrides.pr}})},
    issues: {listComments: 'comments',
      createComment: async value => calls.push(['create', value]),
      updateComment: async value => calls.push(['update', value])}
  };
  await execute(() => ({existsSync: p => files[p] !== undefined, readFileSync: p => files[p]}), context,
    {rest, paginate: async method => {
      assert.equal(method, 'comments');
      return overrides.comments ?? [];
    }},
    {notice: () => {}});
  return calls;
}

test('create a fork PR comment without a base-repository commit association', async () => {
  const calls = await run();
  assert.equal(calls[0][0], 'create');
  assert.equal(calls[0][1].issue_number, 123);
  assert.ok(calls[0][1].body.includes('<!-- mbt-run:20:2 -->'));
});
test('create a comment for a same-repository PR', async () => {
  const calls = await run({workflow_run: {head_repository: {id: 100}},
    pr: {head: {sha: 'abc123', ref: 'topic', repo: {id: 100}}}});
  assert.equal(calls[0][0], 'create');
});
test('reject a matching branch and commit from another source or target repository', async () => {
  for (const pr of [
    {head: {sha: 'abc123', ref: 'topic', repo: {id: 201}}},
    {base: {repo: {id: 101}}},
    {head: {sha: 'abc123', ref: 'topic', repo: null}}
  ]) {
    await assert.rejects(run({pr}), /repositories do not match/);
  }
  for (const workflow_run of [{head_repository: null}, {repository: null}]) {
    await assert.rejects(run({workflow_run}), /repositories do not match/);
  }
});
test('update only our bot comment', async () => {
  const calls = await run({comments: [
    {id: 1, user: {login: 'contributor'}, body: marker},
    {id: 2, user: {login: 'github-actions[bot]'}, body: marker + '\n<!-- mbt-run:19:1 -->'}]});
  assert.equal(calls[0][0], 'update');
  assert.equal(calls[0][1].comment_id, 2);
});
test('skip stale heads, different branches and closed PRs', async () => {
  for (const pr of [{state: 'closed'}, {head: {sha: 'new', ref: 'topic'}}, {head: {sha: 'abc123', ref: 'other'}}]) {
    assert.deepEqual(await run({pr}), []);
  }
});
test('reject malformed or redirected report metadata', async () => {
  await assert.rejects(run({files: {'coverage/pr-number.txt': '123;echo bad'}}), /Invalid PR/);
  await assert.rejects(run({files: {'coverage/coverage-report.md': 'bad'}}), /marker/);
});
test('ignore missing reports and newer existing reports', async () => {
  assert.deepEqual(await run({files: {'coverage/pr-number.txt': undefined}}), []);
  for (const stamp of ['21:1', '20:3']) {
    assert.deepEqual(await run({comments: [{id: 2, user: {login: 'github-actions[bot]'},
      body: marker + `\n<!-- mbt-run:${stamp} -->`}]}), []);
  }
});
test('large reports fit a GitHub comment', async () => {
  const calls = await run({files: {'coverage/coverage-report.md': marker + 'a'.repeat(70000)}});
  assert.ok(calls[0][1].body.length < 65536);
  assert.ok(calls[0][1].body.includes('truncated'));
});
