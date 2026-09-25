'use strict';
// Unit tests for the sandbox test harness, run under plain `node` (no jest, no packages) from
// tests/test_harness.py. The real built-ins are captured before the harness installs its
// require hook, so this file can spawn node and touch the filesystem for real.
const realFs = require('node:fs');
const os = require('node:os');
const pathReal = require('node:path');
const cp = require('node:child_process');
const util = require('node:util');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const source = process.env.MITIG8IT_HARNESS_SOURCE || pathReal.resolve(__dirname, '..', 'src', 'sandbox', 'harness.js');
const root = realFs.mkdtempSync(pathReal.join(os.tmpdir(), 'mitig8it-harness-'));
const write = (relative, content) => {
  const target = pathReal.join(root, relative);
  realFs.mkdirSync(pathReal.dirname(target), { recursive: true });
  realFs.writeFileSync(target, content);
};
realFs.mkdirSync(pathReal.join(root, '.mitig8it', 'regression'), { recursive: true });
realFs.copyFileSync(source, pathReal.join(root, '.mitig8it', 'harness.js'));

const VULNERABLE = `const express = require('express');
const { Pool } = require('pg');
const { exec, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();
const REPORT_DIR = path.join(__dirname, '..', 'reports');
router.get('/orders/:id', async (req, res) => {
  const result = await pool.query("SELECT id FROM orders WHERE id = '" + req.params.id + "'");
  res.json(result.rows);
});
router.post('/orders/:id/invoice', (req, res) => {
  exec(\`invoice-render --order \${req.params.id}\`, (error, stdout) => {
    if (error) return res.status(500).json({ error: 'render failed' });
    res.type('text/plain').send(stdout);
  });
});
router.get('/reports/download', (req, res) => {
  fs.readFile(path.join(REPORT_DIR, req.query.name), (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});
module.exports = router;
`;
const REPAIRED = VULNERABLE
  .replace(`"SELECT id FROM orders WHERE id = '" + req.params.id + "'"`, `'SELECT id FROM orders WHERE id = $1', [req.params.id]`)
  .replace('exec(`invoice-render --order ${req.params.id}`, ', "execFile('invoice-render', ['--order', req.params.id], ")
  .replace(
    'fs.readFile(path.join(REPORT_DIR, req.query.name), ',
    `const base = path.resolve(REPORT_DIR);
  const target = path.resolve(base, String(req.query.name));
  if (target !== base && !target.startsWith(base + path.sep)) return res.status(400).json({ error: 'invalid report name' });
  fs.readFile(target, `,
  );
write('services/orders.js', VULNERABLE);
write('services/orders-fixed.js', REPAIRED);
write('services/app.js', `const express = require('express');
const { Pool } = require('pg');
const { execSync, execFile, spawn } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const axios = require('axios');
const app = express();
const pool = new Pool();
app.use(express.json());
app.set('trust proxy', 1);
const guard = (req, res, next) => { req.seen = ['guard']; next(); };
app.get('/users/:id/posts/:post', guard, (req, res) => res.status(201).set('x-seen', req.seen.join()).json({ params: req.params, query: req.query, body: req.body, auth: req.get('Authorization') }));
app.post('/callback', (req, res) => pool.query('SELECT $1::text AS v', [req.body.v], (error, result) => res.send(result.rows)));
app.get('/client', async (req, res) => { const client = await pool.connect(); const result = await client.query({ text: 'SELECT 1', values: [7] }); client.release(); res.json(result); });
app.get('/boom', () => { throw new Error('handler exploded'); });
app.get('/next-error', (req, res, next) => next(new Error('passed to next')));
app.get('/never', () => {});
app.get('/redirect', (req, res) => res.redirect('/elsewhere'));
app.get('/stream', (req, res) => fs.createReadStream('/var/data/report.pdf').pipe(res));
app.get('/sync', (req, res) => res.send(execSync('uname -a').toString()));
app.get('/promised', async (req, res) => { const { stdout } = await promisify(execFile)('ls', ['-1', req.query.dir]); res.send(stdout); });
app.get('/spawn', (req, res) => { const child = spawn('tar', ['-czf', 'x.tgz'], { shell: false }); let out = ''; child.stdout.on('data', (chunk) => { out += chunk; }); child.on('close', (code) => res.json({ code, out })); });
app.get('/readsync', (req, res) => res.send(fs.readFileSync('/etc/app.conf', 'utf8')));
app.get('/exists', (req, res) => res.json({ exists: fs.existsSync('/tmp/missing'), real: typeof fs.statSync }));
app.get('/axios', async (req, res) => res.json(await axios.get('https://example.test')));
app.listen(3000, () => {});
module.exports = app;
`);

const h = require(pathReal.join(root, '.mitig8it', 'harness.js'));

test('express routes are recorded and invoke matches concrete URLs and route patterns', async () => {
  const app = h.load('services/app.js', { stubs: { axios: { get: async () => ({ ok: true }) } } });
  assert.equal(app, h.app);
  assert.ok(h.express.routes.some((route) => route.method === 'get' && route.path === '/users/:id/posts/:post'));
  const byUrl = await h.invoke(app, 'GET', '/users/42/posts/7', { query: { q: 'x' }, body: { b: 1 }, headers: { Authorization: 'Bearer t' } });
  assert.equal(byUrl.status, 201);
  assert.deepEqual(byUrl.body, { params: { id: '42', post: '7' }, query: { q: 'x' }, body: { b: 1 }, auth: 'Bearer t' });
  assert.equal(byUrl.headers['x-seen'], 'guard');
  assert.equal(byUrl.headers['content-type'], 'application/json');
  const byPattern = await h.invoke(app, 'get', '/users/:id/posts/:post', { params: { id: 'a', post: 'b' } });
  assert.deepEqual(byPattern.body.params, { id: 'a', post: 'b' });
  const redirect = await h.invoke(app, 'get', '/redirect');
  assert.equal(redirect.status, 302);
  assert.equal(redirect.redirect, '/elsewhere');
  assert.throws(() => h.invoke(app, 'delete', '/users/1/posts/2'), /no delete handler recorded for \/users\/1\/posts\/2/);
});

test('handler errors propagate as rejections and a silent handler times out', async () => {
  const app = h.load('services/app.js', { stubs: { axios: {} } });
  await assert.rejects(h.invoke(app, 'get', '/boom'), /handler exploded/);
  await assert.rejects(h.invoke(app, 'get', '/next-error'), /passed to next/);
  await assert.rejects(h.invoke(app, 'get', '/never', { timeout: 30 }), /never ended the response/);
  await assert.rejects(h.invoke(app, 'get', '/axios'), /not a function/);
});

test('pg records query text and values across the promise, callback, config, and client forms', async () => {
  const app = h.load('services/app.js', { stubs: { axios: {} }, pg: { rows: [{ v: 'row' }] } });
  const callback = await h.invoke(app, 'post', '/callback', { body: { v: 'val' } });
  assert.deepEqual(callback.body, [{ v: 'row' }]);
  assert.deepEqual(h.pg.queries[0], { text: 'SELECT $1::text AS v', values: ['val'] });
  const client = await h.invoke(app, 'get', '/client');
  assert.deepEqual(h.pg.queries[1], { text: 'SELECT 1', values: [7] });
  assert.equal(client.body.rowCount, 1);
  h.load('services/app.js', { stubs: { axios: {} }, pg: { result: (query) => ({ rows: [query.text] }) } });
  const custom = await h.invoke(h.app, 'get', '/client');
  assert.deepEqual(custom.body.rows, ['SELECT 1']);
  assert.equal(h.pg.queries.length, 1, 'load resets the recorders');
});

test('db() hands a proof a recording connection without requiring pg', async () => {
  // A generated proof for a helper that takes a connection cannot `require('pg')`: nothing is
  // installed in the sandbox and patch policy refuses a test that asks for a package. h.db() is
  // the only way it reaches one, so it has to record onto the same h.pg.queries the assertions read.
  write('services/lookup.js', 'function loadUser(db, id) {\n  return db.query("SELECT * FROM users WHERE id = $1", [id]);\n}\nmodule.exports = { loadUser };\n');
  const m = h.load('services/lookup.js');
  const db = h.db();
  assert.equal(typeof db.query, 'function', 'h.db() hands back something with a query method');
  const called = h.call(m.loadUser, db, "1' OR '1'='1");
  await Promise.resolve(called.value).catch(() => {});
  assert.equal(h.pg.queries.length, 1, 'the call was recorded on h.pg.queries');
  assert.deepEqual(h.pg.queries[0], { text: 'SELECT * FROM users WHERE id = $1', values: ["1' OR '1'='1"] });
  // A fresh load clears what the previous one recorded, so one proof cannot see another's calls.
  h.load('services/lookup.js');
  assert.equal(h.pg.queries.length, 0);
});

test('child_process records exec, execFile, spawn, and sync calls and feeds configured stdout', async () => {
  const router = h.load('services/orders.js', { child_process: { stdout: 'rendered' } });
  const rendered = await h.invoke(router, 'post', '/orders/:id/invoice', { params: { id: '7; rm -rf /' } });
  assert.equal(rendered.body, 'rendered');
  assert.equal(rendered.headers['content-type'], 'text/plain');
  assert.deepEqual(h.child_process.calls[0], { fn: 'exec', command: 'invoice-render --order 7; rm -rf /', args: null, options: {}, shell: 'invoice-render --order 7; rm -rf /' });
  const app = h.load('services/app.js', { stubs: { axios: {} }, child_process: { stdout: 'out' } });
  assert.equal((await h.invoke(app, 'get', '/sync')).body, 'out');
  assert.equal((await h.invoke(app, 'get', '/promised', { query: { dir: '/x' } })).body, 'out');
  assert.deepEqual((await h.invoke(app, 'get', '/spawn')).body, { code: 0, out: 'out' });
  assert.deepEqual(h.child_process.calls.map((call) => [call.fn, call.command, call.args]), [
    ['execSync', 'uname -a', null],
    ['execFile', 'ls', ['-1', '/x']],
    ['spawn', 'tar', ['-czf', 'x.tgz']],
  ]);
  assert.equal(h.child_process.calls[2].options.shell, false);
  assert.deepEqual(h.child_process.calls.map((call) => call.shell), ['uname -a', null, null]);
  h.load('services/app.js', { stubs: { axios: {} }, child_process: { error: new Error('spawn failed') } });
  await assert.rejects(h.invoke(h.app, 'get', '/promised', { query: { dir: '/x' } }), /spawn failed/);
});

test('fs overrides record paths and return configured content while other fs functions stay real', async () => {
  const router = h.load('services/orders.js', { fs: { content: 'PDF' } });
  const download = await h.invoke(router, 'get', '/reports/download', { query: { name: '../../etc/passwd' } });
  assert.equal(download.status, 200);
  assert.equal(download.body.toString(), 'PDF');
  assert.equal(h.fs.reads.length, 1);
  assert.ok(h.fs.reads[0].path.endsWith(pathReal.join('etc', 'passwd')));
  assert.equal(h.fs.reads[0].resolved, pathReal.resolve(h.fs.reads[0].path), 'resolved is the absolute form');
  assert.equal(String(h.fs.reads[0]), h.fs.reads[0].path, 'String(read) is the raw path');
  assert.throws(() => h.assert.inside(h.fs.reads[0], pathReal.join(h.root, 'reports')), /stay under/);
  assert.throws(() => h.assert.inside(h.fs.reads[0].path, pathReal.join(h.root, 'reports')), /stay under/);
  assert.throws(() => h.assert.inside(pathReal.join(h.root, 'reports'), h.fs.reads[0]), /stay under/, 'an entry is recognized in either position');
  const missing = await h.invoke(h.load('services/orders.js', { fs: { exists: false } }), 'get', '/reports/download', { query: { name: 'a.pdf' } });
  assert.equal(missing.status, 404);
  const app = h.load('services/app.js', { stubs: { axios: {} }, fs: { content: (file) => `content of ${file}` } });
  assert.equal((await h.invoke(app, 'get', '/readsync')).body, 'content of /etc/app.conf');
  assert.equal((await h.invoke(app, 'get', '/stream')).body, 'content of /var/data/report.pdf');
  assert.deepEqual((await h.invoke(app, 'get', '/exists')).body, { exists: true, real: 'function' });
  assert.deepEqual(h.fs.reads.map((read) => read.path), ['/etc/app.conf', '/var/data/report.pdf', '/tmp/missing']);
  assert.deepEqual(h.fs.reads.map((read) => read.resolved), ['/etc/app.conf', '/var/data/report.pdf', '/tmp/missing']);
  assert.equal(realFs.readFileSync(pathReal.join(root, 'services', 'app.js'), 'utf8').length > 0, true, 'the real fs is untouched');
});

test('relative load paths resolve from the test file and repository paths from the root', () => {
  write('.mitig8it/regression/relative.test.js', `const h = require('../harness');
const a = h.load('services/orders.js');
const b = h.load('../../services/orders.js');
process.stdout.write(String(typeof a.get === 'function' && a === b));
`);
  const result = cp.spawnSync(process.execPath, [pathReal.join('.mitig8it', 'regression', 'relative.test.js')], { cwd: root, encoding: 'utf8' });
  assert.equal(result.stdout, 'true', result.stderr);
});

test('every way of turning a string into code is recorded and none of it runs', () => {
  // The module tries each interpreter with a payload that would end the process if it ran, so a
  // recorder that forgot to stub one is the difference between a passing run and no run at all.
  write('services/interpreters.js', `const vm = require('node:vm');
const KILL = "process.exit(3)";
function viaEval(source) { return eval(source); }
function viaFunction(source) { return new Function('row', 'return ' + source + ';'); }
function viaVm(source) { return [vm.runInNewContext(source), vm.runInThisContext(source)]; }
function viaTimer(source) { setTimeout(source, 0); setInterval(source, 0); }
function viaTimerFunction() { let ran = false; setTimeout(() => { ran = true; }, 0); return ran; }
module.exports = { KILL, viaEval, viaFunction, viaVm, viaTimer, viaTimerFunction };
`);
  write('.mitig8it/regression/code.test.js', `const h = require('../harness');
const m = h.load('services/interpreters.js');
h.assert.noCode('nothing has been compiled yet');
m.viaEval(m.KILL);
h.assert.equal(typeof m.viaFunction(m.KILL), 'function', 'new Function must still hand back something callable');
m.viaVm(m.KILL);
m.viaTimer(m.KILL);
h.assert.equal(h.code.calls.length, 6);
h.assert.equal(h.code.calls.map((c) => c.kind).join(','), 'eval,Function,vm.runInNewContext,vm.runInThisContext,setTimeout,setInterval');
for (const entry of h.code.calls) h.assert.includes(entry.source, m.KILL);
// A function handler is a real timer, not a string of code, so it is left alone.
h.assert.equal(m.viaTimerFunction(), false);
h.assert.equal(h.code.calls.length, 6);
// call() reports a throw instead of raising, so one test can send a payload and a document.
const bad = h.call(() => { throw new Error('rejected'); });
h.assert.equal(bad.ok, false);
h.assert.equal(bad.error.message, 'rejected');
h.assert.equal(h.call((text) => JSON.parse(text), '[1, 2]').value.length, 2);
let failed = null;
try { h.assert.noCode(); } catch (error) { failed = error; }
h.assert(failed && failed.name === 'HarnessAssertion', 'noCode must fail once a string has been compiled');
h.assert.includes(String(failed.message), 'process.exit(3)');
process.stdout.write('recorded');
`);
  const result = cp.spawnSync(process.execPath, [pathReal.join('.mitig8it', 'regression', 'code.test.js')], { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'recorded', result.stderr);
});

test('assert helpers throw HarnessAssertion with the given message', () => {
  assert.throws(() => h.assert(false, 'plain'), { name: 'HarnessAssertion', message: 'plain' });
  assert.throws(() => h.assert.equal(1, 2, 'eq'), /eq: \{ actual: 1, expected: 2 \}/);
  assert.throws(() => h.assert.includes('abc', 'z', 'inc'), /inc/);
  assert.throws(() => h.assert.notIncludes('abc', 'b', 'ninc'), /ninc/);
  h.assert.inside('/base/sub/file', '/base');
  h.assert.inside({ path: 'sub/file', resolved: '/base/sub/file' }, '/base');
  assert.throws(() => h.assert.inside('/base', '/base'), /stay under/);
  assert.throws(() => h.assert.inside('/base/../etc', '/base'), /stay under/);
  assert.throws(() => h.assert.inside({ path: '../etc', resolved: '/etc' }, '/base', 'escaped'), { name: 'HarnessAssertion', message: 'escaped' });
  // The array form checks every read, and { payload } demands that a traversal payload read nothing.
  h.assert.inside([{ path: 'a.pdf', resolved: '/base/a.pdf' }, '/base/b.pdf'], '/base');
  assert.throws(() => h.assert.inside([{ path: 'a.pdf', resolved: '/base/a.pdf' }, '/etc/passwd'], '/base'), /stay under/);
  h.assert.inside([], '/base', { payload: '../../etc/passwd' });
  h.assert.inside([{ path: 'a.pdf', resolved: '/base/a.pdf' }], '/base', { payload: 'a.pdf' });
  for (const payload of ['../../etc/passwd', '..%2f..%2fetc%2fpasswd', '/etc/passwd']) {
    assert.throws(
      () => h.assert.inside([{ path: 'passwd', resolved: '/base/passwd' }], '/base', { payload }),
      /rejected before any filesystem read/,
      `${payload} escapes the base, so a basename-style repair that still reads must fail`,
    );
  }
});

test('invoke percent-decodes query values the way express does', async () => {
  const app = h.load('services/app.js', { stubs: { axios: {} } });
  const out = await h.invoke(app, 'get', '/users/:id/posts/:post', {
    params: { id: '1', post: '2' },
    query: { name: '..%2f..%2fetc%2fpasswd', raw: '100% sure', plain: 'q3.pdf' },
  });
  assert.equal(out.body.query.name, '../../etc/passwd');
  assert.equal(out.body.query.raw, '100% sure', 'a value that is not valid percent-encoding is passed through');
  assert.equal(out.body.query.plain, 'q3.pdf');
});

test('assert.argv accepts an argv call carrying the payload and rejects any shell string', async () => {
  const app = h.load('services/app.js', { stubs: { axios: {} } });
  await h.invoke(app, 'get', '/promised', { query: { dir: 'x; id' } });
  h.assert.argv(h.child_process.calls[0], 'x; id');
  h.assert.argv(h.child_process.calls[0], 'ls', 'the command name is argv[0]');
  assert.throws(() => h.assert.argv(h.child_process.calls[0], 'other'), /expected the injected input "other" to be its own args element of ls/);
  await h.invoke(app, 'get', '/sync');
  assert.throws(() => h.assert.argv(h.child_process.calls[1], 'uname'), /ran through a shell: uname -a/);
  assert.throws(() => h.assert.argv(undefined, 'x'), /no child process call/);
  const shelled = h.load('services/orders.js');
  require('child_process').spawn('tar', ['-czf', 'x'], { shell: true });
  assert.equal(h.child_process.calls[0].shell, 'tar -czf x', 'options.shell makes the argv form a shell string');
  assert.throws(() => h.assert.argv(h.child_process.calls[0], 'x'), /ran through a shell/);
  assert.ok(shelled);
});

test('a family test fails on the vulnerable module and passes on the repaired one under plain node', () => {
  const body = (target) => `const h = require('../harness');
h.run(async () => {
  const app = h.load(${JSON.stringify(target)}, { child_process: { stdout: 'ok' }, fs: { content: 'PDF' } });
  const bad = "1' OR '1'='1";
  await h.invoke(app, 'get', '/orders/:id', { params: { id: bad } });
  const q = h.pg.queries[0];
  h.assert(q, 'no query ran');
  h.assert.notIncludes(q.text, bad, 'input reached the SQL text');
  h.assert.includes(JSON.stringify(q.values || []), bad, 'input must be a bound value');
  await h.invoke(app, 'post', '/orders/:id/invoice', { params: { id: 'x; id' } });
  const call = h.child_process.calls[0];
  h.assert.argv(call, 'x; id', 'input must be its own argument, not shell text');
  const base = require('node:path').join(h.root, 'reports');
  for (const payload of ['../../etc/passwd', '..%2f..%2fetc%2fpasswd']) {
    h.fs.reads.length = 0;
    await h.invoke(app, 'get', '/reports/download', { query: { name: payload } });
    h.assert.inside(h.fs.reads, base, { payload, message: 'read before rejecting ' + payload });
  }
  h.fs.reads.length = 0;
  await h.invoke(app, 'get', '/reports/download', { query: { name: 'q3.pdf' } });
  h.assert.inside(h.fs.reads, base, 'a legitimate report must still be served');
});
`;
  write('.mitig8it/regression/vulnerable.test.js', body('services/orders.js'));
  write('.mitig8it/regression/repaired.test.js', body('services/orders-fixed.js'));
  const run = (name) => cp.spawnSync(process.execPath, [pathReal.join('.mitig8it', 'regression', name)], { cwd: root, encoding: 'utf8' });
  const vulnerable = run('vulnerable.test.js');
  assert.equal(vulnerable.status, 1, vulnerable.stderr);
  assert.match(vulnerable.stderr, /HarnessAssertion: input reached the SQL text/);
  const repaired = run('repaired.test.js');
  assert.equal(repaired.status, 0, repaired.stderr);
  assert.equal(repaired.stdout.trim(), 'harness: ok');
});

// --- TypeScript -------------------------------------------------------------------------------
// The sandbox has no TypeScript toolchain and never gets one: what follows is what plain node
// does with the type stripper the service turns on, over the three shapes the corpus writes.
const TS_FLAGS = ['--experimental-strip-types', '--disable-warning=ExperimentalWarning'];
const runTest = (name) => cp.spawnSync(process.execPath, [...TS_FLAGS, pathReal.join('.mitig8it', 'regression', name)], { cwd: root, encoding: 'utf8' });

write('services/config.ts', `export interface Settings { token: string; retries: number }
export const TOKEN: string = process.env.API_TOKEN as string;
export function settings(retries: number = 1): Settings { return { token: TOKEN, retries }; }
`);
write('services/tokens.ts', `const KEY: string = 'sk-live-not-a-real-key';
type Grant = { key: string };
function grant(): Grant { return { key: KEY }; }
module.exports = { grant, KEY };
`);

test('a TypeScript module with type annotations loads and its types are stripped', () => {
  write('.mitig8it/regression/ts-types.test.js', `const h = require('../harness');
h.run(async () => {
  const m = h.load('services/tokens.ts');
  h.assert.equal(m.grant().key, 'sk-live-not-a-real-key');
  h.assert.notInSource(m, 'type Grant');
});
`);
  // The module ran, so the annotation was stripped; notInSource reads the file back, where the
  // annotation still is, so the test's failure is what proves both halves at once.
  const result = runTest('ts-types.test.js');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /the source still contains "type Grant"/);
  write('.mitig8it/regression/ts-ok.test.js', `const h = require('../harness');
h.run(async () => {
  const m = h.load('services/tokens.ts');
  h.assert.equal(m.grant().key, m.KEY);
});
`);
  const passing = runTest('ts-ok.test.js');
  assert.equal(passing.status, 0, passing.stderr);
  assert.equal(passing.stdout.trim(), 'harness: ok');
});

test('a TypeScript module resolves an interface import written without an extension and as .js', () => {
  // Node resolves neither specifier on its own: `./config` has no extension, and `./config.js`
  // names a file that does not exist, which is how a TypeScript project under NodeNext writes
  // an import of `config.ts`.
  write('services/session.ts', `import type { Settings } from './config';
import { settings } from './config';
import { TOKEN } from './config.js';
export function describe(): string { const s: Settings = settings(2); return s.token + ':' + s.retries + ':' + TOKEN; }
`);
  write('.mitig8it/regression/ts-import.test.js', `const h = require('../harness');
h.run(async () => {
  const m = h.load('services/session', { env: { API_TOKEN: 'from-env' } });
  h.assert.envRead('API_TOKEN');
  h.assert.equal(m.describe(), 'from-env:2:from-env');
});
`);
  const result = runTest('ts-import.test.js');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'harness: ok');
});

test('an interface imported as a value binding is a shape strip-only mode cannot load', () => {
  // Strip-only mode deletes an interface but cannot tell that `Settings` in a mixed import list
  // was one, so the import survives and names an export the stripped module does not have. It is
  // the `isolatedModules` rule TypeScript itself enforces with `verbatimModuleSyntax`. Nothing
  // detects it lexically, so the proof is written anyway and fails honestly rather than passing.
  write('services/mixed.ts', `import { Settings, settings } from './config';
export function retries(): number { const s: Settings = settings(3); return s.retries; }
`);
  write('.mitig8it/regression/ts-mixed.test.js', `const h = require('../harness');
h.run(async () => { h.load('services/mixed.ts'); });
`);
  const result = runTest('ts-mixed.test.js');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /does not provide an export named 'Settings'/);
});

test('an enum is refused by the stripper, naming the syntax it cannot handle', () => {
  write('services/levels.ts', `enum Level { Low, High }
module.exports = { Level };
`);
  write('.mitig8it/regression/ts-enum.test.js', `const h = require('../harness');
h.run(async () => { h.load('services/levels.ts'); });
`);
  const result = runTest('ts-enum.test.js');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX/);
  assert.match(result.stderr, /enum is not supported in strip-only mode/);
});

test('an ES module gets the same fakes a CommonJS module gets, by default and by name', () => {
  // The shape the September 2026 corpus put in front: every juice-shop and electerm route is
  // written with `import`/`export`, and the ES module loader never consults the require hook, so
  // those modules used to receive the real `express` and `pg` and fail to load at all.
  write('services/catalog.ts', `import express from 'express'
import { Pool } from 'pg'
import { readFileSync, existsSync } from 'node:fs'

const pool = new Pool()
export const router = express.Router()
router.get('/items/:id', async (req: any, res: any) => {
  const found = await pool.query("SELECT * FROM items WHERE id = '" + req.params.id + "'")
  res.json({ rows: found.rows, seen: existsSync('items.json'), body: String(readFileSync('items.json')) })
})
`);
  write('.mitig8it/regression/esm-fakes.test.js', `const h = require('../harness');
h.run(async () => {
  const m = h.load('services/catalog.ts', { fs: { content: 'catalog-body' } });
  const out = await h.invoke(m.router, 'get', '/items/:id', { params: { id: '7' } });
  h.assert.equal(h.pg.queries.length, 1, 'the ES module must reach the recording pg fake');
  h.assert.includes(h.pg.queries[0].text, "id = '7'");
  h.assert.equal(String(h.fs.reads[h.fs.reads.length - 1]), 'items.json');
  h.assert.equal(out.body.body, 'catalog-body');
});
`);
  const result = runTest('esm-fakes.test.js');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'harness: ok');
});

test('an ES module importing a stub by name gets the stub, and an unfaked package still fails', () => {
  write('services/report.mjs', `import { render } from 'renderer'
export const line = () => render('x')
`);
  write('.mitig8it/regression/esm-stub.test.js', `const h = require('../harness');
h.run(async () => {
  const m = h.load('services/report.mjs', { stubs: { renderer: { render: (v) => 'rendered:' + v } } });
  h.assert.equal(m.line(), 'rendered:x');
});
`);
  const stubbed = runTest('esm-stub.test.js');
  assert.equal(stubbed.status, 0, stubbed.stderr);

  // Nothing is installed in the sandbox and nothing is auto-stubbed: a package the harness does
  // not fake is still a package the module cannot have, and the proof fails rather than passing
  // against something invented.
  write('services/missing.mjs', `import yaml from 'js-yaml'
export const parse = (text) => yaml.load(text)
`);
  write('.mitig8it/regression/esm-missing.test.js', `const h = require('../harness');
h.run(async () => { h.load('services/missing.mjs'); });
`);
  const missing = runTest('esm-missing.test.js');
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /Cannot find package 'js-yaml'/);
});
