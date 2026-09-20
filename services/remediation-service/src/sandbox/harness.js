'use strict';
// mitig8it regression-test harness v1 (contracts/test-harness-v1.md): Node built-ins only, never part of a repair.
const Module = require('node:module');
const path = require('node:path');
const util = require('node:util');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');
const realFs = require('node:fs');

const ROOT = path.resolve(__dirname, '..');
const state = { express: { routes: [] }, pg: { queries: [] }, child_process: { calls: [] }, fs: { reads: [] } };
let config = {};
let fakes = {};
const later = (fn) => setImmediate(fn);
const isFn = (v) => typeof v === 'function';
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const list = (v) => (Array.isArray(v) ? v : []);
const reset = () => Object.values(state).forEach((s) => Object.values(s).forEach((items) => items.splice(0)));

const app = { locals: {}, listen: () => ({ close() {} }) };
const record = (method, args) => {
  state.express.routes.push({ method, path: typeof args[0] === 'string' ? args[0] : null, handlers: args.filter(isFn) });
  return app;
};
for (const m of ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'all']) app[m] = (...a) => (m === 'get' && a.length === 1 ? undefined : record(m, a));
app.use = (...a) => record('use', a);
for (const n of ['set', 'enable', 'disable', 'param']) app[n] = () => app;
const express = () => app;
express.Router = () => app;
for (const n of ['json', 'urlencoded', 'static']) express[n] = () => (req, res, next) => next && next();

const segs = (v) => String(v).split('?')[0].split('/').filter(Boolean);
function matchRoute(method, target) {
  const parts = segs(target);
  for (const route of state.express.routes) {
    if (route.method === 'use' || (route.method !== 'all' && route.method !== method)) continue;
    if (route.path === null || route.path === target) return { route, params: {} };
    const want = segs(route.path);
    if (want.length !== parts.length) continue;
    const params = {};
    let ok = true;
    for (let i = 0; i < want.length && ok; i += 1) {
      if (want[i].startsWith(':')) params[want[i].slice(1).replace(/\?$/, '')] = decodeURIComponent(parts[i]);
      else if (want[i] !== parts[i]) ok = false;
    }
    if (ok) return { route, params };
  }
  throw new Error(`harness.invoke: no ${method} handler recorded for ${target}`);
}

function invoke(target, method, route, options = {}) {
  const found = matchRoute(String(method).toLowerCase(), route);
  const headers = {};
  for (const [k, v] of Object.entries(options.headers || {})) headers[k.toLowerCase()] = v;
  const req = {
    method: String(method).toUpperCase(), path: route, url: route, app, headers, get: (n) => headers[String(n).toLowerCase()],
    params: { ...found.params, ...(options.params || {}) }, query: options.query || {}, body: options.body === undefined ? {} : options.body,
  };
  req.header = req.get;
  const out = { status: 200, body: undefined, headers: {}, redirect: null };
  return new Promise((resolve, reject) => {
    let done = false;
    const settle = (error) => { if (done) return; done = true; clearTimeout(timer); if (error) reject(error instanceof Error ? error : new Error(String(error))); else resolve(out); };
    const timer = setTimeout(() => settle(new Error(`harness.invoke: the ${req.method} ${route} handler never ended the response`)), options.timeout || 2000);
    const end = (body) => { if (body !== undefined) out.body = body; later(() => settle()); return res; };
    const base = Object.assign(new EventEmitter(), {
      locals: {}, statusCode: 200, send: end, end, write(chunk) { out.body = (out.body || '') + chunk; return true; },
      status(code) { out.status = base.statusCode = Number(code); return res; },
      sendStatus(code) { out.status = Number(code); return end(String(code)); },
      json(body) { out.headers['content-type'] = 'application/json'; return end(body); },
      type(v) { out.headers['content-type'] = String(v); return res; },
      set(n, v) { for (const [k, x] of Object.entries(typeof n === 'object' ? n : { [n]: v })) out.headers[k.toLowerCase()] = x; return res; },
      redirect(a, b) { out.redirect = out.headers.location = b === undefined ? a : b; out.status = b === undefined ? 302 : Number(a); return end(''); },
    });
    base.header = base.setHeader = base.set;
    base.contentType = base.type;
    // Other response methods (cookie, vary, sendFile, ...) are chainable no-ops.
    const res = new Proxy(base, { get: (t, k) => (k in t ? t[k] : k === 'then' || typeof k === 'symbol' ? undefined : () => res) });
    const chain = found.route.handlers.filter((h) => h !== app);
    let index = 0;
    const next = (error) => {
      if (error) return settle(error);
      const handler = chain[index++];
      if (!handler) return settle(new Error(`harness.invoke: ${route} called next() without ending the response`));
      try {
        const result = handler.length >= 4 ? handler(null, req, res, next) : handler(req, res, next);
        if (result && isFn(result.then)) result.then(undefined, settle);
      } catch (error) { settle(error); }
      return undefined;
    };
    next();
  });
}

function query(...args) {
  let text = args[0];
  let values;
  let cb = null;
  if (text && typeof text === 'object') { values = text.values; text = text.text; }
  for (const item of args.slice(1)) { if (Array.isArray(item)) values = item; else if (isFn(item)) cb = item; }
  const entry = { text: String(text), values };
  state.pg.queries.push(entry);
  const pgc = obj(config.pg);
  const result = { rows: pgc.rows || [], ...obj(isFn(pgc.result) ? pgc.result(entry) : pgc.result) };
  if (result.rowCount === undefined) result.rowCount = result.rows.length;
  if (cb) { later(() => cb(null, result)); return undefined; }
  return Promise.resolve(result);
}
class Client {
  constructor(options) { this.options = options; }
  connect(cb) { if (cb) later(() => cb(null, this, () => {})); return Promise.resolve(this); }
  query(...args) { return query(...args); }
  release() {}
}
class Pool extends Client {}
const pg = { Pool, Client, query };

const outcome = (command) => { const c = obj(config.child_process); const p = isFn(c.result) ? obj(c.result(command)) : c; return { stdout: p.stdout ?? '', stderr: p.stderr || '', error: p.error || null, code: p.code || 0 }; };
// `shell` is the command line a shell would interpret: the whole string for exec/execSync, or
// command plus args when options.shell is set; null when the child ran with an argv array.
const recordCall = (fn, command, args, options) => { const o = obj(options); const viaShell = args == null || Boolean(o.shell); state.child_process.calls.push({ fn, command: String(command), args: args == null ? null : args, options: o, shell: viaShell ? [command, ...list(args)].map(String).join(' ') : null }); };
function child(command, cb) {
  const o = outcome(command);
  const proc = Object.assign(new EventEmitter(), { stdout: new EventEmitter(), stderr: new EventEmitter(), kill: () => true });
  later(() => {
    if (cb) cb(o.error, o.stdout, o.stderr);
    if (o.stdout) proc.stdout.emit('data', Buffer.from(String(o.stdout)));
    if (o.stderr) proc.stderr.emit('data', Buffer.from(String(o.stderr)));
    if (o.error && proc.listenerCount('error')) proc.emit('error', o.error);
    proc.stdout.emit('end');
    proc.emit('close', o.code, null);
  });
  return proc;
}
const exec = (command, ...rest) => (recordCall('exec', command, null, rest[0]), child(command, rest.find(isFn)));
const execFile = (file, ...rest) => { const args = Array.isArray(rest[0]) ? rest.shift() : []; recordCall('execFile', file, args, rest[0]); return child(file, rest.find(isFn)); };
const spawn = (command, ...rest) => { const args = Array.isArray(rest[0]) ? rest.shift() : []; recordCall('spawn', command, args, rest[0]); return child(command); };
const sync = (fn, command, args, options) => { recordCall(fn, command, args, options); const o = outcome(command); if (o.error && fn !== 'spawnSync') throw o.error; return o; };
for (const fn of [exec, execFile]) fn[util.promisify.custom] = (command, ...rest) => { fn(command, ...rest); const o = outcome(command); return o.error ? Promise.reject(o.error) : Promise.resolve({ stdout: o.stdout, stderr: o.stderr }); };
const child_process = {
  exec, execFile, spawn,
  execSync: (command, options) => sync('execSync', command, null, options).stdout,
  execFileSync: (file, args, options) => sync('execFileSync', file, list(args), options).stdout,
  spawnSync: (command, args, options) => { const o = sync('spawnSync', command, list(args), options); return { ...o, status: o.code }; },
};

const content = (file) => { const c = obj(config.fs); return (isFn(c.content) ? c.content(String(file)) : c.content) ?? ''; };
const exists = (file) => { const c = obj(config.fs); return isFn(c.exists) ? c.exists(String(file)) : c.exists !== false; };
const enoent = (file) => Object.assign(new Error(`ENOENT: no such file or directory, open '${file}'`), { code: 'ENOENT' });
const encode = (v, options) => { const enc = typeof options === 'string' ? options : options && options.encoding; const raw = Buffer.isBuffer(v) ? v : Buffer.from(String(v)); return enc ? raw.toString(enc) : raw; };
// Each read is { path, resolved }: the string the module passed and its absolute form; String(read) is the raw path.
const seen = (file) => { const raw = String(file); state.fs.reads.push(Object.defineProperty({ path: raw, resolved: path.resolve(raw) }, 'toString', { value: () => raw })); };
const fs = Object.create(realFs);
fs.readFile = (file, ...rest) => { seen(file); const cb = rest.find(isFn); const o = isFn(rest[0]) ? undefined : rest[0]; if (cb) later(() => (exists(file) ? cb(null, encode(content(file), o)) : cb(enoent(file)))); };
fs.readFileSync = (file, options) => { seen(file); if (!exists(file)) throw enoent(file); return encode(content(file), options); };
fs.existsSync = (file) => (seen(file), exists(file));
fs.createReadStream = (file) => (seen(file), Readable.from([encode(content(file))]));
Object.defineProperty(fs, 'promises', { value: Object.create(realFs.promises) });
fs.promises.readFile = (file, options) => (seen(file), exists(file) ? Promise.resolve(encode(content(file), options)) : Promise.reject(enoent(file)));

const builtinFakes = { express, pg, child_process, fs, 'fs/promises': fs.promises };
const originalLoad = Module._load;
Module._load = function load(request, parent, isMain) {
  const name = String(request).replace(/^node:/, '');
  return Object.prototype.hasOwnProperty.call(fakes, name) ? fakes[name] : originalLoad.call(this, request, parent, isMain);
};

function load(target, options = {}) {
  config = obj(options);
  reset();
  fakes = { ...builtinFakes, ...obj(config.stubs) };
  for (const name of list(config.real)) delete fakes[name];
  const from = target.startsWith('.') ? path.dirname(require.main ? require.main.filename : __filename) : ROOT;
  const resolved = require.resolve(path.resolve(from, target));
  delete require.cache[resolved];
  return require(resolved);
}

const fail = (message, detail) => { throw Object.assign(new Error(detail === undefined ? message : `${message}: ${util.inspect(detail)}`), { name: 'HarnessAssertion' }); };
function assert(condition, message) { if (!condition) fail(message || 'assertion failed'); }
assert.equal = (actual, expected, message) => { if (actual !== expected) fail(message || 'values differ', { actual, expected }); };
assert.includes = (haystack, needle, message) => { if (!String(haystack).includes(needle)) fail(message || `expected text to include ${JSON.stringify(needle)}`, haystack); };
assert.notIncludes = (haystack, needle, message) => { if (String(haystack).includes(needle)) fail(message || `expected text not to include ${JSON.stringify(needle)}`, haystack); };
const isRead = (v) => Boolean(v) && typeof v === 'object' && typeof v.resolved === 'string';
// inside(read, baseDir): `read` is an h.fs.reads entry or a path string; the entry may come in either position.
assert.inside = (target, base, message) => { if (isRead(base) && !isRead(target)) [target, base] = [base, target]; const rel = path.relative(path.resolve(String(base)), isRead(target) ? target.resolved : path.resolve(String(target))); if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) fail(message || `expected ${String(target)} to stay under ${String(base)}`); };
// argv(call, payload): the child ran with an argv array (no shell string) and the injected payload is its own element (the command name itself is argv[0]).
assert.argv = (call, payload, message) => { if (!call) fail(message || 'no child process call was recorded'); if (typeof call.shell === 'string') fail(message || `command ran through a shell: ${call.shell}`); const want = String(payload); if (want !== call.command && !(Array.isArray(call.args) && call.args.some((a) => String(a) === want))) fail(message || `expected the injected input ${JSON.stringify(payload)} to be its own args element of ${call.command}`, call.args); };

// Runs one test body: exit 0 when it resolves, exit 1 with the error otherwise.
const run = (body) => Promise.resolve().then(body).then(
  () => { process.stdout.write('harness: ok\n'); process.exit(0); },
  (error) => { process.stderr.write(`harness: ${(error && error.stack) || error}\n`); process.exit(1); },
);

module.exports = { version: 1, root: ROOT, load, invoke, run, assert, reset, express: state.express, pg: state.pg, child_process: state.child_process, fs: state.fs, app };
