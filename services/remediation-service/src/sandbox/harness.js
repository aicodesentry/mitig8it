'use strict';
// mitig8it regression-test harness v1 (contracts/test-harness-v1.md): Node built-ins only, never part of a repair.
const Module = require('node:module');
const path = require('node:path');
const util = require('node:util');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');
const realFs = require('node:fs');

const ROOT = path.resolve(__dirname, '..');

// TypeScript modules run through Node's own type stripper (Node 22.6 and later), which deletes
// type-only syntax and refuses enums, namespaces, and parameter properties. Stripping is what
// compiles the file; what Node still does not do is find it. Its resolver never tries a `.ts`
// suffix, so an extension-less relative import and the `.js` specifier a TypeScript project
// writes for a `.ts` source both fail to resolve. Both are resolved here instead, for the
// module a test loads and for every relative import that module makes.
const TS_SUFFIXES = ['.ts', '.mts', '.cts'];
const isFile = (target) => { try { return realFs.statSync(target).isFile(); } catch { return false; } };
const withSuffix = (base) => TS_SUFFIXES.map((suffix) => base + suffix).find(isFile) || null;
// The `.ts` source an absolute specifier names, or null when none exists: the file itself, the
// TypeScript source a `.js`/`.cjs`/`.mjs` specifier stands for, an extension-less path, or a
// directory's `index.ts`.
function tsSource(absolute) {
  const written = /\.([cm]?)js$/.exec(absolute);
  if (written) {
    const base = absolute.slice(0, -written[0].length);
    return (isFile(`${base}.${written[1]}ts`) ? `${base}.${written[1]}ts` : null) || withSuffix(base) || withSuffix(absolute);
  }
  return withSuffix(absolute) || withSuffix(path.join(absolute, 'index'));
}
const isRelative = (request) => request.startsWith('.') || path.isAbsolute(request);
const state = { express: { routes: [] }, pg: { queries: [] }, child_process: { calls: [] }, fs: { reads: [] }, env: { reads: [] }, code: { calls: [] } };
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

// Express hands the route a percent-decoded query string, so the fake decodes it too; a value that
// is not valid percent-encoding is passed through unchanged.
const decodeMaybe = (v) => { const s = String(v); if (!s.includes('%')) return s; try { return decodeURIComponent(s); } catch { return s; } };
const decodeQuery = (query) => {
  const out = {};
  for (const [k, v] of Object.entries(obj(query))) out[k] = typeof v === 'string' ? decodeMaybe(v) : Array.isArray(v) ? v.map((x) => (typeof x === 'string' ? decodeMaybe(x) : x)) : v;
  return out;
};
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
    params: { ...found.params, ...(options.params || {}) }, query: decodeQuery(options.query), body: options.body === undefined ? {} : options.body,
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
// db(): a recording pg client, for a proof that calls an exported function taking a connection
// instead of driving a route. Nothing is installed in the sandbox and the patch policy refuses a
// test that requires a package, so a generated test cannot reach `new Pool()` any other way.
const db = () => new Pool();

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

// Every way a module can turn a string into running code is recorded and none of them runs. A
// code_injection_eval repair is proven by the payload never being compiled, so an interpreter
// that still ran it would prove the opposite of what the test claims. `eval`, `Function`, and a
// string timer are resolved through the global scope chain, so replacing the global binding is
// what the module under test sees; `vm` is a fake module like the others. Each entry is
// { kind, source }: the call that would have compiled, and the text it was given.
const recordCode = (kind, source) => { state.code.calls.push({ kind, source: String(source) }); };
const noop = function compiledByHarness() {};
global.eval = (source) => { recordCode('eval', source); };
const RealFunction = global.Function;
const FakeFunction = function Function(...args) { recordCode('Function', args.length ? args[args.length - 1] : ''); return noop; };
FakeFunction.prototype = RealFunction.prototype;
global.Function = FakeFunction;
const realTimer = { setTimeout: global.setTimeout, setInterval: global.setInterval };
for (const name of ['setTimeout', 'setInterval']) {
  global[name] = (handler, ...rest) => (typeof handler === 'string' ? recordCode(name, handler) : realTimer[name](handler, ...rest));
}
const vm = {
  runInNewContext: (code) => { recordCode('vm.runInNewContext', code); },
  runInThisContext: (code) => { recordCode('vm.runInThisContext', code); },
  runInContext: (code) => { recordCode('vm.runInContext', code); },
  compileFunction: (code) => (recordCode('vm.compileFunction', code), noop),
  createContext: (sandbox) => obj(sandbox),
  Script: class Script { constructor(code) { recordCode('vm.Script', code); } runInNewContext() {} runInThisContext() {} runInContext() {} },
};

const builtinFakes = { express, pg, child_process, fs, 'fs/promises': fs.promises, vm };
const originalLoad = Module._load;
Module._load = function load(request, parent, isMain) {
  const written = String(request);
  const name = written.replace(/^node:/, '');
  if (Object.prototype.hasOwnProperty.call(fakes, name)) return fakes[name];
  try {
    return originalLoad.call(this, request, parent, isMain);
  } catch (error) {
    // Only a relative or absolute specifier Node could not find is retried as TypeScript: a
    // missing package is still a missing package, and the patch policy refuses a test that asks
    // for one.
    if (error.code !== 'MODULE_NOT_FOUND' || !isRelative(written)) throw error;
    const from = parent && parent.filename ? path.dirname(parent.filename) : ROOT;
    const found = tsSource(path.resolve(from, written));
    if (!found) throw error;
    return originalLoad.call(this, found, parent, isMain);
  }
};
// A TypeScript module written with `import`/`export` is loaded by the ES module loader, which
// never consults `Module._load`, so its imports are resolved through the synchronous hooks Node
// 22.15 and later expose. The hook only redirects a relative specifier to the `.ts` source it
// names; everything else falls through to the real resolver.
if (typeof Module.registerHooks === 'function') {
  Module.registerHooks({
    resolve(specifier, context, nextResolve) {
      if (isRelative(String(specifier))) {
        let from = ROOT;
        try { from = path.dirname(new URL(context.parentURL).pathname); } catch { from = ROOT; }
        const found = tsSource(path.resolve(from, String(specifier)));
        if (found) return { url: new URL(`file://${found}`).href, shortCircuit: true };
      }
      return nextResolve(specifier, context);
    },
  });
}

// process.env is replaced once, by a proxy that records every name the module under test reads:
// a hardcoded-credential repair is proven by the read happening at all, so the read has to be
// observable. Values from load(..., { env }) sit over the real environment and are cleared by the
// next load, so one test cannot leak a secret into the next. `loadedFile` is the file the last
// load() ran, so assert.notInSource can read it back.
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const supplied = {};
let loadedFile = null;
Object.defineProperty(process, 'env', { configurable: true, writable: true, value: new Proxy(process.env, {
  get: (t, k) => (typeof k === 'string' && state.env.reads.push(k) && has(supplied, k) ? supplied[k] : t[k]),
  has: (t, k) => (typeof k === 'string' && state.env.reads.push(k), has(supplied, k) || k in t),
  ownKeys: (t) => [...new Set([...Reflect.ownKeys(t), ...Object.keys(supplied)])],
  getOwnPropertyDescriptor: (t, k) => (has(supplied, k)
    ? { value: supplied[k], writable: true, enumerable: true, configurable: true }
    : Reflect.getOwnPropertyDescriptor(t, k)),
}) });

// `process.argv` as the test process was started, so a load that did not supply one restores it.
const realArgv = process.argv.slice();

function load(target, options = {}) {
  config = obj(options);
  reset();
  // A module at module scope may read its input from the command line, which is the only way a
  // test can set it: the sink runs on import, before anything else can be called.
  process.argv = list(config.argv).length ? list(config.argv).map(String) : realArgv.slice();
  for (const name of Object.keys(supplied)) delete supplied[name];
  for (const [name, value] of Object.entries(obj(config.env))) supplied[name] = String(value);
  fakes = { ...builtinFakes, ...obj(config.stubs) };
  for (const name of list(config.real)) delete fakes[name];
  const from = target.startsWith('.') ? path.dirname(require.main ? require.main.filename : __filename) : ROOT;
  const absolute = path.resolve(from, target);
  let resolved;
  try {
    resolved = require.resolve(absolute);
  } catch (error) {
    resolved = tsSource(absolute);
    if (!resolved) throw error;
  }
  delete require.cache[resolved];
  loadedFile = resolved;
  return require(resolved);
}

const fail = (message, detail) => { throw Object.assign(new Error(detail === undefined ? message : `${message}: ${util.inspect(detail)}`), { name: 'HarnessAssertion' }); };
function assert(condition, message) { if (!condition) fail(message || 'assertion failed'); }
assert.equal = (actual, expected, message) => { if (actual !== expected) fail(message || 'values differ', { actual, expected }); };
assert.includes = (haystack, needle, message) => { if (!String(haystack).includes(needle)) fail(message || `expected text to include ${JSON.stringify(needle)}`, haystack); };
assert.notIncludes = (haystack, needle, message) => { if (String(haystack).includes(needle)) fail(message || `expected text not to include ${JSON.stringify(needle)}`, haystack); };
const isRead = (v) => Boolean(v) && typeof v === 'object' && typeof v.resolved === 'string';
// A payload that tries to leave the base directory: a `..` segment or an absolute path, either as
// sent or once percent-decoded the way Express decodes a query string.
const escapesBase = (payload) => [String(payload), decodeMaybe(payload)].some((v) => v.split(/[\\/]/).includes('..') || path.isAbsolute(v));
// inside(read, baseDir[, message | { payload, message }]): `read` is an h.fs.reads entry, a path
// string, or the whole h.fs.reads array (an entry or the array is recognized in either position).
// Every read's resolved path must stay strictly under the base directory, and when `payload` names
// the input that produced those reads and that payload escapes the base, the handler must have
// rejected it before touching the filesystem, so no read may have been recorded at all.
assert.inside = (target, base, options) => {
  if ((isRead(base) || Array.isArray(base)) && !isRead(target) && !Array.isArray(target)) [target, base] = [base, target];
  const o = options === undefined || typeof options === 'string' ? { message: options } : obj(options);
  const reads = (Array.isArray(target) ? target : [target]).filter((v) => v !== undefined && v !== null);
  const root = path.resolve(String(base));
  if (o.payload !== undefined && escapesBase(o.payload) && reads.length) {
    fail(o.message || `expected ${JSON.stringify(String(o.payload))} to be rejected before any filesystem read`, reads.map(String));
  }
  for (const read of reads) {
    const rel = path.relative(root, isRead(read) ? read.resolved : path.resolve(String(read)));
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) fail(o.message || `expected ${String(read)} to stay under ${String(base)}`);
  }
};
// envRead(name): the module read process.env.<name> at least once. A module that still carries the
// literal never reads it, which is what makes this fail before a repair and pass after one.
assert.envRead = (name, message) => { if (!state.env.reads.includes(String(name))) fail(message || `expected the module to read process.env.${String(name)}`, state.env.reads); };
// notInSource(target, literal): the loaded module's file no longer carries the literal, and no
// string it exports does. `target` is the module load() returned, or a path.
assert.notInSource = (target, literal, message) => {
  const file = typeof target === 'string' ? path.resolve(target) : loadedFile;
  if (!file) fail(message || 'no module has been loaded, so there is no source to check');
  const want = String(literal);
  if (realFs.readFileSync(file, 'utf8').includes(want)) fail(message || `the source still contains ${JSON.stringify(want)}`);
  for (const [key, value] of Object.entries(obj(typeof target === 'string' ? {} : target))) {
    if (typeof value === 'string' && value.includes(want)) fail(message || `exported value ${key} still carries ${JSON.stringify(want)}`);
  }
};
// argv(call, payload): the child ran with an argv array (no shell string) and the injected payload is its own element (the command name itself is argv[0]).
assert.argv = (call, payload, message) => { if (!call) fail(message || 'no child process call was recorded'); if (typeof call.shell === 'string') fail(message || `command ran through a shell: ${call.shell}`); const want = String(payload); if (want !== call.command && !(Array.isArray(call.args) && call.args.some((a) => String(a) === want))) fail(message || `expected the injected input ${JSON.stringify(payload)} to be its own args element of ${call.command}`, call.args); };

// noCode(message): nothing the module did turned a string into code. It is the whole proof of a
// code_injection_eval repair, so it names what would have been compiled when it fails.
assert.noCode = (message) => { if (state.code.calls.length) fail(message || 'expected no string to be compiled or evaluated', state.code.calls.map((c) => `${c.kind}: ${c.source}`)); };
// call(fn, ...args): calls a plain exported function and never throws. Returns { ok, value, error },
// so one test can send a payload that is meant to be rejected and a document that must still parse.
const call = (fn, ...args) => {
  if (!isFn(fn)) fail(`expected a function to call, got ${util.inspect(fn)}`);
  try {
    return { ok: true, value: fn(...args), error: null };
  } catch (error) {
    process.stderr.write(`harness: call(${fn.name || 'anonymous'}) threw ${(error && error.message) || error}\n`);
    return { ok: false, value: undefined, error };
  }
};

// Runs one test body: exit 0 when it resolves, exit 1 with the error otherwise.
const run = (body) => Promise.resolve().then(body).then(
  () => { process.stdout.write('harness: ok\n'); process.exit(0); },
  (error) => { process.stderr.write(`harness: ${(error && error.stack) || error}\n`); process.exit(1); },
);

module.exports = { version: 1, root: ROOT, load, invoke, call, run, assert, reset, db, express: state.express, pg: state.pg, child_process: state.child_process, fs: state.fs, code: state.code, app };
