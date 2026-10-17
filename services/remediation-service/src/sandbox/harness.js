'use strict';
// mitig8it regression-test harness v1 (contracts/test-harness-v1.md): Node built-ins only, never part of a repair.
const Module = require('node:module');
const path = require('node:path');
const util = require('node:util');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');
const realFs = require('node:fs');
const realCrypto = require('node:crypto');
const { pathToFileURL, fileURLToPath } = require('node:url');

const ROOT = path.resolve(__dirname, '..');

// TypeScript modules run through Node's own type stripper (Node 22.6 and later), which deletes
// type-only syntax and refuses enums, namespaces, and parameter properties. Stripping is what
// compiles the file; what Node still does not do is find it. Its resolver never tries a `.ts`
// suffix, so an extension-less relative import and the `.js` specifier a TypeScript project
// writes for a `.ts` source both fail to resolve. Both are resolved here instead, for the
// module a test loads and for every relative import that module makes.
const TS_SUFFIXES = ['.ts', '.mts', '.cts'];
const tsSuffix = (file) => TS_SUFFIXES.some((suffix) => file.endsWith(suffix));
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
// The ES module resolver adds no suffix at all, so `import './db'` beside a `db.js` fails there
// although `require('./db')` finds it. A relative specifier is tried as TypeScript first and then
// as the JavaScript file or directory index it names.
const JS_SUFFIXES = ['.js', '.mjs', '.cjs'];
const findSource = (absolute) => tsSource(absolute) || [absolute, path.join(absolute, 'index')].flatMap((b) => JS_SUFFIXES.map((x) => b + x)).find(isFile) || null;
const isRelative = (request) => request.startsWith('.') || path.isAbsolute(request);
const state = { express: { routes: [] }, pg: { queries: [] }, child_process: { calls: [] }, fs: { reads: [] }, env: { reads: [] }, code: { calls: [] }, crypto: { digests: [], kdfs: [] }, cookies: { calls: [] } };
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

// A recording Express response. `res.out` is { status, body, headers, redirect } as the handler
// left it, and `ended` runs once the handler ends the response. `h.res()` hands one to a proof
// that calls a route handler the module never registered, where there is no route to invoke.
function response(ended = () => {}) {
  const out = { status: 200, body: undefined, headers: {}, redirect: null };
  const end = (body) => { if (body !== undefined) out.body = body; ended(); return res; };
  const base = Object.assign(new EventEmitter(), {
    locals: {}, out, statusCode: 200, send: end, end, write(chunk) { out.body = (out.body || '') + chunk; return true; },
    status(code) { out.status = base.statusCode = Number(code); return res; },
    sendStatus(code) { out.status = Number(code); return end(String(code)); },
    json(body) { out.headers['content-type'] = 'application/json'; return end(body); },
    type(v) { out.headers['content-type'] = String(v); return res; },
    set(n, v) { for (const [k, x] of Object.entries(typeof n === 'object' ? n : { [n]: v })) out.headers[k.toLowerCase()] = x; return res; },
    redirect(a, b) { out.redirect = out.headers.location = b === undefined ? a : b; out.status = b === undefined ? 302 : Number(a); return end(''); },
  });
  // A cookie is recorded rather than sent: { kind: 'res.cookie', name, options }.
  base.cookie = (name, value, options) => { state.cookies.calls.push({ kind: 'res.cookie', name: String(name), options: obj(options) }); return res; };
  base.header = base.setHeader = base.set;
  base.contentType = base.type;
  // Other response methods (vary, sendFile, ...) are chainable no-ops.
  const res = new Proxy(base, { get: (t, k) => (k in t ? t[k] : k === 'then' || typeof k === 'symbol' ? undefined : () => res) });
  return res;
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
  return new Promise((resolve, reject) => {
    let done = false;
    const res = response(() => later(() => settle()));
    const out = res.out;
    const settle = (error) => { if (done) return; done = true; clearTimeout(timer); if (error) reject(error instanceof Error ? error : new Error(String(error))); else resolve(out); };
    const timer = setTimeout(() => settle(new Error(`harness.invoke: the ${req.method} ${route} handler never ended the response`)), options.timeout || 2000);
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
// `Function` is recorded and still compiles. A real package builds its wrappers with `new Function`
// while it is being imported (`depd`, under express and body-parser), and a constructor that handed
// back a no-op made `module.exports = deprecate.function(...)` undefined and broke every module
// above it. The proxy keeps the constructor's identity (`Function.prototype`, `instanceof`, `name`)
// and records every call; `load()` then discards what the import itself compiled, so `noCode`
// speaks about the call under test and not about a dependency's wrapper.
const RealFunction = global.Function;
const recordFunction = (args) => recordCode('Function', args.length ? args[args.length - 1] : '');
global.Function = new Proxy(RealFunction, {
  apply: (target, self, args) => (recordFunction(args), Reflect.apply(target, self, args)),
  construct: (target, args, newTarget) => (recordFunction(args), Reflect.construct(target, args, newTarget === global.Function ? target : newTarget)),
});
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

// crypto is the real module with its digests and key-derivation functions recorded. A
// password_hashing repair is proven by what the password reached: never a fast digest
// (createHash, createHmac), and a KDF (scrypt, pbkdf2) with a salt. digests: { algorithm, data };
// kdfs: { kind, password }.
const crypto = Object.create(realCrypto);
const text = (v) => (Buffer.isBuffer(v) || ArrayBuffer.isView(v) ? Buffer.from(v.buffer, v.byteOffset, v.byteLength).toString() : String(v));
const digest = (algorithm, made) => {
  const entry = { algorithm: String(algorithm).toLowerCase(), data: [] };
  state.crypto.digests.push(entry);
  const update = made.update.bind(made);
  made.update = (data, ...rest) => (entry.data.push(text(data)), update(data, ...rest), made);
  return made;
};
crypto.createHash = (a, ...r) => digest(a, realCrypto.createHash(a, ...r));
crypto.createHmac = (a, ...r) => digest(a, realCrypto.createHmac(a, ...r));
for (const [name, kind] of [['scrypt', 'scrypt'], ['scryptSync', 'scrypt'], ['pbkdf2', 'pbkdf2'], ['pbkdf2Sync', 'pbkdf2']]) {
  crypto[name] = (password, ...rest) => (state.crypto.kdfs.push({ kind, password: text(password) }), realCrypto[name](password, ...rest));
}

// express-session and cookie-session record the cookie options they were configured with and
// pass every request through. express-session keeps them under `cookie`, cookie-session at the top.
const pass = () => (req, res, next) => next && next();
const session = (o) => { state.cookies.calls.push({ kind: 'express-session', name: obj(o).name || 'connect.sid', options: obj(obj(o).cookie) }); return pass(); };
session.Store = class Store extends EventEmitter {};
session.MemoryStore = class MemoryStore extends session.Store {};
const cookieSession = (o) => { state.cookies.calls.push({ kind: 'cookie-session', name: obj(o).name || 'session', options: obj(o) }); return pass(); };

const builtinFakes = { express, pg, child_process, fs, 'fs/promises': fs.promises, vm, crypto, 'express-session': session, 'cookie-session': cookieSession };
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
// A module written with `import`/`export` is loaded by the ES module loader, which never consults
// `Module._load`, so its jobs are done through the synchronous hooks Node 22.15 and later expose
// (they see `require` too): a relative specifier is redirected to the source file it names, a
// faked specifier to a synthetic module that re-exports the same fake object a CommonJS module
// gets, and an entry load() wants evaluated again to a URL of its own. Everything else falls
// through to the real resolver.
const FAKE_SCHEME = 'mitig8it-fake:';
const FRESH = '?mitig8it-load=';
const FAKES_KEY = Symbol.for('mitig8it.harness.fakes');
const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
// `length`, `name` and the rest are a function's own machinery, and reading `caller` throws.
const NOT_EXPORTED = new Set(['length', 'name', 'prototype', 'caller', 'arguments', 'constructor', 'default']);
// The names a fake carries, its prototype chain included, because an ES module's named imports
// have to exist as bindings at link time and only the fake itself knows what it offers. `fs` is
// the case that needs the chain: its own keys are the recorders and the rest of node:fs is
// inherited, and a module that imports one of those by name must still get it.
function exported(value) {
  const names = new Set();
  for (let current = value; current && current !== Object.prototype && current !== Function.prototype; current = Object.getPrototypeOf(current)) {
    for (const key of Object.getOwnPropertyNames(current)) if (IDENTIFIER.test(key) && !NOT_EXPORTED.has(key)) names.add(key);
  }
  return [...names];
}
// The format Node gave each file it loaded, so load() knows which entries are ES modules. A `.ts`
// or a `.js` outside a typed package comes back ambiguous (`typescript`, or no format) and Node
// decides by syntax, so that is decided here the same way, from a top-level import or export.
const formats = new Map();
const ESM_SYNTAX = /^[ \t]*(?:import[\s{*'"]|export[\s{*])/m;
function moduleFormat(file) {
  const url = pathToFileURL(file).href;
  const known = String(formats.get(url));
  if (!formats.has(url) || /^(commonjs|json|builtin|wasm)/.test(known)) return null;
  const format = /^module/.test(known) ? known : ESM_SYNTAX.test(realFs.readFileSync(file, 'utf8')) ? (tsSuffix(file) ? 'module-typescript' : 'module') : null;
  if (format) formats.set(url, format);
  return format;
}
let generation = 0;
globalThis[FAKES_KEY] = (name) => fakes[name];
if (typeof Module.registerHooks === 'function') {
  Module.registerHooks({
    resolve(specifier, context, nextResolve) {
      const written = String(specifier);
      const name = written.replace(/^node:/, '');
      // The load generation is part of the URL, so each load() gets a synthetic module that reads
      // the stubs of that load rather than the first one the registry cached.
      if (Object.prototype.hasOwnProperty.call(fakes, name)) return { url: `${FAKE_SCHEME}${generation}:${encodeURIComponent(name)}`, shortCircuit: true, format: 'module' };
      if (written.includes(FRESH)) return { url: pathToFileURL(written).href, shortCircuit: true, format: formats.get(pathToFileURL(written.split(FRESH)[0]).href) };
      if (!isRelative(written)) return nextResolve(specifier, context);
      let from = ROOT;
      try { from = path.dirname(fileURLToPath(context.parentURL)); } catch { from = ROOT; }
      const found = tsSource(path.resolve(from, written));
      if (found) return { url: pathToFileURL(found).href, shortCircuit: true };
      try {
        return nextResolve(specifier, context);
      } catch (error) {
        const other = findSource(path.resolve(from, written));
        if (!other) throw error;
        return { url: pathToFileURL(other).href, shortCircuit: true };
      }
    },
    load(url, context, nextLoad) {
      const written = String(url);
      if (written.startsWith('file:') && fileURLToPath(written).includes(FRESH)) {
        const real = fileURLToPath(written).split(FRESH)[0];
        return { format: formats.get(pathToFileURL(real).href), source: realFs.readFileSync(real, 'utf8'), shortCircuit: true };
      }
      if (!written.startsWith(FAKE_SCHEME)) {
        const result = nextLoad(url, context);
        formats.set(written, result.format);
        return result;
      }
      const name = decodeURIComponent(written.slice(written.indexOf(':', FAKE_SCHEME.length) + 1));
      const names = exported(fakes[name]);
      // Each binding is named `e<n>` and aliased on the way out, because an export alias may be
      // any identifier name and a `const` may not: `express.static` is a strict-mode reserved
      // word, and `export const static` would not parse. The fake is read at evaluation, so the
      // module sees the same recorders the test asserts on.
      const source = [`const v = globalThis[Symbol.for('mitig8it.harness.fakes')](${JSON.stringify(name)});`, 'export default v;']
        .concat(names.map((key, index) => `const e${index} = v[${JSON.stringify(key)}];`))
        .concat(names.length ? [`export { ${names.map((key, index) => `e${index} as ${key}`).join(', ')} };`] : [])
        .join('\n');
      return { format: 'module', source, shortCircuit: true };
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
    resolved = findSource(absolute);
    if (!resolved) throw error;
  }
  delete require.cache[resolved];
  loadedFile = resolved;
  generation += 1;
  // A CommonJS module is evaluated again once its cache entry is gone. An ES module is not: its
  // registry is keyed by URL for the life of the process and nothing can evict an entry. So once a
  // file is known to be an ES module, it is loaded under a URL of its own for this load, which the
  // hooks read back from the real file. Only the entry is fresh, as under CommonJS.
  return require(moduleFormat(resolved) ? resolved + FRESH + generation : resolved);
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
// passwordHash(password): the password never reached a fast digest and did reach a KDF.
assert.passwordHash = (password, message) => {
  const want = String(password);
  const fast = state.crypto.digests.filter((d) => d.data.some((x) => x.includes(want)));
  if (fast.length) fail(message || 'the password was digested with a fast hash', fast.map((d) => d.algorithm));
  if (!state.crypto.kdfs.some((k) => k.password === want)) fail(message || 'expected the password to reach crypto.scrypt or crypto.pbkdf2', state.crypto.kdfs.map((k) => k.kind));
};
// cookieFlags(kind[, name]): every recorded cookie of that kind (and name) is HttpOnly, Secure and SameSite Lax or Strict.
assert.cookieFlags = (kind, name, message) => {
  const found = state.cookies.calls.filter((c) => c.kind === kind && (name === undefined || c.name === String(name)));
  if (!found.length) fail(message || `no ${kind} cookie${name === undefined ? '' : ` named ${name}`} was recorded`, state.cookies.calls.map((c) => `${c.kind}:${c.name}`));
  for (const { options: o, name: n } of found) {
    const same = o.sameSite === true ? 'strict' : String(o.sameSite).toLowerCase();
    if (o.httpOnly !== true || o.secure !== true || !['lax', 'strict'].includes(same)) fail(message || `cookie ${n} lacks httpOnly, secure or sameSite`, o);
  }
};
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

module.exports = { version: 1, root: ROOT, load, invoke, res: response, call, run, assert, reset, db, express: state.express, pg: state.pg, child_process: state.child_process, fs: state.fs, code: state.code, crypto: state.crypto, cookies: state.cookies, app };
