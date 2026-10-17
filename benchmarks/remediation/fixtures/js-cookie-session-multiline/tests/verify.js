// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the server.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
// express, express-session and cookie-session are stood in for here, because nothing is
// installed: each records the cookie options it was given and the routes it was handed. The
// cookie is vulnerable unless it is HttpOnly, Secure, and SameSite Lax or Strict.
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const recorded = [];
const routes = [];
const app = { use() {}, listen() {}, set() {} };
for (const method of ['get', 'post', 'put', 'delete']) app[method] = (route, ...handlers) => routes.push({ method, route, handler: handlers[handlers.length - 1] });
const express = () => app;
express.Router = () => app;
express.json = () => () => {};
const middleware = (kind, pick) => (options) => { recorded.push({ kind, options: pick(options || {}) }); return () => {}; };
const stubs = {
  express,
  'express-session': middleware('express-session', (o) => o.cookie || {}),
  'cookie-session': middleware('cookie-session', (o) => o),
};
const load = Module._load;
Module._load = function stubbed(request, ...rest) {
  return Object.prototype.hasOwnProperty.call(stubs, request) ? stubs[request] : load.call(this, request, ...rest);
};

function run(file) {
  recorded.length = 0;
  routes.length = 0;
  const resolved = path.resolve(file);
  delete require.cache[resolved];
  require(resolved);
  for (const { handler } of routes) {
    const res = { cookie: (name, value, options) => recorded.push({ kind: 'res.cookie', name, value, options: options || {} }), send() {}, json() {} };
    handler({ query: { session: 's', user: 'u' }, params: { theme: 'dark' }, body: { user: 'u' } }, res);
  }
  const found = recorded.filter((entry) => entry.kind === 'cookie-session');
  assert.ok(found.length > 0, 'expected the cookie-session cookie to be recorded');
  return found;
}

function vulnerable(found) {
  return found.some(({ options }) => {
    const same = options.sameSite === true ? 'strict' : String(options.sameSite).toLowerCase();
    return options.httpOnly !== true || options.secure !== true || !['lax', 'strict'].includes(same);
  });
}

function kept(found) {
  assert.equal(found[0].options.name, 'session');
  assert.equal(found[0].options.maxAge, 24 * 60 * 60 * 1000);
  assert.equal(found[0].options.keys.length, 2);
}

function localPath() {
  return path.resolve(__dirname, '..', 'server.js');
}

function exploit() {
  const found = run(localPath());
  if (vulnerable(found)) {
    process.stderr.write('vulnerability present: the cookie is missing HttpOnly, Secure or SameSite\n');
    process.exit(1);
  }
  kept(found);
  process.exit(0);
}

function behavior() {
  kept(run(localPath()));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = run(originalPath);
  assert.equal(vulnerable(original), true);
  kept(original);
  const repaired = run(repairedPath);
  assert.equal(vulnerable(repaired), false);
  kept(repaired);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
