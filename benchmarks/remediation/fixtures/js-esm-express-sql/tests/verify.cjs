// Two invocation modes.
//   node tests/verify.cjs --exploit | --behavior   Sandbox mode: checks the app.mjs in this tree.
//   node tests/verify.cjs <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The module is an ES module, so express and pg are replaced through Node's module hooks rather
// than the require cache: `import` never consults `Module._load`.
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const ATTACK = "1' OR '1'='1";
const LEGITIMATE = '42';
const QUERIES = [];
const ROUTES = [];

const router = { get: (route, handler) => { ROUTES.push({ route, handler }); } };
const express = () => router;
express.Router = () => router;
class Pool {
  query(text, values) {
    QUERIES.push({ text: String(text), values: values || [] });
    return Promise.resolve({ rows: [{ id: 1, total: 10 }] });
  }
}
globalThis.fixtureFakes = { express: { default: express }, pg: { default: { Pool }, Pool } };
Module.registerHooks({
  resolve: (specifier, context, next) => (specifier in globalThis.fixtureFakes
    ? { url: `fixture-fake:${specifier}`, format: 'module', shortCircuit: true }
    : next(specifier, context)),
  load: (url, context, next) => {
    if (!url.startsWith('fixture-fake:')) return next(url, context);
    const name = url.slice('fixture-fake:'.length);
    const names = Object.keys(globalThis.fixtureFakes[name]).filter((key) => key !== 'default');
    const source = [`const f = globalThis.fixtureFakes[${JSON.stringify(name)}];`, 'export default f.default;']
      .concat(names.map((key) => `export const ${key} = f.${key};`)).join('\n');
    return { format: 'module', source, shortCircuit: true };
  },
});

let loads = 0;
async function lookup(file, id) {
  ROUTES.length = 0;
  QUERIES.length = 0;
  loads += 1;
  await import(`${pathToFileURL(path.resolve(file)).href}?load=${loads}`);
  const found = ROUTES.find((item) => item.route === '/orders/:id');
  assert.ok(found, 'the module registers GET /orders/:id');
  let body;
  await found.handler({ params: { id } }, { json: (value) => { body = value; } });
  return { query: QUERIES[0], body };
}

const localPath = () => path.resolve(__dirname, '..', 'app.mjs');

async function exploit() {
  const { query } = await lookup(localPath(), ATTACK);
  if (!query || query.text.includes(ATTACK)) {
    process.stderr.write('vulnerability present: the order id is concatenated into the SQL text\n');
    process.exit(1);
  }
  assert.ok(JSON.stringify(query.values).includes(ATTACK));
  process.exit(0);
}

async function behavior() {
  const { query, body } = await lookup(localPath(), LEGITIMATE);
  assert.match(query.text, /FROM orders/);
  assert.ok((query.text + JSON.stringify(query.values)).includes(LEGITIMATE));
  assert.deepEqual(body, [{ id: 1, total: 10 }]);
  process.exit(0);
}

async function compare(originalPath, repairedPath) {
  assert.ok((await lookup(originalPath, ATTACK)).query.text.includes(ATTACK));
  const repaired = (await lookup(repairedPath, ATTACK)).query;
  assert.equal(repaired.text, 'SELECT id, total FROM orders WHERE id = $1');
  assert.deepEqual(repaired.values, [ATTACK]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
(mode === '--exploit' ? exploit() : mode === '--behavior' ? behavior() : compare(process.argv[2], process.argv[3]))
  .catch((error) => { process.stderr.write(`${error.stack || error}\n`); process.exit(2); });
