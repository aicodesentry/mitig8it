// Two invocation modes.
//   node tests/verify.cjs --exploit | --behavior   Sandbox mode: checks src/accounts.ts in this tree.
//   node tests/verify.cjs <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The module is TypeScript written as an ES module. Node strips its types; its extension-less
// relative import is completed to the `.ts` source and pg is replaced, both through Node's
// module hooks, because the ES module resolver does neither on its own.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');
const { pathToFileURL, fileURLToPath } = require('node:url');

const ATTACK = "x' OR '1'='1";
const LEGITIMATE = 'ada@example.com';
const QUERIES = [];
class Pool {
  query(text, values) {
    QUERIES.push({ text: String(text), values: values || [] });
    return Promise.resolve({ rows: [{ id: 1, email: LEGITIMATE }] });
  }
}
globalThis.fixturePool = Pool;
Module.registerHooks({
  resolve: (specifier, context, next) => {
    if (specifier === 'pg') return { url: 'fixture-fake:pg', format: 'module', shortCircuit: true };
    if (specifier.startsWith('.') && context.parentURL && context.parentURL.startsWith('file:')) {
      // Beside the importing file, or beside the tree's own source when a reviewed copy under
      // expected/ imports a module that only the tree carries.
      const candidate = [path.dirname(fileURLToPath(context.parentURL)), path.resolve(__dirname, '..', 'src')]
        .map((directory) => path.resolve(directory, `${specifier}.ts`)).find((file) => fs.existsSync(file));
      if (candidate) return { url: pathToFileURL(candidate).href, shortCircuit: true };
    }
    return next(specifier, context);
  },
  load: (url, context, next) => (url === 'fixture-fake:pg'
    ? { format: 'module', source: 'export const Pool = globalThis.fixturePool; export default { Pool };', shortCircuit: true }
    : next(url, context)),
});

let loads = 0;
async function find(file, email) {
  QUERIES.length = 0;
  loads += 1;
  const module_ = await import(`${pathToFileURL(path.resolve(file)).href}?load=${loads}`);
  const rows = await module_.findAccounts(email);
  return { query: QUERIES[0], rows };
}
const localPath = () => path.resolve(__dirname, '..', 'src', 'accounts.ts');

async function exploit() {
  const { query } = await find(localPath(), ATTACK);
  if (!query || query.text.includes(ATTACK)) {
    process.stderr.write('vulnerability present: the email is interpolated into the SQL text\n');
    process.exit(1);
  }
  assert.deepEqual(query.values, [ATTACK]);
  process.exit(0);
}

async function behavior() {
  const { query, rows } = await find(localPath(), LEGITIMATE);
  assert.match(query.text, /FROM accounts/);
  assert.ok((query.text + JSON.stringify(query.values)).includes(LEGITIMATE));
  assert.deepEqual(rows, [{ id: 1, email: LEGITIMATE }]);
  process.exit(0);
}

async function compare(originalPath, repairedPath) {
  assert.ok((await find(originalPath, ATTACK)).query.text.includes(ATTACK));
  const repaired = (await find(repairedPath, ATTACK)).query;
  assert.equal(repaired.text, 'SELECT id, email FROM accounts WHERE email = $1');
  assert.deepEqual(repaired.values, [ATTACK]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
(mode === '--exploit' ? exploit() : mode === '--behavior' ? behavior() : compare(process.argv[2], process.argv[3]))
  .catch((error) => { process.stderr.write(`${error.stack || error}\n`); process.exit(2); });
