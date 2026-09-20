# Sandbox test harness v1

The repair sandbox has no network and no installed packages. A generated regression test that
requires `express`, `supertest`, `pg`, or a test framework crashes with `MODULE_NOT_FOUND` on
both trees and proves nothing. The service therefore materializes one dependency-free CommonJS
file, `.mitig8it/harness.js`, next to the generated tests in both the baseline and the candidate
workspace. It is evidence infrastructure, not part of the repair: it is never a patch, never a
manifest entry, and a proposal that writes to it is rejected as `harness_path_protected`.

Source: `services/remediation-service/src/sandbox/harness.js` (Node 20, built-ins only, under 12 KB).

## Shape of a test

```js
const h = require('../harness');
h.run(async () => {
  const app = h.load('services/orders.js');
  const bad = "1' OR '1'='1";
  await h.invoke(app, 'get', '/orders/:id', { params: { id: bad } });
  const q = h.pg.queries[0];
  h.assert(q, 'no query ran');
  h.assert.notIncludes(q.text, bad, 'input reached the SQL text');
  h.assert.includes(JSON.stringify(q.values || []), bad, 'input must be a bound value');
});
```

The test lives at `.mitig8it/regression/<finding-id>.test.js`, so `require('../harness')` is the
correct relative path. `h.run` exits 0 when the body resolves and 1 with the error otherwise; a
test must fail on the original code and pass on the repaired code to prove its finding.

## API

`h.load(target, options)`: requires the target module with the fakes below injected through the
require cache, and returns its exports. `target` is a repository path (`services/orders.js`,
resolved from the repository root) or a path starting with `./` or `../` relative to the test
file. Each call resets the recorders. `options`:

- `pg: { rows: [...] }` or `pg: { result: {...} | (query) => ({...}) }`: what every query resolves; default `{ rows: [], rowCount: 0 }`.
- `child_process: { stdout, stderr, error, code }` or `child_process: { result: (command) => ({...}) }`: what every child reports; default empty stdout, exit 0.
- `fs: { content, exists }`: `content` is a string, Buffer, or `(path) => content`; `exists` is a boolean or `(path) => boolean` (default true). A missing file rejects with `ENOENT`.
- `stubs: { '<specifier>': value }`: any other module to inject by its exact require specifier (`'axios'`, `'./db'`).
- `real: ['fs']`: names from `express`, `pg`, `child_process`, `fs` to leave real.

`h.invoke(app, method, path, { params, query, body, headers, timeout })`: finds the handler recorded
for `method` and `path` (an exact route pattern such as `/orders/:id` with `params`, or a concrete
URL such as `/orders/7` whose `:param` segments are extracted), builds `req` and `res`, runs the
route's handlers in order, and resolves once the response ends or the handler settles. Rejects
when the handler throws, rejects, calls `next(err)`, or never ends the response (default 2000 ms).
Resolves `{ status, body, headers, redirect }`. `res` records `status`, `json`, `send`, `end`,
`sendStatus`, `type`, `set`/`header`, and `redirect`; other response methods are chainable no-ops.

Fakes and their recorders:

- `express`: `express()` and `express.Router()` return the same recording app. `get`, `post`, `put`, `delete`, `patch`, `head`, `options`, `all`, and `use` record `{ method, path, handlers }` in `h.express.routes`. `express.json()`, `urlencoded()`, and `static()` are pass-through middleware; `listen` is a no-op.
- `pg`: `Pool` and `Client` whose `query(text, values?, cb?)` (or `query({ text, values })`) record `{ text, values }` in `h.pg.queries` and resolve the configured result. `connect()` resolves a client with `query` and `release`.
- `child_process`: `exec`, `execFile`, `spawn`, `execSync`, `execFileSync`, and `spawnSync` record `{ fn, command, args, options }` in `h.child_process.calls` (`args` is `null` for `exec` and `execSync`), then report the configured stdout through the callback, the returned child's `stdout`/`close` events, or the sync return value. `util.promisify(exec|execFile)` works.
- `fs`: `readFile`, `readFileSync`, `existsSync`, `createReadStream`, and `fs.promises.readFile` (also `fs/promises`) record each path in `h.fs.reads` and return the configured content; every other `fs` function is the real one.

Assertions (each throws a `HarnessAssertion` with the message on failure):

- `h.assert(condition, message)`
- `h.assert.equal(actual, expected, message)`
- `h.assert.includes(text, needle, message)` and `h.assert.notIncludes(text, needle, message)`
- `h.assert.inside(baseDirectory, path, message)`: the resolved path stays strictly under the base directory.

`h.reset()` clears every recorder. `h.root` is the repository root the harness was materialized in.

## What to assert per family

- SQL injection: the recorded query `text` does not contain the payload and `values` does.
- Command injection: the recorded call's `fn` is `execFile` or `spawn`, `args` carries the payload as its own element, and `options.shell` is unset.
- Path traversal: every path in `h.fs.reads` satisfies `h.assert.inside(base, path)`, or the handler answered with a 4xx status and read nothing.

## Policy

A regression test may require only Node built-ins, relative repository paths, and the harness.
Any other specifier is rejected as `missing_dependency:<name>` with guidance naming the harness.
The harness is added to the sandbox payload's file list only when the candidate carries generated
tests, and is left out with the limitation
`the repository already carries .mitig8it/harness.js, so the service test harness was not materialized`
when the snapshot occupies that path.
