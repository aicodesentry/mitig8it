# Sandbox test harness v1

The repair sandbox has no network and no installed packages. A generated regression test that
requires `express`, `supertest`, `pg`, or a test framework crashes with `MODULE_NOT_FOUND` on
both trees and proves nothing. The service therefore materializes one dependency-free CommonJS
file, `.mitig8it/harness.js`, next to the generated tests in both the baseline and the candidate
workspace. It is evidence infrastructure, not part of the repair: it is never a patch, never a
manifest entry, and a proposal that writes to it is rejected as `harness_path_protected`.

Source: `services/remediation-service/src/sandbox/harness.js` (Node 22 LTS, built-ins only, under 32 KB).

## TypeScript

The sandbox has no TypeScript toolchain and gets none. What it has is Node's own type stripper,
which the service turns on for every generated test and every derived syntax check with
`--experimental-strip-types --disable-warning=ExperimentalWarning` (`patches.NODE_TYPESCRIPT_FLAGS`).
Stripping deletes type-only syntax and emits nothing, so a `.ts`, `.cts`, or `.mts` module loads
as the JavaScript it already is.

Three constructs cannot be deleted, only compiled, and Node refuses the whole file for each with
`ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`: an `enum`, a `namespace` (or the `module X {}` form), and a
constructor parameter property (`constructor(private x: number)`). The service refuses such a
finding before it runs anything, with `typescript_syntax_not_strippable:<construct>`. `.jsx` and
`.tsx` are refused as `module_not_loadable_by_node`: strip-only mode does not transform JSX.

Stripping does not resolve imports, and Node's resolver never tries a `.ts` suffix, so `h.load`
and the harness's require hook do: an extension-less relative specifier, a directory's
`index.ts`, and the `.js` specifier a TypeScript project writes for a `.ts` source (`./config.js`
for `config.ts`, `.cjs` for `.cts`, `.mjs` for `.mts`) all resolve to the TypeScript file. A
module written with `import`/`export` is loaded by the ES module loader, which does not consult
the require hook, so its imports resolve through `module.registerHooks` instead.

## ES modules and the fakes

The same `module.registerHooks` pair serves the fakes to the ES module loader. A faked specifier
resolves to a synthetic module whose source reads the live fake object and re-exports it, as the
default export and under every name the fake carries, its prototype chain included, so both
`import express from 'express'` and `import { Pool } from 'pg'` get the recorder a CommonJS
module would have got. `load(..., { stubs })` and `{ real }` apply the same way.

Two limits are worth knowing. The ES module registry caches a module for the life of the
process, so a second `load()` that supplies a *different* stub for the same specifier does not
re-evaluate it; a test that needs two different stubs for one name needs two processes. And
nothing is auto-stubbed: a package the harness does not fake is a package the sandbox does not
have, so the module fails to load and the proof fails on both trees rather than passing against
something invented. That is the honest outcome, and on a real application's entry module it is
the common one, because a proof has to load the module's whole import closure.

## What a proof's module may reach

Because of that, the service decides before it writes a proof whether the module can load at
all, over the closure the load actually pulls in: every static `import`, and every `require`
whose statement begins at column 0, followed through relative specifiers inside the snapshot. A
`require` inside a function body runs when that function is called, which a proof need never do,
so it is not counted.

A specifier in that closure has to be a Node built-in or one of the fakes above; anything else
refuses the finding as `dependency_not_available_in_sandbox:<package>`. A TypeScript file
anywhere in the closure is checked for the three constructs strip-only mode refuses, so an
`enum` two relative imports away refuses as `typescript_syntax_not_strippable:enum` rather than
ending in a bare `SyntaxError` on both trees. A relative specifier the snapshot does not carry is
neither followed nor refused: the snapshot is a budgeted slice of the tree, and its absence says
nothing about the repository.

One shape loads under `tsc` and not here: an interface imported as an ordinary value binding
(`import { Settings, settings } from './config'`). Strip-only mode cannot tell which name was a
type, so the import survives and names an export the stripped module does not have. It is the
`isolatedModules` rule TypeScript enforces with `verbatimModuleSyntax`, nothing detects it
lexically, and the module simply fails to load, so a proof over it fails rather than passing.

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
- `env: { NAME: 'value' }`: values laid over the real environment for this load only, cleared by the next one. Every `process.env` name the module reads is recorded in `h.env.reads`, whether or not the test supplied it.
- `argv: ['node', 'module', 'value']`: `process.argv` for this load only, restored to the test process's own on the next load that does not supply one. It is for a module that reads its input from the command line at import, where there is no function to pass an argument to.

`h.invoke(app, method, path, { params, query, body, headers, timeout })`: finds the handler recorded
for `method` and `path` (an exact route pattern such as `/orders/:id` with `params`, or a concrete
URL such as `/orders/7` whose `:param` segments are extracted), builds `req` and `res` (string `query` values are percent-decoded the way Express decodes a query string, and a value that is not valid percent-encoding is passed through unchanged), runs the
route's handlers in order, and resolves once the response ends or the handler settles. Rejects
when the handler throws, rejects, calls `next(err)`, or never ends the response (default 2000 ms).
Resolves `{ status, body, headers, redirect }`. `res` records `status`, `json`, `send`, `end`,
`sendStatus`, `type`, `set`/`header`, and `redirect`; other response methods are chainable no-ops.

Fakes and their recorders:

- `express`: `express()` and `express.Router()` return the same recording app. `get`, `post`, `put`, `delete`, `patch`, `head`, `options`, `all`, and `use` record `{ method, path, handlers }` in `h.express.routes`. `express.json()`, `urlencoded()`, and `static()` are pass-through middleware; `listen` is a no-op.
- `pg`: `Pool` and `Client` whose `query(text, values?, cb?)` (or `query({ text, values })`) record `{ text, values }` in `h.pg.queries` and resolve the configured result. `connect()` resolves a client with `query` and `release`.
- `child_process`: `exec`, `execFile`, `spawn`, `execSync`, `execFileSync`, and `spawnSync` record `{ fn, command, args, options, shell }` in `h.child_process.calls` (`args` is `null` for `exec` and `execSync`; `shell` is the command line a shell would interpret, the whole string for `exec`/`execSync` or command plus args when `options.shell` is set, and `null` when the child ran with an argv array), then report the configured stdout through the callback, the returned child's `stdout`/`close` events, or the sync return value. `util.promisify(exec|execFile)` works.
- `process.env`: a recording view of the real environment. Every name read is appended to `h.env.reads`; names given in `load(..., { env })` answer with the supplied value, and every other name answers as the real environment does.
- `fs`: `readFile`, `readFileSync`, `existsSync`, `createReadStream`, and `fs.promises.readFile` (also `fs/promises`) record each read in `h.fs.reads` as `{ path, resolved }`, the string the module passed and its absolute form (`String(read)` is the raw path), and return the configured content; every other `fs` function is the real one.
- dynamic code: `eval`, `new Function`, `vm.runInNewContext`, `vm.runInThisContext`, `vm.runInContext`, `vm.compileFunction`, `new vm.Script`, and `setTimeout`/`setInterval` given a string record `{ kind, source }` in `h.code.calls` and run nothing. `eval` and `vm.runIn*Context` answer `undefined`, `new Function` and `vm.compileFunction` hand back a function that does nothing, and a timer given a function is the real timer. `eval`, `Function`, and the timers are resolved through the global scope chain, so the module under test gets the recorder without naming it.

`h.call(fn, ...args)` calls a plain exported function and never throws: it returns `{ ok, value, error }`, so one test can send a payload that is meant to be rejected and a document that must still be read.

`h.res()`: a recording Express response, for a route handler the module exports but never registers with Express, where there is no route for `h.invoke` to find. It records the same methods `h.invoke`'s response does, and `res.out` is `{ status, body, headers, redirect }` as the handler left it. The proof builds the request itself: `h.call(m.handler, { params: { name: payload } }, h.res())`.

Assertions (each throws a `HarnessAssertion` with the message on failure):

- `h.assert(condition, message)`
- `h.assert.equal(actual, expected, message)`
- `h.assert.includes(text, needle, message)` and `h.assert.notIncludes(text, needle, message)`
- `h.assert.inside(read, baseDirectory, message | { payload, message })`: `read` is an `h.fs.reads` entry, a path string, or the whole `h.fs.reads` array (an entry or the array is recognized in either position); every read's resolved path stays strictly under the base directory. With `{ payload }` naming the input that produced those reads, a payload that escapes the base (a `..` segment or an absolute path, as sent or once percent-decoded) additionally requires that no read was recorded at all, so the handler must have rejected it before touching the filesystem.
- `h.assert.envRead(name, message)`: the module read `process.env.<name>` at least once. A module that still holds the literal never reads it, which is what makes this fail before a repair and pass after one.
- `h.assert.notInSource(module, literal, message)`: the file the last `load()` executed no longer contains the literal, and no string the module exports carries it. A path may be passed in place of the module.
- `h.assert.argv(call, payload, message)`: the recorded child process call has no `shell` string and `payload`, the injected input, is its own element of `args` (the command name itself is argv[0] and also satisfies it); one call covers the command-injection assertion.
- `h.assert.noCode(message)`: nothing the module did turned a string into code. On failure it names every recorded call and the text it was given.

`h.reset()` clears every recorder. `h.root` is the repository root the harness was materialized in.

## What to assert per family

- SQL injection: the recorded query `text` does not contain the payload and `values` does.
- Command injection: `h.assert.argv(h.child_process.calls[0], payload)`: the call has no `shell` string and the payload is its own `args` element.
- Hardcoded credential: `const m = h.load(path, { env: { NAME: 'value-from-env' } })`, then `h.assert.envRead('NAME')` and `h.assert.notInSource(m, literal)`, and `h.assert.equal(m.<identifier>, 'value-from-env')` when the module exports the identifier. `NAME` is derived from the identifier the literal was bound to (`apiKey` gives `API_KEY`). The repair this proves replaces the literal with `process.env.NAME` in place; deleting the constant fails the exported-value assertion.
- Code injection: with `FUNC` the function at the finding, `h.call(m.FUNC, ...)` with a payload that would run code, then `h.assert.noCode()`, then `h.assert.equal(JSON.stringify(h.call(m.FUNC, ...'[1, 2]'...).value), '[1,2]')`. The repair this proves parses the value as data (`JSON.parse`) instead of interpreting it. It is for a string the code reads back as a value; a string compiled into something the module calls later is refused by the `dynamic_code_unsupported` gate rather than rewritten.
- Path traversal: for each traversal payload (`../../etc/passwd` and its encoded form `..%2f..%2fetc%2fpasswd`), reset `h.fs.reads.length = 0`, invoke the handler, and assert `h.assert.inside(h.fs.reads, base, { payload })`, where `base` is the directory the handler serves from; the handler has to answer 400 or an equivalent error before any filesystem access, so no read is recorded. Then send one legitimate name and assert `h.assert.inside(h.fs.reads, base)`. The repair this proves resolves the candidate path against the base directory (`path.resolve(base, name)`) and rejects it unless the resolved path is the base itself or starts with base + `path.sep`; `path.basename` alone does not pass, and the analysis service reports it as an insufficient sanitizer.

## Policy

A regression test may require only Node built-ins, relative repository paths, and the harness.
Any other specifier is rejected as `missing_dependency:<name>` with guidance naming the harness.
The harness is added to the sandbox payload's file list only when the candidate carries generated
tests, and is left out with the limitation
`the repository already carries .mitig8it/harness.js, so the service test harness was not materialized`
when the snapshot occupies that path.
