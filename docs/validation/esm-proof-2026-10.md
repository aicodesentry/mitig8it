# Proofs that reach ES modules, October 2026

`docs/validation/pairs-2026-09.md` and `docs/architecture/known-debt.md` named four things in the
Node harness that stood between a generated proof and a module written with `import`/`export`:
the fakes reached only the CommonJS loader, the `registerHooks` resolver did not answer for the
entry module, the `global.Function` recorder broke packages that build wrappers at import, and
`module_scope_source_not_controllable` was said to hide module-scope credential reads an
env-driven reload could drive. This page is what each of those turned out to be when read against
the source and the corpus, what changed, and what the numbers did.

The sandbox runs Node 22.23.3 (`services/remediation-service/Dockerfile`, `ARG NODE_VERSION`).
Everything here was run under Node 22.21.1 and, for the harness spec and the fixture tests, also
under Node 24.1.0.

## What each named gap was

**The fakes under the ES module loader were already served.** `afdf5ac8` (25 September) resolves a
faked specifier to a synthetic module that re-exports the live fake. It reads the same `fakes`
table `Module._load` answers from, so any fake a later change adds to that table reaches both
loaders without another edit. What it did not do was re-evaluate: the synthetic module was cached
for the process, so a second `load()` with a different stub got the first one.

**The entry module, as described, did not reproduce.** A `.ts` ES module loaded by `h.load` resolves
and runs on Node 22.21, including the juice-shop `routes/vulnCodeFixes.ts` taken out of the corpus
cache, which fails on `js-yaml` and then on `@juice-shop/models/challenge`, never on itself. The
`ERR_MODULE_NOT_FOUND` recorded in the pairs page came from the with-dependencies run, whose
installed tree is no longer on disk, so that exact failure could not be re-run. Three real
resolver defects were found while looking for it, and all three are fixed:

- The resolver read the parent module's location with `new URL(parentURL).pathname`, which is
  percent-encoded. In a workspace whose path holds a space, `#` or `%`, every relative TypeScript
  import missed (`Cannot find module '.../my dir/lib/accuracy'`). It now uses `fileURLToPath` and
  `pathToFileURL`.
- The ES module resolver adds no suffix, so an extension-less relative import of a `.js`, `.mjs`
  or `.cjs` file, or of a directory `index`, failed under `import` where `require` would have found
  it. A relative specifier the real resolver cannot find is now tried with those suffixes, after
  the TypeScript ones.
- `h.load('services/report')` did not find `services/report.mjs`. The entry now resolves through the
  same order.

**A second load of an ES module returned the first evaluation.** This is the defect that matters
most for proofs, and the pairs page did not name it. `load()` deleted the `require.cache` record,
which re-evaluates CommonJS and does nothing for an ES module: its registry entry is keyed by URL
for the life of the process. A module-scope proof loads the module once per payload
(`_js_module_traversal_proof` loops over traversal payloads, each through `h.load(..., { env })`),
so on an ES module it saw only the first payload, and a module that threw on one load threw the
same cached error on every later one, including the legitimate name. Such a proof could fail on
the repaired tree and never verify.

**The `Function` recorder broke real packages.** It returned a no-op for every `new Function`, so
`depd`'s wrapper was `undefined` and every module above it failed to load.

**No module-scope credential read is behind `module_scope_source_not_controllable`.** The
JavaScript and Python credential proofs are generated before the site model runs
(`proofs.generate_proof`, `_js_credential_proof`, `_py_credential_proof`), so a
`hardcoded_credential` finding never reaches that refusal. On the cache measured here the refusal
counts 11 findings, and none is a credential read:

| Repository | Path | Family | What the value is |
| --- | --- | --- | --- |
| `dicebear/dicebear` | `packages/@dicebear/converter/tests/jpeg.test.js:9`, `core/tests/create.test.js:79`, `converter/tests/utils/svg.test.js:91` | `path_containment` | A fixture path built from `import.meta.url` in a test file |
| `sebhildebrandt/systeminformation` | `lib/battery.js:108`, `lib/system.js:217` | `path_containment` | `/proc/cpuinfo` and a sysfs path found at run time |
| `benbusby/whoogle-search` | `app/routes.py:36`, `misc/update-translations.py:39`, `app/static/js/controller.js:48`, `misc/replit.py:5` (2) | path, command | `app.config`, `__file__`, a browser `XMLHttpRequest`, a literal command line |
| `zamotany/logkitty` | `src/android/adb.ts:54` | `command_arguments` | Inside a function whose TypeScript return annotation the site model does not read, so it was taken for module scope |

The "40 of 81, 29 in dicebear" in `docs/architecture/known-debt.md` described those findings as
secrets at module scope; on this cache the dicebear ones are path findings in test files. Refusing
all eleven stays correct, so `proofs.py` and `sites.py` were not narrowed for credentials. The
logkitty row is a site-model gap (a TypeScript return type on a multi-line signature), recorded
here and not fixed on this branch.

## What changed

All in `services/remediation-service/src/sandbox/harness.js` unless named.

1. **Fresh ES module loads.** The `load` hook records the format Node gave every file. From the
   second load of a file that is an ES module (`module`, `module-typescript`, or an ambiguous
   `.js`/`.ts` with a top-level `import` or `export`), `load()` requires it as
   `<file>?mitig8it-load=<generation>`. The hooks resolve that to its own file URL and serve the
   real file's source, so the entry is evaluated again with that load's `env`, `argv` and `stubs`.
   Relative imports resolve against the real directory, and only the entry is fresh, as under
   CommonJS. Why this mechanism: on Node 22 a query string on a `require()`d ES module is dropped
   (the registry is keyed by the file path), `vm.SourceTextModule` exists only behind
   `--experimental-vm-modules`, which the sandbox does not pass, and `import()` is asynchronous
   while every proof calls `h.load` synchronously. A distinct path is the one key `require()` keeps.
2. **Per-load fakes.** The synthetic fake module's URL carries the load generation, so each load
   reads its own stubs. The contract's "a test that needs two different stubs needs two
   processes" limit is gone.
3. **Resolver.** `fileURLToPath`/`pathToFileURL` throughout, `.js`/`.mjs`/`.cjs` and `index`
   suffixes after the TypeScript ones, for imports and for the entry.
4. **`Function` that records and compiles.** `global.Function` is a `Proxy` over the real
   constructor: called or constructed, it records `{ kind: 'Function', source }` and returns a
   working function. `Function.prototype.constructor` points at the proxy, so `instanceof
   Function`, `Object.getPrototypeOf(fn) === Function.prototype` and `fn.constructor === Function`
   all hold (the last one did not hold before either). A call whose first non-harness stack frame
   is a file under `node_modules` is not recorded: a dependency compiling its own wrapper is not
   the code under test and would fail `noCode` on both trees. The earlier agent's draft discarded
   everything compiled during the import instead; that would let a module-scope `eval` in the code
   under test pass `noCode` on the vulnerable tree, so it was not kept. Compiling is safe for
   proofs because what a code-injection proof asserts is the recording, which still fails the
   original, and the `dynamic_code_unsupported` gate keeps the service from writing a proof for a
   `new Function` site at all.
5. **`sites.py`.** A named ES import from a repository module (`import { branch as target } from
   './settings'`) is now a `config` driver with the imported name as the member, so the stub
   carries `{ branch: payload }`. Before, the member was dropped and the stub was the bare payload,
   which a named import cannot bind to.
6. **`sites.js_require_line` and `js_bound_names`.** A named ES import of `child_process` is
   recognized and widened the way a destructuring `require` is, so the command template rewrites
   `exec` to `execFile` in an ES module instead of refusing as
   `child_process_binding_not_recognized`.
7. **Contracts.** `contracts/test-harness-v1.md` documents the fresh load, its mechanism and its
   one visible effect (`import.meta.url` carries the suffix), the resolver order, per-load fakes,
   the `Function` behaviour, and one remaining limit below. `contracts/repair-v1.md` says
   `Function` still compiles.

The harness was 30,253 bytes against a 32 KiB budget (28,283 on `main`) when this branch was
written. Rebased onto `feat/families-weak-hash-cookie-flags`, whose `crypto` recorder and session
fakes take the merged file to 33,903 bytes, the budget is raised to 34 KiB (34,816 bytes).

## Tests

`tests/harness_spec.js` gained five cases, each run under plain `node`: an ES module evaluated
again on every load with that load's `env` and stubs, including a load that throws between two
that succeed; a CommonJS module still evaluated twice; an `.mjs` entry and a `.js`/`index.mjs`
import resolved without suffixes; a workspace path with a space, `#` and `%`; and a `depd`-like
package under `node_modules` that builds a wrapper with `new Function` at import, loaded from a
CommonJS and an ES module, with `noCode` clean, the subject's own `new Function` recorded and
working, and `Function` identity intact. Run against `main`'s harness the four behaviour cases fail
and the CommonJS one passes; against this branch all 23 pass on Node 22.21.1 and 24.1.0.

`tests/test_module_scope_sites.py` gained three: a named import from a repository module is a
config member, a named import from a package is not, and the ES module proof stubs the imported
name.

Five fixtures under `benchmarks/remediation/fixtures/`, each with a trusted `tests/verify.cjs` that
fails on the original and passes on the reviewed repair, checked by hand on Node 22.21.1 and
24.1.0 in exploit, behavior and compare modes:

| Fixture | Shape |
| --- | --- |
| `js-esm-express-sql` | Express route in an `.mjs` module, `express` and `pg` imported |
| `js-esm-module-scope-path` | A read at import of an `.mjs` module driven by `DOC_NAME`; the proof loads once per payload, so it depends on the fresh load |
| `js-esm-command-exec` | `exec` bound by a named import in a `.js` file Node reads as ESM by syntax |
| `js-esm-typescript-entry` | A `.ts` ES module entry with an extension-less relative import |
| `js-esm-module-scope-credential` | An exported module-scope secret in an `.mjs` module |

## Numbers

| Suite | Before (`main`) | After |
| --- | --- | --- |
| `harness_spec.js` | 18 pass | 23 pass |
| Remediation seed, reference adapter | 51 of 51 supported verified, 12 abstentions | 56 of 56, 12 abstentions |
| Remediation seed, engine-local adapter | 51 of 51 (46 executed, 5 static assertion) | 56 of 56 (51 executed, 5 static assertion) |

All five ES module fixtures verify under engine-local at `development_unverified`: the service's
own template and generated proof, run through the harness on both trees.

The corpus, measured with `scripts/replay/replay.py --pairs` over the 23 cached snapshot runs,
before on `main`'s service source (`REPLAY_REMEDIATION_ROOT`) and after on this branch, both with
an empty interpreter first on `PATH` and Node 22.21.1:

| | Before | After |
| --- | ---: | ---: |
| Supported-family findings whose file the snapshot carries | 281 | 281 |
| Findings the template builds a patch for | 62 | 62 |
| Findings the service writes a proof for | 16 | 16 |
| Findings with both halves | 8 | 8 |
| Pairs that verify end to end | 8 | **8** |
| `dependency_not_available_in_sandbox` | 84 | 84 |
| `module_scope_source_not_controllable` | 11 | 11 |

Every proof-side refusal reason has the same count on both sides. (The after run also counted the
static assertion columns, 54 assertable and 9 asserted, because the analysis service was
importable beside the branch's source and not beside the extracted copy of `main`; that is the
instrument, not this change, and it is not compared here.)

**The end-to-end count did not move, and it was not expected to.** In the shipping configuration
no ES module finding on this corpus reaches the proof generator at all: the loadability check
refuses it first, because its import closure reaches a package the sandbox does not have
(`@dicebear`, `@angular`, `js-yaml`, `mongoose` and the rest of the 84). Every gap this branch
closes sits behind that refusal. What moved is the ceiling: an ES module whose closure the
sandbox can load is now driven by the same proofs a CommonJS module is, including module-scope
proofs that load more than once, and the fixtures hold that.

## The new ceiling

1. **Dependencies, unchanged.** 84 proofs refused as `dependency_not_available_in_sandbox`.
   Installing them was measured and decided against (`pairs-2026-09.md`, "With dependencies
   installed": 8 verified before and after) and is not reopened here.
2. **A root `"type": "module"`.** The harness and the generated tests are CommonJS `.js` files under
   `.mitig8it/`, so in a repository whose root `package.json` declares `"type": "module"` Node
   reads both as ES modules and every Node proof fails on both trees. None of the 23 corpus
   repositories declares it at the root, so it costs nothing measured today. The fix is a
   `.mitig8it/package.json` of `{ "type": "commonjs" }` materialized beside the harness, which
   touches the harness materialization in every driver and the protected-path policy; it was left
   for its own change.
3. **`eval` from a dependency.** A package that builds a wrapper with direct `eval` (older `depd`)
   still gets the recorder, which runs nothing. Not observed on the corpus.
4. **`AsyncFunction` and `GeneratorFunction`** constructors reach the real compiler unrecorded, as
   before.

## Reproducing this

```sh
PY=~/.pyenv/versions/3.11.6/bin/python
VENV=.venv/remediation/bin/python          # or make deps
export PATH=/opt/homebrew/opt/node@22/bin:$PATH

node --test-reporter=tap services/remediation-service/tests/harness_spec.js
make test-remediation test-harness
make bench-remediation-reference bench-remediation-engine-local

# the corpus, with a snapshot cache and its result files (see pairs-2026-09.md for building them)
$PY -m venv /tmp/empty
git archive origin/main services/remediation-service | tar -x -C /tmp/base
PATH=/tmp/empty/bin:$PATH REPLAY_REMEDIATION_ROOT=/tmp/base/services/remediation-service \
  $VENV scripts/replay/replay.py --pairs --cache scripts/replay/.cache \
  --results scripts/replay/results/*.json --python $VENV --out /tmp/pairs-before.json
PATH=/tmp/empty/bin:$PATH \
  $VENV scripts/replay/replay.py --pairs --cache scripts/replay/.cache \
  --results scripts/replay/results/*.json --python $VENV --out /tmp/pairs-after.json
$PY scripts/replay/summarize.py --pairs /tmp/pairs-after.json
```
