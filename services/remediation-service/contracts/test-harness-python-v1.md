# Sandbox test harness v1 for Python

The repair sandbox has no network and no installed packages. A generated regression test that
imports `flask`, `pytest`, `requests`, or a database driver crashes with `ModuleNotFoundError`
on both trees and proves nothing. For Python findings the service therefore materializes one
standard-library-only file, `.mitig8it/harness.py`, next to the generated tests in both the
baseline and the candidate workspace. It is evidence infrastructure, not part of the repair: it
is never a patch, never a manifest entry, and a proposal that writes to it is rejected as
`harness_path_protected`.

Source: `services/remediation-service/src/sandbox/harness_py.py` (Python 3.9 or later, standard
library only, under 40 KB). The Node harness for JavaScript findings is described in
[test-harness-v1.md](test-harness-v1.md); a finding group is one language, so a test uses one.

## How a test runs

The verifier runs a Python regression test as a fixed argv:

```
python3 .mitig8it/harness.py .mitig8it/regression/<finding-id>.test.py
```

The harness is also the runner: it registers itself as the `harness` module, puts the test's
directory on `sys.path`, and executes the test as `__main__`. The test therefore needs no
`sys.path` preamble and starts with `import harness as h`. The test must fail on the original
code and pass on the repaired code to prove its finding; `h.run` exits 0 when the body returns
and 1 with the traceback otherwise.

## Shape of a test

```python
import harness as h


def body():
    m = h.load("services/orders.py", env={"API_KEY": "from-env"})
    bad = "1' OR '1'='1"
    h.invoke(m.app, "GET", "/orders/<id>", params={"id": bad})
    h.assert_param(h.db.queries[0], bad)


h.run(body)
```

## API

`h.load(target, stubs=None, real=(), env=None, argv=None, rows=None, stdout="", stderr="", code=0, content="", exists=True, auto_stub=True)`
executes the repository module at `target` (a repository path such as `services/orders.py`,
resolved from the repository root, or an absolute path) with the fakes below installed, and
returns the module object. Each call resets every recorder and re-executes the module. The
module's directory and the repository root are put on `sys.path`, so sibling imports resolve.

- `env`: values set in `os.environ` before the module runs; reads are recorded in `h.env.reads`. A literal name the module reads with `os.environ["NAME"]` that the test did not set gets the placeholder `mitig8it-unset-NAME`, so a patch that moved one secret to the environment does not crash every other test of the same patch at import; `os.environ.get` keeps its real semantics.
- `argv`: `sys.argv` for this load only, restored to the test process's own on the next load that does not supply one. It is for a module that reads its input from the command line at import, where there is no function to pass an argument to.
- `rows`: what every query's `fetchone`/`fetchall` returns (a list, or a callable of the recorded query).
- `stdout`, `stderr`, `code`: what every faked process reports.
- `content`, `exists`: what `open()` returns (a string, bytes, or a callable of the path) and whether the path exists (a boolean or a callable); a missing file raises `FileNotFoundError`.
- `stubs`: `{"module.name": object}` to inject by exact import name; a dict or object becomes a module.
- `real`: names from `flask`, `sqlite3`, `psycopg2`, `psycopg`, `sqlalchemy`, `subprocess`, `os.system`, `open` to leave real.
- `auto_stub`: any other third-party import the sandbox cannot resolve (for example `lxml`) is replaced by a permissive stub module whose attributes are callable no-ops; the names are recorded in `h.stubbed`.

`h.invoke(app, method, rule, params=None, query=None, json=None, form=None, data=None, headers=None)`
finds the view the module registered with `@app.route` (or `add_url_rule`, `app.get`, a
`Blueprint`) for `method` and `rule` (a rule such as `/orders/<id>` with `params`, or a concrete
path whose `<name>` segments are extracted; `<int:name>` converts), fills `flask.request`
(`args`, `form`, `values`, `json`, `data`, `headers`, `method`, `path`), calls the view, and
returns a `Response` with `status_code`, `body`, `headers`, and `get_json()`. A view that
returns a string, dict, tuple `(body, status[, headers])`, or `Response` is normalized;
`abort(code)` becomes a response with that status. Any other exception propagates and fails
the test.

`h.call(fn, *args, **kwargs)` calls a plain function and never raises: it returns a `Call`
with `value`, `error`, `ok`, and `raised(ExceptionType)`.

Fakes and their recorders:

- `flask`: `Flask`, `Blueprint`, `request`, `jsonify`, `abort`, `redirect`, `make_response`, `Response`, `render_template` (returns `template:<name>`), `send_file` and `send_from_directory` (which open the file through the recorded `open()`), `url_for`, `g`, `session`. Routes are recorded in `h.flask.routes` as `{rule, methods, view, endpoint}`; `app.run()` is a no-op.
- `sqlite3`, `psycopg2`, `psycopg`, `pymysql`: `connect()` returns a connection whose `cursor()`, `execute(sql, params)`, `executemany`, and `executescript` record `{api, sql, params}` in `h.db.queries` and return the configured rows. `psycopg2.sql.SQL/Identifier/Literal/Placeholder` compose to text; `psycopg2.extras` cursor classes are the same recording cursor.
- `sqlalchemy`: `text(sql)` keeps its text and `bindparams`; `create_engine().connect()` (or `begin()`) returns a connection whose `execute(statement, params)` records `{api: "sqlalchemy", sql, params}`.
- `subprocess`: `run`, `call`, `check_call`, `check_output`, `Popen`, `getoutput`, and `getstatusoutput` record `{fn, args, shell, command, options}` in `h.subprocess.calls` (`args` is the argv list, or `None` when a single command string was passed; `shell` is true for a string command or `shell=True`), then report the configured stdout, stderr, and exit code. `os.system` and `os.popen` record with `fn` `os.system`/`os.popen` and `shell` true, without running anything.
- `os.environ`: a recording mapping; every `[]`, `.get`, `in`, and `os.getenv` read appends the key to `h.env.reads`.
- `open()` (also `io.open`): a read records `{path, resolved, mode}` in `h.fs.reads`, `resolved` being `os.path.realpath` of the path, and returns the configured content as a text or bytes file; a write records in `h.fs.writes` and returns an in-memory buffer. Imports and the harness itself use the real `open`.

Assertions (each raises `HarnessAssertion` with the message on failure):

- `h.assert_true(condition, message)`, `h.assert_equal(actual, expected, message)`
- `h.assert_includes(text, needle, message)`, `h.assert_not_includes(text, needle, message)`
- `h.assert_param(query, payload, message)`: the recorded query's `sql` does not contain the payload and its `params` (tuple, list, or dict, flattened) does.
- `h.assert_argv(call, payload, message)`: the recorded process call has no shell (`shell` false and `args` a list) and the payload is its own `args` element.
- `h.assert_inside(reads, base, payload=None, message=None)`: `reads` is an `h.fs.reads` entry, a path, or the whole `h.fs.reads` list; every resolved path stays strictly under `base`. With `payload`, an input that escapes the base (a `..` segment or an absolute path, as sent or once percent-decoded) additionally requires that no read was recorded at all, so the view must have rejected it before touching the filesystem.
- `h.assert_env_read(name, message)`: the module read environment variable `name`.
- `h.assert_not_in_source(module, literal, message)`: the module's source text does not contain the literal and no module-level string value carries it.
- `h.assert_no_commands(message)`: no process call was recorded (`subprocess`, `os.system`, `os.popen`).
- `h.fail(message)` fails outright.

`h.ROOT` is the repository root the harness was materialized in.

## What to assert per family

- SQL injection (`sql_parameterization`): `h.assert_param(h.db.queries[0], payload)`. The repair passes the value as a bound parameter with the driver's placeholder: `?` for sqlite3, `%s` for psycopg/psycopg2, `:name` with a dict for SQLAlchemy `text()`. A query handed to a helper whose placeholder syntax the snapshot does not show is not repaired: the engine skips it as `ambiguous_query_api`, and the agent abstains with the same reason if it only discovers this while reading.
- Hardcoded credential (`hardcoded_credential`): `m = h.load(path, env={"NAME": "from-env"})`, then `h.assert_equal(m.NAME, "from-env")`, `h.assert_env_read("NAME")`, and `h.assert_not_in_source(m, literal)`. The repair replaces the literal with `os.environ["NAME"]` (or `os.environ.get("NAME")` when the code tolerates an absent value), adds `import os` if missing, and the candidate records the limitation `<path> now reads NAME from the environment; the deployment must provide it`. A literal that is a default the code has to keep is not repaired (`credential_default_not_preservable`).
- Code injection through `eval` (`code_injection_eval`): with `FUNC` the function at the finding, `h.call(m.FUNC, "__import__('os').system('id')")` then `h.assert_no_commands()`, and `h.assert_equal(h.call(m.FUNC, "[1, 2]").value, [1, 2])`. The repair replaces `eval(x)` with `ast.literal_eval(x)` plus `import ast` when the surrounding code only needs a literal; code that evaluates expressions, names, or calls is not repaired (`eval_semantics_unknown`).
- Command injection (`command_arguments`): `h.assert_argv(h.subprocess.calls[0], payload)`. The repair passes an argv list with `shell=False` and the untrusted value as its own element; a command line with a pipe is skipped as `shell_pipeline_unsupported`.
- Path traversal (`path_containment`): for each traversal payload (`../../etc/passwd` and `..%2f..%2fetc%2fpasswd`), `h.fs.reads.clear()`, invoke the view, and `h.assert_inside(h.fs.reads, base, payload=payload)`; then one legitimate name and `h.assert_inside(h.fs.reads, base)`. The repair resolves `os.path.realpath(os.path.join(base, name))` and answers 400 before any file access unless the result is `base` or starts with `base + os.sep`.

## Policy

A Python regression test may import only the standard library, modules the snapshot itself
provides, and `harness`. Any other name is rejected as `missing_dependency:<name>` with guidance
naming the harness. A test that calls `open()` (or `read_text`/`read_bytes`) without loading a
repository module through `h.load` or an import is rejected as `regression_test_reads_source_as_text`.
The test file must be `.mitig8it/regression/<name>.test.py`; it is compiled with `py_compile`
before it is accepted. The harness is added to the sandbox payload's file list only when the
candidate carries Python tests, and is left out with the limitation
`the repository already carries .mitig8it/harness.py, so the service Python test harness was not materialized`
when the snapshot occupies that path.

Every changed `.py` file is also compiled with `python3 -m py_compile` in the sandbox (a
`typecheck` check) and loaded once in the service with `runpy.run_path` under a module name
that is not `__main__`. A missing third-party import or an environment variable the module reads
at import time is recorded as a limitation (`runtime load check skipped for <path>: ...`); any
other exception rejects the candidate as `candidate_load_failed`.
