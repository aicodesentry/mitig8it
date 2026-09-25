"""Service-generated regression tests: one deterministic proof per supported finding.

The model used to write both the patch and the test that proved it, and the test was the flaky
half: a proof that never reached the vulnerable path, asserted on wording, or timed out left a
real fix unproven. Each generator here derives the enclosing route or function from the exact
snapshot (`sites.py`) and emits a harness test that invokes it with an injection payload and
asserts the family's contract through the harness recorders. The test is generated before any
model call and handed to the model as the proof its patch must satisfy.

A generator that cannot derive the site returns the reason instead of a test, and the engine
falls back to the model-written test for that finding, recording why.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .families import (
    CODE_INJECTION_EVAL,
    COMMAND_ARGUMENTS,
    HARDCODED_CREDENTIAL,
    JAVASCRIPT,
    PATH_CONTAINMENT,
    PYTHON,
    SQL_PARAMETERIZATION,
)
from .gates import PYTHON_SQL_DRIVERS, python_imports
from .models import FindingSnapshot
from .patches import GENERATED_TEST_DIRECTORY
from .retrieval import Snapshot
from .sites import (
    JS_CALLBACK_PARAMETERS,
    JsFunction,
    JsParameter,
    JsRoute,
    ModuleScope,
    PyFunction,
    SiteError,
    js_environment_name,
    js_eval_site,
    js_literal_assignment,
    js_literal_assignment_in_span,
    js_module_binding,
    js_module_constant,
    js_module_exports_name,
    js_path_site_in_scope,
    js_site_for_line,
    module_directory,
    python_flask_app_name,
    python_site_for_line,
    python_module_assignment,
    python_module_value,
    scope_lines_near,
)

SQL_PAYLOAD = "1' OR '1'='1"
COMMAND_PAYLOAD = "x; rm -rf /"
TRAVERSAL_PAYLOADS = ("../../etc/passwd", "..%2f..%2fetc%2fpasswd")
# A function called directly receives its argument as written: nothing percent-decodes it, so the
# encoded payload above is a route-level concern and a correct helper rightly does not refuse it.
# An absolute path takes its place, because `path.resolve` and `os.path.join` discard the base for
# one, which is the other way a name leaves the directory it was supposed to stay in.
DIRECT_TRAVERSAL_PAYLOADS = ("../../etc/passwd", "/etc/passwd")
LEGITIMATE_NAME = "report.txt"
EVAL_PAYLOAD = "__import__('os').system('id')"
JS_EVAL_PAYLOAD = "require('node:child_process').execSync('id')"
# A JSON document the repaired parser must still accept, and its exact re-serialization.
JS_EVAL_DOCUMENT = "[1, 2]"
JS_EVAL_DOCUMENT_JSON = "[1,2]"
ENV_VALUE = "value-from-env"
BENIGN_VALUE = "sample"
# Parameter names that stand for a database handle rather than untrusted input.
CONNECTION_PARAMETERS = frozenset({"conn", "connection", "db", "database", "engine", "session"})
# The same idea on the JavaScript side, plus the names a pg handle is bound to.
JS_CONNECTION_PARAMETERS = frozenset({"conn", "connection", "db", "database", "pool", "client", "pg"})
# Parameters a generated call fills with a value that cannot change what is asserted.
JS_IGNORED_PARAMETERS = frozenset({"next", "callback", "cb", "done", "options", "opts"})
CURSOR_PARAMETERS = frozenset({"cursor", "cur"})
_SQL_SINK_RE = re.compile(r"\.(?:execute|executemany|exec_driver_sql)\s*\(|\bquery\s*\(")
_JS_INLINE_SQL_RE = re.compile(r"\.query\s*\(")


@dataclass(frozen=True)
class GeneratedProof:
    finding_id: str
    family: str
    language: str
    path: str
    content: str
    # What the test exercises, for the evidence and the model's task message.
    description: str
    site: JsRoute | JsFunction | PyFunction | ModuleScope | None = None

    def spec(self) -> dict[str, str]:
        return {"finding_id": self.finding_id, "path": self.path, "content": self.content}


@dataclass(frozen=True)
class ProofFallback:
    finding_id: str
    family: str
    reason: str


def _js(value: Any) -> str:
    return json.dumps(value)


def _py(value: Any) -> str:
    return json.dumps(value)


def _safe_name(finding_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", finding_id).strip("-.") or "finding"


def test_path(finding_id: str, language: str) -> str:
    return f"{GENERATED_TEST_DIRECTORY}/{_safe_name(finding_id)}.test.{'py' if language == PYTHON else 'js'}"


def _finding_line(finding: FindingSnapshot) -> int:
    return max(1, int(finding.line_start or 1))


# --- JavaScript -----------------------------------------------------------------------------

def _js_invoke_options(route: JsRoute, untrusted: str | None, payload: str) -> str:
    """The `h.invoke` options object: the payload on the untrusted input, benign values elsewhere."""
    groups: dict[str, dict[str, str]] = {}
    for item in route.inputs:
        value = payload if item.expression == untrusted else BENIGN_VALUE
        groups.setdefault(item.source, {})[item.name] = value
    parts = []
    for source in ("params", "query", "body"):
        if source in groups:
            inner = ", ".join(f"{_js(name)}: {_js(value)}" for name, value in groups[source].items())
            parts.append(f"{source}: {{ {inner} }}")
    return "{ " + ", ".join(parts) + " }" if parts else "{}"


def _js_untrusted_for(route: JsRoute, source_lines: list[str], sink_line: int, window_start: int) -> str | None:
    """The request input that reaches the sink: one used on the sink line, else the nearest earlier one."""
    for candidate_line in range(sink_line, window_start - 1, -1):
        used = [item for item in route.inputs if item.line == candidate_line]
        if used:
            return used[0].expression
    return route.inputs[0].expression if route.inputs else None


def _js_header(path: str) -> list[str]:
    return [
        "const h = require('../harness');",
        "const path = require('node:path');",
        "h.run(async () => {",
        f"  const app = h.load({_js(path)});",
    ]


def _js_module_header(path: str) -> list[str]:
    """The header for a proof that calls an exported function instead of driving a route."""
    return [
        "const h = require('../harness');",
        "h.run(async () => {",
        f"  const m = h.load({_js(path)});",
    ]


def _js_untrusted_parameter(function: JsFunction, lines: list[str], sink_line: int) -> str | None:
    """The parameter used nearest the sink, ignoring the ones that stand for a handle.

    A helper's untrusted input is an argument, not a `req.*` read, so the proof has to decide
    which argument carries it. The one named on the sink line, or on the assignment feeding it,
    is that argument; a function whose only parameters are a connection and a callback has none.
    """
    rest = {name for parameter in function.parameter_model if parameter.rest for name in parameter.bound_names}
    candidates = [
        name for name in function.parameters
        if name not in JS_CONNECTION_PARAMETERS and name not in JS_IGNORED_PARAMETERS and name not in rest
    ]
    if not candidates:
        return None
    for number in range(min(sink_line, function.end_line), function.start_line - 1, -1):
        text = lines[number - 1]
        for parameter in candidates:
            if re.search(rf"(?<![\w$.]){re.escape(parameter)}(?![\w$])", text):
                return parameter
    return candidates[-1]


def _js_call_arguments_for(function: JsFunction, untrusted: str, needs_connection: bool) -> tuple[str, list[str]]:
    """`(argument list, setup lines)` for calling `function` with the payload in place.

    Every parameter that is not the untrusted one gets a value that cannot change what the
    assertion observes: a pg handle where the name says the function expects one, a no-op
    function where it expects a callback, and an empty object everywhere else.
    """
    setup: list[str] = []
    arguments: list[str] = []
    for parameter in function.parameter_model or tuple(JsParameter(name, name) for name in function.parameters):
        if parameter.rest:
            # A rest element takes whatever arguments are left, so the call passes it none: an
            # extra argument would change the array the function sees.
            continue
        if parameter.members:
            # A destructured parameter binds no name, so the payload goes in the member the body
            # reads. `{ id }` from a request becomes `{ id: payload }`.
            fields = ", ".join(
                f"{member}: " + ("payload" if member == untrusted else _js(BENIGN_VALUE))
                for member in parameter.members
            )
            arguments.append("{ " + fields + " }")
        elif parameter.name == untrusted:
            arguments.append("payload")
        elif parameter.name in JS_CONNECTION_PARAMETERS and needs_connection:
            # `h.db()`, not `require('pg')`: nothing is installed in the sandbox and the patch
            # policy refuses a regression test that asks for a package.
            arguments.append("h.db()")
        elif parameter.name in ("cb", "callback", "done", "next"):
            arguments.append("() => {}")
        else:
            arguments.append("{}")
    return ", ".join(arguments), list(dict.fromkeys(setup))


def _js_handler_untrusted(function: JsFunction, sink_line: int) -> str | None:
    """The request input a handler-shaped function reads nearest its sink."""
    for number in range(min(sink_line, function.end_line), function.start_line - 1, -1):
        used = [item for item in function.inputs if item.line == number]
        if used:
            return used[0].expression
    return function.inputs[0].expression if function.inputs else None


def _js_handler_request(function: JsFunction, untrusted: str, payload: str) -> str:
    """The `req` a proof builds for a route handler the module never registered with Express."""
    groups: dict[str, dict[str, str]] = {}
    for item in function.inputs:
        groups.setdefault(item.source, {})[item.name] = payload if item.expression == untrusted else _js(BENIGN_VALUE)
    parts = [
        f"{source}: {{ " + ", ".join(f"{_js(name)}: {value}" for name, value in fields.items()) + " }"
        for source, fields in groups.items()
    ]
    return "{ " + ", ".join(parts) + " }"


def _js_handler_drive(function: JsFunction, untrusted: str, payload: str) -> list[str]:
    """Calls a handler-shaped function with a request and a recording response.

    It is an Express handler the snapshot never shows registered, so there is no route to
    invoke: the proof builds the request itself and reads the status off `res.out`, which is
    the same thing `h.invoke` would have resolved.
    """
    request = _js_handler_request(function, untrusted, payload)
    extra = "".join(", {}" for _ in (function.parameter_model or function.parameters)[2:])
    return [
        "  const res = h.res();",
        f"  const called = h.call(m.{function.name}, {request}, res{extra});",
        "  await Promise.resolve(called.value).catch(() => {});",
    ]


def _js_function_call(function: JsFunction, arguments: str) -> list[str]:
    """The call and the await that lets an async function finish before anything is asserted.

    `h.call` never throws and never awaits, so a function that returns a promise would be
    asserted on before its query ran. `Promise.resolve` over a plain value is a no-op, so the
    same two lines are correct whether or not the function is async.
    """
    return [
        f"  const called = h.call(m.{function.name}, {arguments});",
        "  await Promise.resolve(called.value).catch(() => {});",
    ]


# The suffixes the sandbox's `node` can run. Plain JavaScript runs as written; TypeScript runs
# through Node's own type stripper, which the verifier turns on for every generated test
# (`verification.checks.NODE_TYPESCRIPT_FLAGS`). Nothing is installed in the sandbox and nothing
# compiles there, so `.jsx` and `.tsx` stay out: strip-only mode deletes type syntax and does not
# transform JSX, and a proof that cannot parse its own module proves nothing.
NODE_LOADABLE_SUFFIXES = (".js", ".cjs", ".mjs")
TYPESCRIPT_SUFFIXES = (".ts", ".cts", ".mts")
# What strip-only mode refuses outright, because each one has to emit code rather than delete
# text. Node reports these as ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX; matching them here turns that
# into a refusal with a reason instead of a sandbox run that was never going to load.
_TS_UNSTRIPPABLE = (
    (re.compile(r"^[ \t]*(?:export[ \t]+)?(?:declare[ \t]+)?(?:const[ \t]+)?enum[ \t]+[\w$]+", re.M), "enum"),
    (re.compile(r"^[ \t]*(?:export[ \t]+)?(?:declare[ \t]+)?(?:namespace|module)[ \t]+[\w$.]+[ \t]*\{", re.M), "namespace"),
    (re.compile(r"constructor\s*\([^)]*(?<![\w$])(?:public|private|protected|readonly)\s+[\w$]+"), "parameter_property"),
)


# Everything the sandbox can supply at load time. The harness fakes the first set and Node
# supplies the second; there is no network and no `node_modules`, so a module that reaches
# anything else while it is being imported does not load, on the repaired tree exactly as on the
# vulnerable one. `contracts/test-harness-v1.md` is the source of the fake list.
HARNESS_FAKED_MODULES = frozenset({"express", "pg", "child_process", "fs", "fs/promises", "vm"})
NODE_BUILTIN_MODULES = frozenset(
    """assert assert/strict async_hooks buffer child_process cluster console constants crypto dgram
    diagnostics_channel dns dns/promises domain events fs fs/promises http http2 https inspector
    inspector/promises module net os path path/posix path/win32 perf_hooks process punycode
    querystring readline readline/promises repl stream stream/consumers stream/promises stream/web
    string_decoder test test/mock_loader timers timers/promises tls trace_events tty url util
    util/types v8 vm wasi worker_threads zlib sqlite""".split()
)
# What a module pulls in *while it is being imported*: every static `import`, and a `require`
# whose statement begins at column 0. A `require` inside a function body is indented and runs
# only when that function is called, which a proof may never do, so counting it would refuse
# modules that load perfectly well. The heuristic therefore errs toward attempting.
_JS_STATIC_IMPORT_RE = re.compile(r"""^[ \t]*(?:import|export)\b[^;\n]*?from\s*['"]([^'"]+)['"]|^[ \t]*import\s*['"]([^'"]+)['"]""", re.M)
_JS_LOAD_TIME_REQUIRE_RE = re.compile(r"""^(?=\S)[^\n]*?\brequire\(\s*['"]([^'"]+)['"]\s*\)""", re.M)
# A proof's module graph is walked once; a repository with a cycle or a very wide import fan-out
# still costs a bounded number of reads.
MAX_WALKED_MODULES = 200


def _js_specifiers(source: str) -> list[str]:
    found: list[str] = []
    for match in _JS_STATIC_IMPORT_RE.finditer(source):
        found.append(next(group for group in match.groups() if group))
    found.extend(match.group(1) for match in _JS_LOAD_TIME_REQUIRE_RE.finditer(source))
    return found


def _js_resolve(snapshot: Snapshot, from_path: str, specifier: str) -> str | None:
    """The snapshot path a relative specifier names, by the rules the harness resolves it with."""
    base = PurePosixPath(PurePosixPath(from_path).parent / specifier)
    parts: list[str] = []
    for part in base.parts:
        if part == "..":
            if not parts:
                return None
            parts.pop()
        elif part != ".":
            parts.append(part)
    stem = "/".join(parts)
    candidates = [stem]
    written = re.search(r"\.([cm]?)js$", stem)
    if written:
        # `./config.js` is how a TypeScript project under NodeNext writes an import of config.ts.
        candidates.insert(0, stem[: -len(written.group(0))] + "." + written.group(1) + "ts")
    candidates += [stem + suffix for suffix in (*TYPESCRIPT_SUFFIXES, *NODE_LOADABLE_SUFFIXES)]
    candidates += [stem + "/index" + suffix for suffix in (*TYPESCRIPT_SUFFIXES, *NODE_LOADABLE_SUFFIXES)]
    paths = set(snapshot.paths)
    return next((candidate for candidate in candidates if candidate in paths), None)


def _js_loadable(snapshot: Snapshot, path: str) -> None:
    """Raises unless the sandbox's `node` can load the module a generated proof has to load.

    The subject is not the only file that has to load: importing it imports everything it names
    at load time, and a failure anywhere in that closure is a proof that fails identically on
    both trees. Those are the failures this refuses in advance, with the module that caused them
    named. A relative import the snapshot does not carry is not inspected and not refused: the
    snapshot is a budgeted slice of the tree, so absence there says nothing about the repository.
    """
    pending = [path]
    seen: set[str] = set()
    while pending and len(seen) < MAX_WALKED_MODULES:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current.endswith(TYPESCRIPT_SUFFIXES):
            for pattern, construct in _TS_UNSTRIPPABLE:
                if pattern.search(snapshot.full_content(current)):
                    raise SiteError(f"typescript_syntax_not_strippable:{construct}")
        elif not current.endswith(NODE_LOADABLE_SUFFIXES):
            raise SiteError("module_not_loadable_by_node")
        for specifier in _js_specifiers(snapshot.full_content(current)):
            if specifier.startswith("."):
                found = _js_resolve(snapshot, current, specifier)
                if found is not None:
                    pending.append(found)
                continue
            name = specifier[5:] if specifier.startswith("node:") else specifier
            if name in NODE_BUILTIN_MODULES or name in HARNESS_FAKED_MODULES:
                continue
            raise SiteError(f"dependency_not_available_in_sandbox:{name.split('/')[0]}")


# The calls the harness records for each family. A generated proof asserts on those recorders, so
# the scope it drives has to contain one: a builder that returns a query object or an argv array
# without running it is a real finding, but nothing the harness observes changes when it is
# repaired, and a proof that cannot fail on the original code would sink the candidate instead of
# proving it. The model writes that test, against the caller it can read.
_JS_COMMAND_SINK_RE = re.compile(r"(?<![\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|\.(?:exec|execSync|spawn|spawnSync)\s*\(")


def _js_sink_in_scope(lines: list[str], function: JsFunction, pattern: re.Pattern[str], code: str) -> None:
    """Raises unless the function's own body carries the call the family's assertion watches."""
    body = "\n".join(lines[function.start_line - 1 : function.end_line])
    if not pattern.search(body):
        raise SiteError(code)


def _js_callable(source: str, function: JsFunction) -> None:
    """Raises unless a generated test can reach `function` as `m.<name>`."""
    if function.kind == "method":
        raise SiteError("method_receiver_not_supported")
    if not js_module_exports_name(source, function.name):
        raise SiteError("function_not_exported")


def _js_base_expression(source: str, path: str, base: str) -> str | None:
    """The served directory as the test can compute it, or None when it is not derivable."""
    value = base.strip()
    definition = js_module_constant(source, value) if re.fullmatch(r"[\w$]+", value) else value
    if definition is None:
        return None
    definition = definition.strip()
    if re.fullmatch(r"(['\"])(?:(?!\1).)*\1", definition):
        return definition
    directory = module_directory(path)
    module_dir = f"path.join(h.root, {_js(directory)})" if directory else "h.root"
    if "__dirname" in definition and re.fullmatch(r"path\.(?:join|resolve)\((?:__dirname|['\"][^'\"]*['\"])(?:\s*,\s*(?:__dirname|['\"][^'\"]*['\"]))*\)", definition):
        return definition.replace("__dirname", module_dir)
    if definition == "__dirname":
        return module_dir
    return None


_JS_QUERY_ASSERTIONS = [
    "  const q = h.pg.queries[0];",
    "  h.assert(q, 'expected one pg query to be run');",
    "  h.assert.notIncludes(q.text, payload);",
    "  h.assert.includes(JSON.stringify(q.values || []), payload);",
    "});",
    "",
]


def _js_sql_proof(snapshot: Snapshot, finding: FindingSnapshot, site: JsRoute | JsFunction) -> GeneratedProof:
    """The test a JavaScript SQL repair has to satisfy, driven however the site is reachable.

    A route is driven through `h.invoke`; a helper is called directly. The assertions are the
    same either way, because what is being proven is a property of the query the module built,
    not of how it was reached.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    if isinstance(site, JsRoute):
        untrusted = _js_untrusted_for(site, lines, line, site.start_line)
        if untrusted is None:
            raise SiteError("no_request_input_in_route")
        drive = [f"  await h.invoke(app, {_js(site.method)}, {_js(site.route)}, {_js_invoke_options(site, untrusted, SQL_PAYLOAD)});"]
        head = _js_header(path) + [f"  const payload = {_js(SQL_PAYLOAD)};"]
        what = f"{site.method.upper()} {site.route} with {untrusted}"
    elif site.kind == "handler":
        _js_callable(source, site)
        _js_sink_in_scope(lines, site, _JS_INLINE_SQL_RE, "sql_sink_not_in_scope")
        untrusted = _js_handler_untrusted(site, line)
        if untrusted is None:
            raise SiteError("no_request_input_in_route")
        head = _js_module_header(path) + [f"  const payload = {_js(SQL_PAYLOAD)};"]
        drive = _js_handler_drive(site, untrusted, "payload")
        what = f"{site.name}(req) with {untrusted}"
    else:
        _js_callable(source, site)
        _js_sink_in_scope(lines, site, _JS_INLINE_SQL_RE, "sql_sink_not_in_scope")
        untrusted = _js_untrusted_parameter(site, lines, line)
        if untrusted is None:
            raise SiteError("no_untrusted_parameter")
        arguments, setup = _js_call_arguments_for(site, untrusted, needs_connection=True)
        head = _js_module_header(path) + setup + [f"  const payload = {_js(SQL_PAYLOAD)};"]
        drive = _js_function_call(site, arguments)
        what = f"{site.name}({untrusted})"
    return GeneratedProof(
        finding.stable_id, SQL_PARAMETERIZATION, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT),
        "\n".join(head + drive + _JS_QUERY_ASSERTIONS),
        f"{what} = {SQL_PAYLOAD!r}: the query text must not carry the payload and the values must",
        site,
    )


_JS_ARGV_ASSERTIONS = [
    "  h.assert(h.child_process.calls.length > 0, 'expected one child process to be started');",
    "  h.assert.argv(h.child_process.calls[0], payload);",
    "});",
    "",
]


def _js_command_proof(snapshot: Snapshot, finding: FindingSnapshot, site: JsRoute | JsFunction) -> GeneratedProof:
    """The test a JavaScript command repair has to satisfy, driven however the site is reachable."""
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    if isinstance(site, JsRoute):
        untrusted = _js_untrusted_for(site, lines, line, site.start_line)
        if untrusted is None:
            raise SiteError("no_request_input_in_route")
        head = _js_header(path) + [f"  const payload = {_js(COMMAND_PAYLOAD)};"]
        drive = [f"  await h.invoke(app, {_js(site.method)}, {_js(site.route)}, {_js_invoke_options(site, untrusted, COMMAND_PAYLOAD)});"]
        what = f"{site.method.upper()} {site.route} with {untrusted}"
    elif site.kind == "handler":
        _js_callable(source, site)
        _js_sink_in_scope(lines, site, _JS_COMMAND_SINK_RE, "command_sink_not_in_scope")
        untrusted = _js_handler_untrusted(site, line)
        if untrusted is None:
            raise SiteError("no_request_input_in_route")
        head = _js_module_header(path) + [f"  const payload = {_js(COMMAND_PAYLOAD)};"]
        drive = _js_handler_drive(site, untrusted, "payload")
        what = f"{site.name}(req) with {untrusted}"
    else:
        _js_callable(source, site)
        _js_sink_in_scope(lines, site, _JS_COMMAND_SINK_RE, "command_sink_not_in_scope")
        untrusted = _js_untrusted_parameter(site, lines, line)
        if untrusted is None:
            raise SiteError("no_untrusted_parameter")
        arguments, setup = _js_call_arguments_for(site, untrusted, needs_connection=False)
        head = _js_module_header(path) + setup + [f"  const payload = {_js(COMMAND_PAYLOAD)};"]
        drive = _js_function_call(site, arguments)
        what = f"{site.name}({untrusted})"
    return GeneratedProof(
        finding.stable_id, COMMAND_ARGUMENTS, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT),
        "\n".join(head + drive + _JS_ARGV_ASSERTIONS),
        f"{what} = {COMMAND_PAYLOAD!r}: the child must run with an argument array and the payload as its own element",
        site,
    )


def _js_traversal_function_proof(
    snapshot: Snapshot, finding: FindingSnapshot, function: JsFunction, join: tuple[int, str, str], base: str | None
) -> GeneratedProof:
    """The plain-function half of `_js_traversal_proof`: the call must refuse a traversal.

    How it refuses depends on the signature. A function that takes a callback reports the
    refusal through it, which is the contract its caller already has; one that does not has
    nothing to report through and throws, where a returned sentinel would be indistinguishable
    from a path. The proof accepts either, because both are refusals and neither is the thing
    being proven: what is proven is that nothing was read. The benign call is what stops a
    repair that simply refuses every input.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    _js_callable(source, function)
    untrusted = _js_untrusted_parameter(function, lines, join[0])
    if untrusted is None:
        raise SiteError("no_untrusted_parameter")
    attack, _ = _js_call_arguments_for(function, untrusted, needs_connection=False)
    callback = next((name for name in function.parameters if name in JS_CALLBACK_PARAMETERS), None)
    attack = attack.replace("() => {}", "(error) => { reported = error; }", 1) if callback else attack
    refused_ok = "!refused.ok || reported instanceof Error" if callback else "!refused.ok"
    allowed_ok = "allowed.ok && !(reported instanceof Error)" if callback else "allowed.ok"
    body = _js_module_header(path) + ([
        "  let reported = null;",
    ] if callback else []) + [
        f"  const base = {base or 'h.root'};",
        f"  for (const payload of {_js(list(DIRECT_TRAVERSAL_PAYLOADS))}) {{",
        "    h.fs.reads.length = 0;",
        *(["    reported = null;"] if callback else []),
        f"    const refused = h.call(m.{function.name}, {attack});",
        f"    h.assert({refused_ok}, `expected ${{JSON.stringify(payload)}} to be refused, got ${{JSON.stringify(refused.value)}}`);",
        "    h.assert.inside(h.fs.reads, base, { payload });",
        "  }",
        "  h.fs.reads.length = 0;",
        *(["  reported = null;"] if callback else []),
        f"  const payload = {_js(LEGITIMATE_NAME)};",
        f"  const allowed = h.call(m.{function.name}, {attack});",
        f"  h.assert({allowed_ok}, 'expected a legitimate name to still resolve');",
    ]
    if base:
        # What the call returns depends on the helper: a resolver hands back the path, a reader
        # hands back the file. What both do is read inside the base directory, or not read at all.
        body.append("  h.assert.inside(h.fs.reads, base);")
    body += ["});", ""]
    return GeneratedProof(
        finding.stable_id, PATH_CONTAINMENT, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"{function.name}({untrusted}) with a traversal payload: the call refuses it and reads nothing; a legitimate name still resolves"
        + (" inside the base directory" if base else ""),
        function,
    )


def _js_traversal_handler_proof(
    snapshot: Snapshot, finding: FindingSnapshot, function: JsFunction, join: tuple[int, str, str], base: str | None
) -> GeneratedProof:
    """The unregistered-handler half of `_js_traversal_proof`: the response has to be 4xx.

    `templates._js_rejection` writes `res.status(400).end()` for a site that owns a response, so
    the assertion is the route's, read off the recording response the proof supplies rather than
    off a route the snapshot never shows registered.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    _js_callable(source, function)
    untrusted = next((item.expression for item in function.inputs if item.expression in join[2]), None) or _js_handler_untrusted(function, join[0])
    if untrusted is None:
        raise SiteError("no_request_input_in_route")
    body = [
        "const h = require('../harness');",
        "const path = require('node:path');",
        "h.run(async () => {",
        f"  const m = h.load({_js(path)});",
        f"  const base = {base or 'h.root'};",
        f"  for (const payload of {_js(list(DIRECT_TRAVERSAL_PAYLOADS))}) {{",
        "    h.fs.reads.length = 0;",
        *(f"  {line}" for line in _js_handler_drive(function, untrusted, "payload")),
        "    h.assert.inside(h.fs.reads, base, { payload });",
        "    h.assert(res.out.status >= 400 && res.out.status < 500, `expected a 4xx status for ${JSON.stringify(payload)}, got ${res.out.status}`);",
        "  }",
        "  h.fs.reads.length = 0;",
        f"  const payload = {_js(LEGITIMATE_NAME)};",
        *_js_handler_drive(function, untrusted, "payload"),
        # Not "a file was read": a handler that answers with `res.sendFile` never touches the
        # filesystem through anything the harness records. What both shapes promise is that a
        # legitimate name is not refused, and that whatever they did read stayed inside the base.
        "  h.assert(res.out.status < 400, `expected a legitimate name to be accepted, got ${res.out.status}`);",
    ]
    if base:
        body.append("  h.assert.inside(h.fs.reads, base);")
    body += ["});", ""]
    return GeneratedProof(
        finding.stable_id, PATH_CONTAINMENT, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"{function.name}(req) with {untrusted} set to a traversal payload: no file is read and the status is 4xx; "
        "a legitimate name is still read" + (" inside the served directory" if base else ""),
        function,
    )


def _js_traversal_proof(snapshot: Snapshot, finding: FindingSnapshot, site: JsRoute | JsFunction) -> GeneratedProof:
    """The test a JavaScript path-containment repair has to satisfy.

    A route is driven and must answer 4xx without reading anything. A plain function is called
    and must throw, which is the contract `templates._js_rejection` writes for it: a returned
    sentinel would be indistinguishable from a path. Both then check that a legitimate name is
    still resolved, so a repair cannot pass by refusing everything.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    binding = js_module_binding(source, "path", "path")
    found = js_path_site_in_scope(lines, site.start_line, site.end_line, line, (binding.name, "path"))
    join = (found.line, found.base, found.user_input)
    base = _js_base_expression(source, path, join[1])
    if isinstance(site, JsFunction) and site.kind == "handler":
        return _js_traversal_handler_proof(snapshot, finding, site, join, base)
    if not isinstance(site, JsRoute):
        return _js_traversal_function_proof(snapshot, finding, site, join, base)
    route = site
    untrusted = next((item.expression for item in route.inputs if item.expression in join[2]), None) or _js_untrusted_for(route, lines, join[0], route.start_line)
    if untrusted is None:
        raise SiteError("no_request_input_in_route")
    body = _js_header(path) + [
        f"  const base = {base or 'h.root'};",
        f"  for (const payload of {_js(list(TRAVERSAL_PAYLOADS))}) {{",
        "    h.fs.reads.length = 0;",
        f"    const response = await h.invoke(app, {_js(route.method)}, {_js(route.route)}, {_js_invoke_options(route, untrusted, '__PAYLOAD__').replace(_js('__PAYLOAD__'), 'payload')});",
        "    h.assert.inside(h.fs.reads, base, { payload });",
        "    h.assert(response.status >= 400 && response.status < 500, `expected a 4xx status for ${JSON.stringify(payload)}, got ${response.status}`);",
        "  }",
        "  h.fs.reads.length = 0;",
        f"  await h.invoke(app, {_js(route.method)}, {_js(route.route)}, {_js_invoke_options(route, untrusted, LEGITIMATE_NAME)});",
        "  h.assert(h.fs.reads.length > 0, 'expected a legitimate name to be read');",
    ]
    if base:
        body.append("  h.assert.inside(h.fs.reads, base);")
    body += ["});", ""]
    return GeneratedProof(
        finding.stable_id, PATH_CONTAINMENT, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"{route.method.upper()} {route.route} with {untrusted} set to a traversal payload: no file is read and the status is 4xx; a legitimate name is still read"
        + (" inside the served directory" if base else ""),
        route,
    )


def _js_credential_drive(source: str, line: int) -> list[str]:
    """The call that makes a secret inside a function run, or nothing when the import already did.

    Every argument is an empty object: what is being observed is the environment read that
    building the value performs, and the call is allowed to fail afterwards, which `h.call`
    reports rather than raising. A secret in a function the module does not export, or one whose
    parameters a call cannot line up with, is left to the import, and the proof then fails
    honestly rather than claiming a repair the test never reached.
    """
    try:
        site = js_site_for_line(source, line)
    except SiteError:
        # A scope this module cannot describe is not a reason to refuse the credential proof,
        # which needed no scope at all before: the import is what it falls back to.
        return []
    if not isinstance(site, JsFunction) or site.kind != "function" or not js_module_exports_name(source, site.name):
        return []
    return [f"  h.call(m.{site.name}{''.join(', {}' for _ in (site.parameter_model or site.parameters))});"]


def _js_credential_proof(snapshot: Snapshot, finding: FindingSnapshot) -> GeneratedProof:
    """The test a JavaScript hardcoded-credential repair has to satisfy.

    It fails on the literal for two independent reasons and passes only on the env read: a
    module that holds the literal never touches `process.env`, so `assert.envRead` fails,
    and the literal is still in the file, so `assert.notInSource` fails. When the module
    exports the name, the value read back is asserted too, which is what stops a repair
    that deletes the constant instead of moving it.

    A secret bound at module scope is read by the import itself. One inside a function is not,
    so the proof calls that function first: without the call the repaired module never reads
    the environment either, and `envRead` would fail on the fix as well as on the original.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    found = js_literal_assignment_in_span(source, finding.line_start, finding.line_end)
    if found is None:
        raise SiteError("string_literal_assignment_not_found")
    line, (name, literal, _quote, kind) = found
    variable = js_environment_name(name)
    if not variable:
        raise SiteError("environment_name_not_derived")
    exported = kind == "constant" and js_module_exports_name(source, name)
    body = [
        "const h = require('../harness');",
        "h.run(async () => {",
        f"  const m = h.load({_js(path)}, {{ env: {{ {json.dumps(variable)}: {_js(ENV_VALUE)} }} }});",
        *_js_credential_drive(source, line),
        f"  h.assert.envRead({_js(variable)});",
        f"  h.assert.notInSource(m, {_js(literal)});",
    ]
    if exported:
        body.append(f"  h.assert.equal(m.{name}, {_js(ENV_VALUE)});")
    body += ["});", ""]
    return GeneratedProof(
        finding.stable_id, HARDCODED_CREDENTIAL, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"{name} must come from process.env.{variable} and the literal must be gone from the module",
        None,
    )


def _js_call_arguments(function: JsFunction, untrusted: str, members: tuple[str, ...], value: str) -> str:
    """The argument list for a direct call, with `value` placed where the request put it.

    Every other parameter gets an empty object: the eval families take a row or a context there,
    and a value the function never reads cannot change what the assertion observes.
    """
    placed = value
    for part in reversed(members):
        placed = "{ " + _js(part) + ": " + placed + " }"
    arguments = []
    for parameter in function.parameter_model or tuple(JsParameter(name, name) for name in function.parameters):
        if parameter.rest:
            continue
        if parameter.members:
            # The parameter is destructured at the signature, so the value goes under the member
            # the body reads rather than in the parameter's own position.
            fields = ", ".join(
                f"{member}: " + (placed if member == untrusted else "{}") for member in parameter.members
            )
            arguments.append("{ " + fields + " }")
        elif parameter.name == untrusted:
            arguments.append(placed)
        else:
            arguments.append("{}")
    return ", ".join(arguments)


def _js_eval_proof(snapshot: Snapshot, finding: FindingSnapshot) -> GeneratedProof:
    """The test a JavaScript code_injection_eval repair has to satisfy.

    It fails on the original for two independent reasons: the harness records the payload
    reaching `eval`, and the document the function is meant to read comes back as `undefined`
    because the recorder ran nothing. It passes only when the value is parsed as data.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    line = _finding_line(finding)
    function, untrusted, members = js_eval_site(source, line)
    attack = _js_call_arguments(function, untrusted, members, "payload")
    document = _js_call_arguments(function, untrusted, members, _js(JS_EVAL_DOCUMENT))
    body = [
        "const h = require('../harness');",
        "h.run(async () => {",
        f"  const m = h.load({_js(path)});",
        f"  const payload = {_js(JS_EVAL_PAYLOAD)};",
        f"  h.call(m.{function.name}, {attack});",
        "  h.assert.noCode();",
        f"  const parsed = h.call(m.{function.name}, {document});",
    ]
    if function.returns_directly:
        body.append(f"  h.assert.equal(JSON.stringify(parsed.value), {_js(JS_EVAL_DOCUMENT_JSON)});")
    else:
        body.append("  h.assert(parsed.ok, 'expected a JSON document to still be accepted');")
    body += ["});", ""]
    reached = ".".join((untrusted, *members))
    return GeneratedProof(
        finding.stable_id, CODE_INJECTION_EVAL, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"{function.name}({reached}) with a payload that would run a command: nothing is compiled, and a JSON document still parses",
        None,
    )


# --- module scope ----------------------------------------------------------------------------
# A finding with no enclosing callable. The sink runs once, when the module is imported, so the
# proof's only lever is what it can set before `h.load` runs it, and the family assertion is made
# on the load itself. `sites.ModuleScope.driver` says which lever there is; None means there is
# none, and the finding is refused rather than given a test that cannot fail on the original.
MODULE_SCOPE_REFUSAL = "module_scope_source_not_controllable"
# The argv a proof hands a module that reads `process.argv[i]` / `sys.argv[i]`: the interpreter
# and the script in their real places, the payload at the index the module reads, and a benign
# value in every position between.
ARGV_PROGRAM = ("node", "module")
PY_ARGV_PROGRAM = ("module",)


def _argv_elements(index: int, program: tuple[str, ...]) -> list[str | None]:
    """`None` marks the slot the payload expression goes into; every other slot is a string."""
    slots: list[str | None] = [*program]
    while len(slots) <= index:
        slots.append(BENIGN_VALUE)
    slots[index] = None
    return slots


def _js_module_load(path: str, scope: ModuleScope, payload: str) -> str:
    """The `h.load(...)` call that drives a module-scope sink with `payload` in place."""
    if scope.driver == "env":
        return f"h.load({_js(path)}, {{ env: {{ {_js(scope.key)}: {payload} }} }})"
    if scope.driver == "argv":
        items = ", ".join(payload if item is None else _js(item) for item in _argv_elements(int(scope.key), ARGV_PROGRAM))
        return f"h.load({_js(path)}, {{ argv: [{items}] }})"
    if scope.driver == "config":
        value = "{ " + _js(scope.member) + ": " + payload + " }" if scope.member else payload
        return f"h.load({_js(path)}, {{ stubs: {{ {_js(scope.key)}: {value} }} }})"
    raise SiteError(MODULE_SCOPE_REFUSAL)


def _js_module_source(scope: ModuleScope) -> str:
    if scope.driver == "env":
        return f"process.env.{scope.key}"
    if scope.driver == "argv":
        return f"process.argv[{scope.key}]"
    return f"{scope.key}" + (f".{scope.member}" if scope.member else "")


def _js_module_proof(
    snapshot: Snapshot, finding: FindingSnapshot, scope: ModuleScope, family: str, payload: str, assertions: list[str]
) -> GeneratedProof:
    """A module-scope proof for a family whose assertion is made once, on the load."""
    path = finding.affected_path
    body = [
        "const h = require('../harness');",
        "h.run(async () => {",
        f"  const payload = {_js(payload)};",
        f"  {_js_module_load(path, scope, 'payload')};",
        *assertions,
        "});",
        "",
    ]
    return GeneratedProof(
        finding.stable_id, family, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"the module runs its sink on import with {_js_module_source(scope)} = {payload!r}", scope,
    )


def _js_module_traversal_proof(snapshot: Snapshot, finding: FindingSnapshot, scope: ModuleScope, base: str | None) -> GeneratedProof:
    """The traversal family at module scope: the import itself has to refuse the payload.

    A module-scope repair has no caller to answer, so `templates._js_rejection` throws, and the
    throw happens during the import. `h.call` reports it rather than raising, so one test can
    require every traversal payload to be refused and a legitimate name to still be read.
    """
    path = finding.affected_path
    body = [
        "const h = require('../harness');",
        "const path = require('node:path');",
        "h.run(async () => {",
        f"  const base = {base or 'h.root'};",
        f"  for (const payload of {_js(list(DIRECT_TRAVERSAL_PAYLOADS))}) {{",
        "    h.fs.reads.length = 0;",
        f"    const refused = h.call(() => {_js_module_load(path, scope, 'payload')});",
        "    h.assert(!refused.ok, `expected ${JSON.stringify(payload)} to be refused on import`);",
        "    h.assert.inside(h.fs.reads, base, { payload });",
        "  }",
        "  h.fs.reads.length = 0;",
        f"  const payload = {_js(LEGITIMATE_NAME)};",
        f"  const allowed = h.call(() => {_js_module_load(path, scope, 'payload')});",
        "  h.assert(allowed.ok, 'expected a legitimate name to still resolve on import');",
    ]
    if base:
        body.append("  h.assert.inside(h.fs.reads, base);")
    body += ["});", ""]
    return GeneratedProof(
        finding.stable_id, PATH_CONTAINMENT, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"importing the module with {_js_module_source(scope)} set to a traversal payload throws and reads nothing; "
        "a legitimate name still resolves",
        scope,
    )


def _js_module_scope_proof(snapshot: Snapshot, finding: FindingSnapshot, scope: ModuleScope, family: str) -> GeneratedProof:
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    if scope.driver is None:
        raise SiteError(MODULE_SCOPE_REFUSAL)
    if family == SQL_PARAMETERIZATION:
        _js_sink_in_scope(lines, scope, _JS_INLINE_SQL_RE, "sql_sink_not_in_scope")
        return _js_module_proof(snapshot, finding, scope, family, SQL_PAYLOAD, _JS_QUERY_ASSERTIONS[:-2])
    if family == COMMAND_ARGUMENTS:
        _js_sink_in_scope(lines, scope, _JS_COMMAND_SINK_RE, "command_sink_not_in_scope")
        return _js_module_proof(snapshot, finding, scope, family, COMMAND_PAYLOAD, _JS_ARGV_ASSERTIONS[:-2])
    if family == PATH_CONTAINMENT:
        binding = js_module_binding(source, "path", "path")
        join = js_path_site_in_scope(lines, scope.start_line, scope.end_line, _finding_line(finding), (binding.name, "path"))
        return _js_module_traversal_proof(snapshot, finding, scope, _js_base_expression(source, path, join.base))
    raise SiteError("family_not_generated_at_module_scope")


# --- Python ---------------------------------------------------------------------------------

def _py_header(path: str, env: dict[str, str] | None = None) -> list[str]:
    env_text = f", env={_py(env)}" if env else ""
    return ["import harness as h", "", "", "def body():", f"    m = h.load({_py(path)}{env_text})"]


def _py_footer() -> list[str]:
    return ["", "", "h.run(body)", ""]


def _py_driver(snapshot: Snapshot, path: str) -> str | None:
    imports = python_imports(snapshot.full_content(path))
    for name in sorted(imports):
        for driver in PYTHON_SQL_DRIVERS:
            if name == driver or name.startswith(driver + "."):
                return driver
    return None


def _py_call_arguments(function: PyFunction, untrusted: str, payload: str, driver: str | None) -> tuple[list[str], list[str]]:
    """Positional argument expressions for the function and the setup lines they need."""
    setup: list[str] = []
    arguments: list[str] = []
    for parameter in function.parameters:
        if parameter == untrusted:
            arguments.append("payload")
        elif parameter in CONNECTION_PARAMETERS and driver:
            setup.append(f"    import {driver}")
            connect = f"{driver}.connect(':memory:')" if driver == "sqlite3" else (f"{driver}.create_engine('sqlite://')" if driver == "sqlalchemy" else f"{driver}.connect('')")
            setup.append(f"    {parameter} = {connect}")
            arguments.append(parameter)
        elif parameter in CURSOR_PARAMETERS and driver and driver != "sqlalchemy":
            setup.append(f"    import {driver}")
            setup.append(f"    {parameter} = {driver}.connect('')" + ".cursor()")
            arguments.append(parameter)
        elif parameter in ("self", "cls"):
            raise SiteError("method_receiver_not_supported")
        else:
            arguments.append(_py(BENIGN_VALUE))
    return arguments, list(dict.fromkeys(setup))


def _py_untrusted_parameter(function: PyFunction, lines: list[str], sink_line: int) -> str | None:
    """The parameter used on the sink line or on the assignment feeding it, else the last parameter."""
    candidates = [p for p in function.parameters if p not in CONNECTION_PARAMETERS and p not in CURSOR_PARAMETERS and p not in ("self", "cls")]
    if not candidates:
        return None
    for number in range(sink_line, function.start_line, -1):
        text = lines[number - 1]
        for parameter in candidates:
            if re.search(rf"(?<!\w){re.escape(parameter)}(?!\w)", text):
                return parameter
    return candidates[-1]


def _py_view_invoke(function: PyFunction, untrusted_expression: str | None, payload_expression: str) -> str:
    """`h.invoke(...)` for a Flask view: the payload on the untrusted input, benign values elsewhere."""
    params: dict[str, str] = {}
    for name in re.findall(r"<(?:\w+:)?(\w+)>", function.route or ""):
        params[name] = payload_expression if name == untrusted_expression else _py(BENIGN_VALUE)
    groups: dict[str, dict[str, str]] = {}
    for item in function.inputs:
        value = payload_expression if item.expression == untrusted_expression else _py(BENIGN_VALUE)
        groups.setdefault({"args": "query", "form": "form", "json": "json", "values": "query"}[item.source], {})[item.name] = value
    parts = ["app", _py(function.methods[0] if function.methods else "GET"), _py(function.route)]
    if params:
        parts.append("params={" + ", ".join(f"{_py(k)}: {v}" for k, v in params.items()) + "}")
    for keyword in ("query", "form", "json"):
        if keyword in groups:
            parts.append(f"{keyword}={{" + ", ".join(f"{_py(k)}: {v}" for k, v in groups[keyword].items()) + "}")
    return "h.invoke(" + ", ".join(parts) + ")"


def _py_view_untrusted(function: PyFunction, lines: list[str], sink_line: int) -> str | None:
    """The view input feeding the sink: a rule parameter or a `request.*` read, nearest the sink."""
    for number in range(sink_line, function.start_line, -1):
        used = [item for item in function.inputs if item.line == number]
        if used:
            return used[0].expression
        text = lines[number - 1]
        for name in re.findall(r"<(?:\w+:)?(\w+)>", function.route or ""):
            if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text):
                return name
    if function.inputs:
        return function.inputs[0].expression
    names = re.findall(r"<(?:\w+:)?(\w+)>", function.route or "")
    return names[0] if names else None


def _py_app_line(source: str) -> str:
    name = python_flask_app_name(source)
    return f"    app = getattr(m, {_py(name or 'app')}, None)"


def _py_sql_proof(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> GeneratedProof:
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    driver = _py_driver(snapshot, path)
    body = _py_header(path)
    if function.route:
        untrusted = _py_view_untrusted(function, lines, line)
        if untrusted is None:
            raise SiteError("no_request_input_in_view")
        body += [_py_app_line(source), f"    payload = {_py(SQL_PAYLOAD)}", f"    {_py_view_invoke(function, untrusted, 'payload')}"]
        what = f"{function.methods[0] if function.methods else 'GET'} {function.route} with {untrusted}"
    else:
        untrusted = _py_untrusted_parameter(function, lines, line)
        if untrusted is None:
            raise SiteError("no_untrusted_parameter")
        arguments, setup = _py_call_arguments(function, untrusted, SQL_PAYLOAD, driver)
        body += setup + [f"    payload = {_py(SQL_PAYLOAD)}", f"    h.call(m.{function.name}, {', '.join(arguments)})"]
        what = f"{function.name}({untrusted})"
    body += [
        "    h.assert_true(h.db.queries, 'expected one query to be executed')",
        "    h.assert_param(h.db.queries[0], payload)",
    ] + _py_footer()
    return GeneratedProof(
        finding.stable_id, SQL_PARAMETERIZATION, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
        f"{what} = {SQL_PAYLOAD!r}: the SQL text must not carry the payload and the bound parameters must", function,
    )


def _py_command_proof(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> GeneratedProof:
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    body = _py_header(path)
    if function.route:
        untrusted = _py_view_untrusted(function, lines, line)
        if untrusted is None:
            raise SiteError("no_request_input_in_view")
        body += [_py_app_line(source), f"    payload = {_py(COMMAND_PAYLOAD)}", f"    {_py_view_invoke(function, untrusted, 'payload')}"]
        what = f"{function.methods[0] if function.methods else 'GET'} {function.route} with {untrusted}"
    else:
        untrusted = _py_untrusted_parameter(function, lines, line)
        if untrusted is None:
            raise SiteError("no_untrusted_parameter")
        arguments, setup = _py_call_arguments(function, untrusted, COMMAND_PAYLOAD, None)
        body += setup + [f"    payload = {_py(COMMAND_PAYLOAD)}", f"    h.call(m.{function.name}, {', '.join(arguments)})"]
        what = f"{function.name}({untrusted})"
    body += [
        "    h.assert_true(h.subprocess.calls, 'expected one process to be started')",
        "    h.assert_argv(h.subprocess.calls[0], payload)",
    ] + _py_footer()
    return GeneratedProof(
        finding.stable_id, COMMAND_ARGUMENTS, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
        f"{what} = {COMMAND_PAYLOAD!r}: the process must run with an argv list, no shell, and the payload as its own element", function,
    )


def _py_base_expression(source: str, base: str) -> str | None:
    value = base.strip()
    if re.fullmatch(r"(['\"])(?:(?!\1).)*\1", value):
        return value
    if re.fullmatch(r"[A-Za-z_]\w*", value) and python_module_value(source, value) is not None:
        return f"m.{value}"
    return None


def _py_traversal_function_proof(
    snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction, join: tuple[int, str, str], base: str | None
) -> GeneratedProof:
    """The plain-function half of `_py_traversal_proof`: the call must raise on a traversal.

    A view aborts 400 and this raises, which is the contract `templates._py_traversal` writes for
    a function. `h.call` reports the exception rather than propagating it, so one test can require
    the payload to be refused and a legitimate name to still resolve.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    untrusted = _py_untrusted_parameter(function, lines, join[0])
    if untrusted is None:
        raise SiteError("no_untrusted_parameter")
    arguments, setup = _py_call_arguments(function, untrusted, LEGITIMATE_NAME, None)
    body = _py_header(path) + setup + [
        f"    base = {base or 'h.ROOT'}",
        # A function called directly gets its argument as written, so the encoded payload is a
        # view-level concern: `os.path.join` leaves `..%2f..%2fetc%2fpasswd` inside the base and a
        # correct helper rightly does not refuse it. The absolute path takes its place.
        f"    for payload in {_py(list(DIRECT_TRAVERSAL_PAYLOADS))}:",
        "        h.fs.reads.clear()",
        f"        refused = h.call(m.{function.name}, {', '.join(arguments)})",
        "        h.assert_true(refused.raised(ValueError), 'expected %r to be refused, got %r' % (payload, refused.value))",
        "        h.assert_inside(h.fs.reads, base, payload=payload)",
        "    h.fs.reads.clear()",
        f"    payload = {_py(LEGITIMATE_NAME)}",
        f"    allowed = h.call(m.{function.name}, {', '.join(arguments)})",
        "    h.assert_true(allowed.error is None, 'expected a legitimate name to still resolve')",
    ]
    if base:
        body.append("    h.assert_inside(h.fs.reads, base)")
    body += _py_footer()
    return GeneratedProof(
        finding.stable_id, PATH_CONTAINMENT, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
        f"{function.name}({untrusted}) with a traversal payload: the call raises ValueError and opens nothing; a legitimate name still resolves",
        function,
    )


def _py_traversal_proof(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> GeneratedProof:
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    join = None
    for number in scope_lines_near(function.start_line, function.end_line, line):
        found = re.search(r"os\.path\.join\(\s*(?P<base>[^,()]+?)\s*,\s*(?P<input>[^()]+?)\s*\)", lines[number - 1])
        if found:
            join = (number, found.group("base"), found.group("input"))
            break
    if join is None:
        raise SiteError("path_join_not_found_in_scope")
    base = _py_base_expression(source, join[1])
    if not function.route:
        return _py_traversal_function_proof(snapshot, finding, function, join, base)
    untrusted = _py_view_untrusted(function, lines, join[0])
    if untrusted is None:
        raise SiteError("no_request_input_in_view")
    body = _py_header(path) + [
        _py_app_line(source),
        f"    base = {base or 'h.ROOT'}",
        # A view receives a percent-decoded value, so the encoded payload is the one that
        # distinguishes a repair that decodes before checking from one that does not.
        f"    for payload in {_py(list(TRAVERSAL_PAYLOADS))}:",
        "        h.fs.reads.clear()",
        f"        response = {_py_view_invoke(function, untrusted, 'payload')}",
        "        h.assert_inside(h.fs.reads, base, payload=payload)",
        "        h.assert_true(400 <= response.status_code < 500, 'expected a 4xx status for %r, got %s' % (payload, response.status_code))",
        "    h.fs.reads.clear()",
        f"    {_py_view_invoke(function, untrusted, _py(LEGITIMATE_NAME))}",
        "    h.assert_true(h.fs.reads, 'expected a legitimate name to be read')",
    ]
    if base:
        body.append("    h.assert_inside(h.fs.reads, base)")
    body += _py_footer()
    return GeneratedProof(
        finding.stable_id, PATH_CONTAINMENT, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
        f"{function.methods[0] if function.methods else 'GET'} {function.route} with {untrusted} set to a traversal payload: no file is opened and the status is 4xx; a legitimate name is still read",
        function,
    )


def _py_credential_proof(snapshot: Snapshot, finding: FindingSnapshot) -> GeneratedProof:
    path = finding.affected_path
    source = snapshot.full_content(path)
    assignment = python_module_assignment(source, _finding_line(finding))
    if assignment is None:
        raise SiteError("module_level_string_assignment_not_found")
    name, literal, _ = assignment
    if not literal:
        raise SiteError("empty_literal")
    body = _py_header(path, {name: ENV_VALUE}) + [
        f"    h.assert_equal(m.{name}, {_py(ENV_VALUE)})",
        f"    h.assert_env_read({_py(name)})",
        f"    h.assert_not_in_source(m, {_py(literal)})",
    ] + _py_footer()
    return GeneratedProof(
        finding.stable_id, HARDCODED_CREDENTIAL, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
        f"{name} must come from the environment and the literal must be gone from the module", None,
    )


def _py_eval_proof(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> GeneratedProof:
    path = finding.affected_path
    lines = snapshot.full_content(path).splitlines()
    line = _finding_line(finding)
    found = re.search(r"(?<![\w.])eval\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", lines[line - 1])
    if not found or found.group("arg") not in function.parameters:
        raise SiteError("eval_argument_not_a_parameter")
    untrusted = found.group("arg")
    arguments, _ = _py_call_arguments(function, untrusted, EVAL_PAYLOAD, None)
    call = f"m.{function.name}, " + ", ".join(arguments)
    body = _py_header(path) + [
        f"    payload = {_py(EVAL_PAYLOAD)}",
        f"    h.call({call})",
        "    h.assert_no_commands()",
        f"    literal = h.call({call.replace('payload', _py('[1, 2]'))})",
    ]
    if function.returns_directly is not None:
        body.append("    h.assert_equal(literal.value, [1, 2])")
    else:
        body.append("    h.assert_true(literal.ok, 'expected a literal to still be accepted')")
    body += _py_footer()
    return GeneratedProof(
        finding.stable_id, CODE_INJECTION_EVAL, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
        f"{function.name}({untrusted}) with a payload that would run a command: nothing runs, and a literal still parses", function,
    )


def _py_module_load(path: str, scope: ModuleScope, payload: str) -> str:
    if scope.driver == "env":
        return f"h.load({_py(path)}, env={{{_py(scope.key)}: {payload}}})"
    if scope.driver == "argv":
        items = ", ".join(payload if item is None else _py(item) for item in _argv_elements(int(scope.key), PY_ARGV_PROGRAM))
        return f"h.load({_py(path)}, argv=[{items}])"
    if scope.driver == "config":
        value = "{" + _py(scope.member) + ": " + payload + "}" if scope.member else payload
        return f"h.load({_py(path)}, stubs={{{_py(scope.key)}: {value}}})"
    raise SiteError(MODULE_SCOPE_REFUSAL)


def _py_module_source(scope: ModuleScope) -> str:
    if scope.driver == "env":
        return f"os.environ[{scope.key!r}]"
    if scope.driver == "argv":
        return f"sys.argv[{scope.key}]"
    return f"{scope.key}" + (f".{scope.member}" if scope.member else "")


def _py_module_scope_proof(snapshot: Snapshot, finding: FindingSnapshot, scope: ModuleScope, family: str) -> GeneratedProof:
    """The Python half of `_js_module_scope_proof`, through the Python harness."""
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    if scope.driver is None:
        raise SiteError(MODULE_SCOPE_REFUSAL)
    if family in (SQL_PARAMETERIZATION, COMMAND_ARGUMENTS):
        payload = SQL_PAYLOAD if family == SQL_PARAMETERIZATION else COMMAND_PAYLOAD
        recorder, assertion = (
            ("h.db.queries", "h.assert_param(h.db.queries[0], payload)")
            if family == SQL_PARAMETERIZATION
            else ("h.subprocess.calls", "h.assert_argv(h.subprocess.calls[0], payload)")
        )
        what = "one query to be executed" if family == SQL_PARAMETERIZATION else "one process to be started"
        body = [
            "import harness as h",
            "",
            "",
            "def body():",
            f"    payload = {_py(payload)}",
            f"    {_py_module_load(path, scope, 'payload')}",
            f"    h.assert_true({recorder}, 'expected {what}')",
            f"    {assertion}",
        ] + _py_footer()
        return GeneratedProof(
            finding.stable_id, family, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
            f"the module runs its sink on import with {_py_module_source(scope)} = {payload!r}", scope,
        )
    if family == PATH_CONTAINMENT:
        join = None
        for number in scope_lines_near(scope.start_line, scope.end_line, _finding_line(finding)):
            found = re.search(r"os\.path\.join\(\s*(?P<base>[^,()]+?)\s*,\s*(?P<input>[^()]+?)\s*\)", lines[number - 1])
            if found:
                join = found
                break
        if join is None:
            raise SiteError("path_join_not_found_in_scope")
        base = _py_base_expression(source, join.group("base"))
        # A module value is only readable once a load has succeeded, and these loads are meant to
        # fail, so only a literal base is usable here.
        if base and base.startswith("m."):
            base = None
        body = [
            "import harness as h",
            "",
            "",
            "def body():",
            f"    for payload in {_py(list(DIRECT_TRAVERSAL_PAYLOADS))}:",
            "        h.fs.reads.clear()",
            f"        refused = h.call(lambda: {_py_module_load(path, scope, 'payload')})",
            "        h.assert_true(refused.raised(ValueError), 'expected %r to be refused on import' % (payload,))",
            "        h.assert_inside(h.fs.reads, %s, payload=payload)" % (base or "h.ROOT"),
            "    h.fs.reads.clear()",
            f"    payload = {_py(LEGITIMATE_NAME)}",
            f"    allowed = h.call(lambda: {_py_module_load(path, scope, 'payload')})",
            "    h.assert_true(allowed.error is None, 'expected a legitimate name to still resolve on import')",
        ]
        if base:
            body.append(f"    h.assert_inside(h.fs.reads, {base})")
        body += _py_footer()
        return GeneratedProof(
            finding.stable_id, PATH_CONTAINMENT, PYTHON, test_path(finding.stable_id, PYTHON), "\n".join(body),
            f"importing the module with {_py_module_source(scope)} set to a traversal payload raises ValueError and "
            "opens nothing; a legitimate name still resolves",
            scope,
        )
    raise SiteError("family_not_generated_at_module_scope")


# --- entry point ----------------------------------------------------------------------------

def generate_proof(snapshot: Snapshot, finding: FindingSnapshot, family: str, language: str) -> GeneratedProof | ProofFallback:
    """The service-generated test for one finding, or the reason the model has to write it."""
    path = finding.affected_path
    try:
        if language == JAVASCRIPT:
            # Every JavaScript proof loads the module, so loadability is decided once, before the
            # families that need no enclosing scope: a secret literal is not inside any function,
            # and neither is a parser a route calls.
            _js_loadable(snapshot, path)
            if family == HARDCODED_CREDENTIAL:
                return _js_credential_proof(snapshot, finding)
            if family == CODE_INJECTION_EVAL:
                return _js_eval_proof(snapshot, finding)
            site = js_site_for_line(snapshot.full_content(path), _finding_line(finding))
            if isinstance(site, ModuleScope):
                return _js_module_scope_proof(snapshot, finding, site, family)
            if family == SQL_PARAMETERIZATION:
                return _js_sql_proof(snapshot, finding, site)
            if family == COMMAND_ARGUMENTS:
                return _js_command_proof(snapshot, finding, site)
            if family == PATH_CONTAINMENT:
                return _js_traversal_proof(snapshot, finding, site)
            return ProofFallback(finding.stable_id, family, "family_not_generated")
        if language == PYTHON:
            if family == HARDCODED_CREDENTIAL:
                return _py_credential_proof(snapshot, finding)
            function = python_site_for_line(snapshot.full_content(path), _finding_line(finding))
            if isinstance(function, ModuleScope):
                return _py_module_scope_proof(snapshot, finding, function, family)
            if family == SQL_PARAMETERIZATION:
                return _py_sql_proof(snapshot, finding, function)
            if family == COMMAND_ARGUMENTS:
                return _py_command_proof(snapshot, finding, function)
            if family == PATH_CONTAINMENT:
                return _py_traversal_proof(snapshot, finding, function)
            if family == CODE_INJECTION_EVAL:
                return _py_eval_proof(snapshot, finding, function)
            return ProofFallback(finding.stable_id, family, "family_not_generated")
    except SiteError as exc:
        return ProofFallback(finding.stable_id, family, exc.code)
    return ProofFallback(finding.stable_id, family, "language_not_generated")
