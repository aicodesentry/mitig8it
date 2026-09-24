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
    JsFunction,
    JsRoute,
    PyFunction,
    SiteError,
    js_environment_name,
    js_eval_site,
    js_literal_assignment,
    js_literal_assignment_in_span,
    js_module_constant,
    js_module_exports_name,
    js_route_for_line,
    module_directory,
    python_flask_app_name,
    python_function_for_line,
    python_module_assignment,
    python_module_value,
)

SQL_PAYLOAD = "1' OR '1'='1"
COMMAND_PAYLOAD = "x; rm -rf /"
TRAVERSAL_PAYLOADS = ("../../etc/passwd", "..%2f..%2fetc%2fpasswd")
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
    site: JsRoute | PyFunction | None = None

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


def _js_sql_proof(snapshot: Snapshot, finding: FindingSnapshot, route: JsRoute) -> GeneratedProof:
    path = finding.affected_path
    lines = snapshot.full_content(path).splitlines()
    line = _finding_line(finding)
    untrusted = _js_untrusted_for(route, lines, line, route.start_line)
    if untrusted is None:
        raise SiteError("no_request_input_in_route")
    body = _js_header(path) + [
        f"  const payload = {_js(SQL_PAYLOAD)};",
        f"  await h.invoke(app, {_js(route.method)}, {_js(route.route)}, {_js_invoke_options(route, untrusted, SQL_PAYLOAD)});",
        "  const q = h.pg.queries[0];",
        "  h.assert(q, 'expected the handler to run one pg query');",
        "  h.assert.notIncludes(q.text, payload);",
        "  h.assert.includes(JSON.stringify(q.values || []), payload);",
        "});",
        "",
    ]
    return GeneratedProof(
        finding.stable_id, SQL_PARAMETERIZATION, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"{route.method.upper()} {route.route} with {untrusted} = {SQL_PAYLOAD!r}: the query text must not carry the payload and the values must",
        route,
    )


def _js_command_proof(snapshot: Snapshot, finding: FindingSnapshot, route: JsRoute) -> GeneratedProof:
    path = finding.affected_path
    lines = snapshot.full_content(path).splitlines()
    line = _finding_line(finding)
    untrusted = _js_untrusted_for(route, lines, line, route.start_line)
    if untrusted is None:
        raise SiteError("no_request_input_in_route")
    body = _js_header(path) + [
        f"  const payload = {_js(COMMAND_PAYLOAD)};",
        f"  await h.invoke(app, {_js(route.method)}, {_js(route.route)}, {_js_invoke_options(route, untrusted, COMMAND_PAYLOAD)});",
        "  h.assert(h.child_process.calls.length > 0, 'expected the handler to start one child process');",
        "  h.assert.argv(h.child_process.calls[0], payload);",
        "});",
        "",
    ]
    return GeneratedProof(
        finding.stable_id, COMMAND_ARGUMENTS, JAVASCRIPT, test_path(finding.stable_id, JAVASCRIPT), "\n".join(body),
        f"{route.method.upper()} {route.route} with {untrusted} = {COMMAND_PAYLOAD!r}: the child must run with an argument array and the payload as its own element",
        route,
    )


def _js_traversal_proof(snapshot: Snapshot, finding: FindingSnapshot, route: JsRoute) -> GeneratedProof:
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    join = None
    for number in range(min(line, route.end_line), route.start_line, -1):
        found = re.search(r"path\.(?:join|resolve)\(\s*(?P<base>[^,()]+?)\s*,\s*(?P<input>[^()]+?)\s*\)", lines[number - 1])
        if found:
            join = (number, found.group("base"), found.group("input"))
            break
    if join is None:
        raise SiteError("path_join_not_found_in_route")
    untrusted = next((item.expression for item in route.inputs if item.expression in join[2]), None) or _js_untrusted_for(route, lines, join[0], route.start_line)
    if untrusted is None:
        raise SiteError("no_request_input_in_route")
    base = _js_base_expression(source, path, join[1])
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


def _js_credential_proof(snapshot: Snapshot, finding: FindingSnapshot) -> GeneratedProof:
    """The test a JavaScript hardcoded-credential repair has to satisfy.

    It fails on the literal for two independent reasons and passes only on the env read: a
    module that holds the literal never touches `process.env`, so `assert.envRead` fails,
    and the literal is still in the file, so `assert.notInSource` fails. When the module
    exports the name, the value read back is asserted too, which is what stops a repair
    that deletes the constant instead of moving it.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    found = js_literal_assignment_in_span(source, finding.line_start, finding.line_end)
    if found is None:
        raise SiteError("string_literal_assignment_not_found")
    _line, (name, literal, _quote, kind) = found
    variable = js_environment_name(name)
    if not variable:
        raise SiteError("environment_name_not_derived")
    exported = kind == "constant" and js_module_exports_name(source, name)
    body = [
        "const h = require('../harness');",
        "h.run(async () => {",
        f"  const m = h.load({_js(path)}, {{ env: {{ {json.dumps(variable)}: {_js(ENV_VALUE)} }} }});",
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
    arguments = []
    for parameter in function.parameters:
        if parameter != untrusted:
            arguments.append("{}")
            continue
        placed = value
        for part in reversed(members):
            placed = "{ " + _js(part) + ": " + placed + " }"
        arguments.append(placed)
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


def _py_traversal_proof(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> GeneratedProof:
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    if not function.route:
        raise SiteError("traversal_outside_flask_view")
    join = None
    for number in range(min(line, function.end_line), function.start_line, -1):
        found = re.search(r"os\.path\.join\(\s*(?P<base>[^,()]+?)\s*,\s*(?P<input>[^()]+?)\s*\)", lines[number - 1])
        if found:
            join = (number, found.group("base"), found.group("input"))
            break
    if join is None:
        raise SiteError("path_join_not_found_in_view")
    untrusted = _py_view_untrusted(function, lines, join[0])
    if untrusted is None:
        raise SiteError("no_request_input_in_view")
    base = _py_base_expression(source, join[1])
    body = _py_header(path) + [
        _py_app_line(source),
        f"    base = {base or 'h.ROOT'}",
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


# --- entry point ----------------------------------------------------------------------------

def generate_proof(snapshot: Snapshot, finding: FindingSnapshot, family: str, language: str) -> GeneratedProof | ProofFallback:
    """The service-generated test for one finding, or the reason the model has to write it."""
    path = finding.affected_path
    try:
        if language == JAVASCRIPT:
            # A secret literal is not inside a request handler, and neither is a parser a route
            # calls, so both are proven without one.
            if family == HARDCODED_CREDENTIAL:
                return _js_credential_proof(snapshot, finding)
            if family == CODE_INJECTION_EVAL:
                return _js_eval_proof(snapshot, finding)
            route = js_route_for_line(snapshot.full_content(path), _finding_line(finding))
            if family == SQL_PARAMETERIZATION:
                return _js_sql_proof(snapshot, finding, route)
            if family == COMMAND_ARGUMENTS:
                return _js_command_proof(snapshot, finding, route)
            if family == PATH_CONTAINMENT:
                return _js_traversal_proof(snapshot, finding, route)
            return ProofFallback(finding.stable_id, family, "family_not_generated")
        if language == PYTHON:
            if family == HARDCODED_CREDENTIAL:
                return _py_credential_proof(snapshot, finding)
            function = python_function_for_line(snapshot.full_content(path), _finding_line(finding))
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
