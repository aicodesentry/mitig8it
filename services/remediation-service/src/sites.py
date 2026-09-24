"""Where a finding lives: the enclosing route handler, function, or method.

The proof generator and the template patcher both need the same facts about a finding's
surroundings: which route or function encloses it, how untrusted input enters it, and which
names that scope binds. This module derives them lexically (JavaScript) or from the `ast`
(Python) over the exact snapshot. It never guesses: when the enclosing site cannot be derived,
it says why, and the caller falls back to the model-written test.

A site is a route when one encloses the finding and a function otherwise, on both sides. The
route is preferred because it is the reachable entry point, but a repair does not depend on one
existing: most of a real codebase's vulnerable code sits in the helpers a handler calls, not in
the handler, and those are proven by calling the function directly.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from .models import FindingSnapshot
from .retrieval import Snapshot

ROUTE_METHODS = ("get", "post", "put", "delete", "patch", "all")
_JS_ROUTE_RE = re.compile(
    r"^\s*(?P<owner>[\w$]+(?:\.[\w$]+)*)\.(?P<method>get|post|put|delete|patch|all)\s*\(\s*(?P<quote>['\"`])(?P<route>[^'\"`\n]+)(?P=quote)\s*,"
)
_JS_HANDLER_RE = re.compile(
    r"(?:async\s*)?(?:\(\s*(?P<req>[\w$]+)\s*,\s*(?P<res>[\w$]+)(?:\s*,\s*(?P<next>[\w$]+))?\s*\)\s*=>|function\s*\w*\s*\(\s*(?P<req2>[\w$]+)\s*,\s*(?P<res2>[\w$]+)(?:\s*,\s*[\w$]+)?\s*\))"
)
_JS_INPUT_RE = re.compile(r"(?P<req>[\w$]+)\.(?P<source>params|query|body)(?:\.(?P<name>[\w$]+)|\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])")
_JS_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_PY_REQUEST_RE = re.compile(
    r"request\.(?P<source>args|form|values|json)(?:\.get\(\s*['\"](?P<getname>[^'\"]+)['\"]|\[\s*['\"](?P<name>[^'\"]+)['\"]\s*\])"
)


@dataclass(frozen=True)
class UntrustedInput:
    """One way request data reaches the handler, in the order the handler reads it."""

    source: str  # params | query | body | args | form | json | argument
    name: str
    expression: str  # the exact source expression, such as `req.params.id` or `email`
    line: int


@dataclass(frozen=True)
class JsRoute:
    owner: str
    method: str
    route: str
    start_line: int
    end_line: int
    req: str
    res: str
    inputs: tuple[UntrustedInput, ...]

    @property
    def names(self) -> set[str]:
        return {self.req, self.res}

    @property
    def parameters(self) -> tuple[str, ...]:
        return (self.req, self.res)


@dataclass(frozen=True)
class JsFunction:
    """A named JavaScript function that is not an Express handler, called directly by a proof.

    `kind` says how the name is bound, because that is what decides whether a generated test can
    reach it: a `function` (a declaration, a const binding, or an `exports.name =` assignment) is
    reachable as `m.name` once the module exports it, while a `method` hangs off a class or an
    object literal and needs a receiver the scan cannot construct.
    """

    name: str
    start_line: int
    end_line: int
    parameters: tuple[str, ...]
    returns_directly: bool = False
    kind: str = "function"  # function | method
    is_async: bool = False
    inputs: tuple[UntrustedInput, ...] = ()

    @property
    def names(self) -> set[str]:
        return set(self.parameters)


@dataclass(frozen=True)
class PyFunction:
    name: str
    start_line: int
    end_line: int
    parameters: tuple[str, ...]
    indent: str
    route: str | None = None
    methods: tuple[str, ...] = ()
    inputs: tuple[UntrustedInput, ...] = ()
    returns_directly: str | None = None
    node: Any = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class ModuleScope:
    """A finding with no enclosing callable: the sink runs once, when the module is imported.

    There is no function for a generated test to call, so the template rewrites the sink in
    place exactly as it would inside one and the proof drives the module by loading it. What
    decides whether a proof is possible at all is `driver`: how the tainted value enters the
    module, and therefore what a test can set before the import that runs the sink.

    `driver` is `env` (the module reads `process.env.NAME` / `os.environ[NAME]`), `argv` (it
    reads `process.argv[i]` / `sys.argv[i]`), `config` (it reads a member of a module it
    requires or imports at the top level), or None when the value comes from a call the test
    cannot reach, which is `module_scope_source_not_controllable`.

    It carries the same bounds and parameter fields a function site does, because the template
    reads only those: the scope is the whole file and it binds no parameters.
    """

    end_line: int
    driver: str | None = None
    # The environment name, the argv index, or the module specifier, by driver.
    key: str = ""
    # For `config`, the member read off the required module (`config.dsn` gives `dsn`).
    member: str | None = None
    start_line: int = 1
    parameters: tuple[str, ...] = ()
    route: str | None = None
    methods: tuple[str, ...] = ()
    indent: str = ""
    inputs: tuple[UntrustedInput, ...] = ()
    returns_directly: bool = False

    @property
    def names(self) -> set[str]:
        return set()


@dataclass(frozen=True)
class SiteError(Exception):
    code: str

    def __str__(self) -> str:
        return self.code


def _finding_line(finding: FindingSnapshot) -> int:
    return max(1, int(finding.line_start or 1))


def module_directory(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


# --- JavaScript -----------------------------------------------------------------------------

def js_strip_strings(source: str) -> str:
    """Blanks string and comment contents so brackets inside them do not count, keeping newlines."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch in "'\"`":
            quote = ch
            out.append(quote)
            i += 1
            depth = 0
            while i < n:
                c = source[i]
                if c == "\\":
                    out.append("  ")
                    i += 2
                    continue
                if quote == "`" and source.startswith("${", i):
                    depth += 1
                    out.append("${")
                    i += 2
                    continue
                if quote == "`" and depth and c == "}":
                    depth -= 1
                    out.append("}")
                    i += 1
                    continue
                if c == quote and not depth:
                    out.append(quote)
                    i += 1
                    break
                out.append(c if c == "\n" or depth else " ")
                i += 1
            continue
        if source.startswith("//", i):
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("".join("\n" if c == "\n" else " " for c in source[i:end]))
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _js_block_end(stripped_lines: list[str], start_index: int) -> int | None:
    """The 0-based index of the line where the call opened on `start_index` closes."""
    depth = 0
    opened = False
    for index in range(start_index, len(stripped_lines)):
        for ch in stripped_lines[index]:
            if ch == "(":
                depth += 1
                opened = True
            elif ch == ")":
                depth -= 1
                if opened and depth == 0:
                    return index
    return None


def js_route_for_line(source: str, line: int) -> JsRoute:
    """The Express route handler that encloses `line`, or a SiteError naming what is missing."""
    lines = source.splitlines()
    stripped = js_strip_strings(source).splitlines()
    if line > len(lines):
        raise SiteError("finding_line_outside_file")
    for index in range(line - 1, -1, -1):
        match = _JS_ROUTE_RE.match(lines[index])
        if not match:
            continue
        end = _js_block_end(stripped, index)
        if end is None or end < line - 1:
            continue
        head = "\n".join(lines[index : min(len(lines), index + 3)])
        handler = _JS_HANDLER_RE.search(head[match.end() :]) if match.end() < len(head) else None
        if not handler:
            raise SiteError("route_handler_signature_not_derived")
        req = handler.group("req") or handler.group("req2")
        res = handler.group("res") or handler.group("res2")
        inputs: list[UntrustedInput] = []
        seen: set[str] = set()
        for number in range(index + 1, end + 1):
            for found in _JS_INPUT_RE.finditer(lines[number - 1]):
                if found.group("req") != req:
                    continue
                name = found.group("name") or found.group("bracket")
                if not name or found.group(0) in seen:
                    continue
                seen.add(found.group(0))
                inputs.append(UntrustedInput(found.group("source"), name, found.group(0), number))
        return JsRoute(match.group("owner"), match.group("method"), match.group("route"), index + 1, end + 1, req, res, tuple(inputs))
    raise SiteError("enclosing_route_not_found")


_JS_FUNCTION_RE = re.compile(
    r"^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?(?:"
    r"function\s+(?P<name>[\w$]+)\s*\((?P<params>[^()]*)\)"
    r"|(?:const|let|var)\s+(?P<name2>[\w$]+)\s*=\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\((?P<params2>[^()]*)\)\s*(?:=>\s*)?"
    r")"
)
# `module.exports.load = function (name) {` and `exports.load = (name) => {`: a declaration whose
# name is the exported one, so a proof reaches it the same way it reaches a const binding.
_JS_EXPORT_FUNCTION_RE = re.compile(
    r"^\s*(?:module\.)?exports\.(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?"
    r"\((?P<params>[^()]*)\)\s*(?:=>\s*)?(?=\{)"
)
# A method in a class body or an object literal: `read(name) {`, `async read(name) {`,
# `static read(name) {`. The same line shape opens a control-flow block, so the keywords that
# take a parenthesized head are refused by name rather than by a longer pattern.
_JS_METHOD_RE = re.compile(
    r"^\s*(?:static\s+)?(?:async\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^()]*)\)\s*(?=\{)"
)
# `read: function (name) {` and `read: (name) => {` inside an object literal.
_JS_METHOD_PROPERTY_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?"
    r"\((?P<params>[^()]*)\)\s*(?:=>\s*)?(?=\{)"
)
# Words that open a parenthesized block and are not method names.
_JS_BLOCK_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "with", "do", "else", "try", "return", "function",
     "const", "let", "var", "class", "export", "import", "new", "typeof", "void", "delete",
     "await", "yield", "case", "in", "of", "instanceof"}
)
_JS_MEMBER_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:const|let|var)\s+(?P<name>[\w$]+)\s*=\s*(?P<root>[\w$]+)(?P<member>(?:\.[\w$]+)*)\s*;?\s*$"
)


def _js_brace_end(stripped_lines: list[str], start_index: int, column: int = 0) -> int | None:
    """The 0-based index of the line closing the block that opens at or after `column`.

    The column matters: a destructured parameter list carries its own braces, and counting those
    would close the function on its own signature line.
    """
    depth = 0
    opened = False
    for index in range(start_index, len(stripped_lines)):
        for ch in stripped_lines[index][column if index == start_index else 0 :]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return index
    return None


def _js_declaration(text: str) -> tuple[str, str, str, int] | None:
    """`(name, parameter text, kind, end offset)` for a function a line opens, or None.

    The four shapes are the ones the corpus and the live files carry: a declaration or a const
    binding (`function parse(raw) {`, `const parse = (raw) => {`), an export assignment
    (`exports.parse = (raw) => {`), a class or object-literal method (`parse(raw) {`), and an
    object-literal property (`parse: (raw) => {`).
    """
    match = _JS_FUNCTION_RE.match(text)
    if match:
        declared = match.group("params") if match.group("name") else match.group("params2")
        return match.group("name") or match.group("name2"), declared, "function", match.end()
    match = _JS_EXPORT_FUNCTION_RE.match(text)
    if match:
        return match.group("name"), match.group("params"), "function", match.end()
    for pattern in (_JS_METHOD_PROPERTY_RE, _JS_METHOD_RE):
        match = pattern.match(text)
        if match and match.group("name") not in _JS_BLOCK_KEYWORDS:
            return match.group("name"), match.group("params"), "method", match.end()
    return None


def js_function_for_line(source: str, line: int) -> JsFunction:
    """The named function enclosing `line`, or a SiteError naming what is missing.

    The JavaScript families whose finding sits inside a request handler are found with
    `js_route_for_line`. This is for every other enclosing scope: a repair of a module's own
    function is proven by calling that function, so the proof needs its name and its parameters.
    A parameter list with a default, a rest element, or destructuring cannot be lined up with
    arguments, and says so rather than being called with a list that does not match.
    """
    lines = source.splitlines()
    stripped = js_strip_strings(source).splitlines()
    if line > len(lines):
        raise SiteError("finding_line_outside_file")
    for index in range(min(line, len(lines)) - 1, -1, -1):
        found = _js_declaration(lines[index])
        if not found or "{" not in stripped[index][found[3] :]:
            continue
        name, declared, kind, offset = found
        end = _js_brace_end(stripped, index, offset)
        if end is None or end < line - 1:
            continue
        written = [item.strip() for item in declared.split(",") if item.strip()]
        if any(not re.fullmatch(r"[\w$]+", item) for item in written):
            raise SiteError("function_parameters_not_plain_names")
        returns = bool(re.match(r"^\s*return\s", lines[line - 1]))
        is_async = bool(re.search(r"(?<![\w$])async(?![\w$])", lines[index][: offset]))
        return JsFunction(name, index + 1, end + 1, tuple(written), returns, kind, is_async)
    raise SiteError("enclosing_function_not_found")


def scope_lines_near(start_line: int, end_line: int, line: int) -> list[int]:
    """Every line of a scope, nearest the finding first: back to its start, then on to its end.

    A rule reports the line its *pattern* opens on, which for a path helper is often the function
    signature rather than the `path.join` inside it. Scanning only backwards from the finding
    misses the sink in that case, and scanning the scope in source order would pick the wrong one
    when a function holds two.
    """
    anchor = min(max(line, start_line), end_line)
    return list(range(anchor, start_line - 1, -1)) + list(range(anchor + 1, end_line + 1))


_JS_ENV_RE = re.compile(r"process\.env(?:\.(?P<name>[\w$]+)|\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])")
_JS_ARGV_RE = re.compile(r"process\.argv\s*\[\s*(?P<index>\d+)\s*\]")
_JS_REQUIRE_CALL_RE = re.compile(r"require\(\s*['\"](?P<module>[^'\"]+)['\"]\s*\)")
_JS_TOP_BINDING_RE = re.compile(
    r"^(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=]+?)?=\s*(?P<value>.+?);?\s*$"
)
# `import x from 'm'`, `import { a, b } from 'm'`, `import * as x from 'm'`.
_JS_TOP_IMPORT_RE = re.compile(
    r"^import\s+(?:(?P<default>[A-Za-z_$][\w$]*)|\*\s*as\s+(?P<star>[A-Za-z_$][\w$]*)|\{(?P<named>[^}]*)\})"
    r"(?:\s*,\s*\{[^}]*\})?\s+from\s+['\"](?P<module>[^'\"]+)['\"]"
)
# How far back a module-scope taint walk follows assignments. A value the sink reads is bound
# within a few statements of it in every shape the corpus carries, and an unbounded walk over a
# whole file resolves names that only share a spelling.
_MODULE_TAINT_HOPS = 6


def _js_top_bindings(lines: list[str]) -> dict[str, str]:
    """Module-level `const/let/var NAME = value` and `import` bindings, by bound name.

    Column zero is the test for module scope: everything a function binds is indented, and a
    declaration that is not is the module's own. It is lexical, like the rest of this file.
    """
    bindings: dict[str, str] = {}
    for text in lines:
        if not text[:1] or text[:1].isspace():
            continue
        found = _JS_TOP_BINDING_RE.match(text)
        if found:
            bindings.setdefault(found.group("name"), found.group("value"))
            continue
        imported = _JS_TOP_IMPORT_RE.match(text)
        if imported:
            specifier = f"require('{imported.group('module')}')"
            for name in [imported.group("default"), imported.group("star")]:
                if name:
                    bindings.setdefault(name, specifier)
            for item in (imported.group("named") or "").split(","):
                bound = item.split(" as ")[-1].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", bound):
                    bindings.setdefault(bound, specifier)
    return bindings


def js_module_scope(source: str, line: int) -> ModuleScope:
    """The module-scope site for `line`, with how a test can drive the value that reaches it.

    The walk starts at the sink and follows module-level bindings back a bounded number of
    hops, because that is the whole question: a `process.env` read, a `process.argv` element,
    or a member of a required module can be set before the import that runs the sink, and
    anything else cannot be reached from outside at all.
    """
    lines = source.splitlines()
    if line > len(lines):
        raise SiteError("finding_line_outside_file")
    bindings = _js_top_bindings(lines)
    texts = [lines[line - 1]]
    seen: set[str] = set()
    for _ in range(_MODULE_TAINT_HOPS):
        if not texts:
            break
        text = texts.pop(0)
        env = _JS_ENV_RE.search(text)
        if env:
            return ModuleScope(len(lines), "env", env.group("name") or env.group("bracket"))
        argv = _JS_ARGV_RE.search(text)
        if argv:
            return ModuleScope(len(lines), "argv", argv.group("index"))
        for name in _JS_IDENT_RE.findall(text):
            if name in seen or name not in bindings:
                continue
            seen.add(name)
            value = bindings[name]
            required = _JS_REQUIRE_CALL_RE.search(value)
            # Only a module of this repository is a config a test may stand in for, and only a
            # member it reads as a value: `os.userInfo()` is a call whose result no stub decides,
            # and replacing the function with a payload would break the module instead of driving
            # it. Everything else keeps walking and ends at the refusal.
            if required and required.group("module").startswith("."):
                member = re.search(rf"(?<![\w$.]){re.escape(name)}\.(?P<member>[\w$]+)(?!\s*\()", text)
                if member or f"{name}." not in text:
                    return ModuleScope(len(lines), "config", required.group("module"), member.group("member") if member else None)
                continue
            if required:
                continue
            texts.append(value)
    return ModuleScope(len(lines), None)


def js_site_for_line(source: str, line: int) -> JsRoute | JsFunction | ModuleScope:
    """The Express route that encloses `line`, else the function that does, else the module.

    The route comes first because it is the reachable entry point: when a finding sits in a
    helper a handler calls, the handler is what a proof can drive and what a repair has to keep
    working. Only a line no route encloses falls through to its own function, and a line no
    function encloses is module-scope code, which runs at import and is driven by loading it.
    """
    try:
        return js_route_for_line(source, line)
    except SiteError as exc:
        if exc.code != "enclosing_route_not_found":
            raise
    try:
        return js_function_for_line(source, line)
    except SiteError as exc:
        if exc.code != "enclosing_function_not_found":
            raise
    return js_module_scope(source, line)


def js_value_origin(lines: list[str], function: JsFunction, line: int, name: str) -> tuple[str, tuple[str, ...]] | None:
    """The parameter an identifier holds at `line` and the member path read off it, or None.

    `eval(expression)` after `const expression = body.expression;` resolves to `('body',
    ('expression',))`, which is what lets a proof place its payload where the request put it.
    One assignment is followed, because a second would be a chain the scan cannot vouch for.
    """
    if name in function.parameters:
        return name, ()
    for number in range(line - 1, function.start_line - 1, -1):
        match = _JS_MEMBER_ASSIGNMENT_RE.match(lines[number - 1])
        if not match or match.group("name") != name:
            continue
        root = match.group("root")
        return (root, tuple(part for part in match.group("member").split(".") if part)) if root in function.parameters else None
    return None


# `eval(raw)` over a single identifier: the one shape the eval family reads as data.
JS_EVAL_ARGUMENT_RE = re.compile(r"(?<![\w$.])eval\s*\(\s*(?P<arg>[A-Za-z_$][\w$]*)\s*\)")


def js_eval_site(source: str, line: int) -> tuple[JsFunction, str, tuple[str, ...]]:
    """`(function, untrusted parameter, member path)` for an `eval` of one identifier at `line`.

    The proof and the template both go through here, so both accept and refuse the same shapes
    for the same recorded reason.
    """
    function = js_function_for_line(source, line)
    lines = source.splitlines()
    found = JS_EVAL_ARGUMENT_RE.search(lines[line - 1])
    if not found:
        raise SiteError("eval_argument_not_an_identifier")
    origin = js_value_origin(lines, function, line, found.group("arg"))
    if origin is None:
        raise SiteError("eval_argument_not_request_data")
    return function, origin[0], origin[1]


def js_names_in(lines: list[str]) -> set[str]:
    return {match.group(0) for line in lines for match in _JS_IDENT_RE.finditer(js_strip_strings(line))}


def js_module_constant(source: str, name: str) -> str | None:
    """The initializer of a top-level `const NAME = ...;`, or None."""
    match = re.search(rf"^(?:const|let|var)\s+{re.escape(name)}\s*=\s*(?P<value>[^\n;]+?)\s*;?\s*$", source, re.M)
    return match.group("value") if match else None


_JS_CONSTANT_RE = re.compile(
    r"^(?P<prefix>\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*"
    r"(?::\s*[\w$.<>\[\]| ]+\s*)?=\s*)(?P<quote>['\"])(?P<literal>(?:(?!(?P=quote)).)*)(?P=quote)\s*;?\s*$"
)
_JS_PROPERTY_RE = re.compile(
    r"^(?P<prefix>\s*(?P<name>[A-Za-z_$][\w$]*|['\"][A-Za-z_$][\w$]*['\"])\s*:\s*)"
    r"(?P<quote>['\"])(?P<literal>(?:(?!(?P=quote)).)*)(?P=quote)\s*,?\s*$"
)


def js_literal_assignment(source: str, line: int) -> tuple[str, str, str, str] | None:
    """`(name, literal, quote, kind)` for a string literal bound at `line`, or None.

    Two shapes, which are the two the September 2026 replay found: a declared constant
    (`const apiKey = "..."`, with or without `export` and a TypeScript annotation) and an
    object property used as a config key (`apiKey: "..."`). `kind` is `"constant"` or
    `"property"`; the caller needs to know because only a constant can be read back as a
    module value. The line is read lexically after strings and comments are blanked, so a
    literal that merely looks like an assignment inside a comment is not one.
    """
    lines = source.splitlines()
    if line < 1 or line > len(lines):
        return None
    text = lines[line - 1]
    blanked = js_strip_strings(source).splitlines()[line - 1]
    if blanked.lstrip().startswith(("//", "*", "/*")):
        return None
    for pattern, kind in ((_JS_CONSTANT_RE, "constant"), (_JS_PROPERTY_RE, "property")):
        match = pattern.match(text)
        if not match:
            continue
        literal = match.group("literal")
        if not literal or "\\" in literal or "${" in literal:
            # An escape or an interpolation means the literal in the source is not the
            # value, so the test could not assert on it and the rewrite could not be exact.
            return None
        return match.group("name").strip("'\""), literal, match.group("quote"), kind
    return None


def js_literal_assignment_in_span(
    source: str, line_start: int, line_end: int | None
) -> tuple[int, tuple[str, str, str, str]] | None:
    """The first line in a finding's own range that binds a string literal, and what it binds.

    A rule that matches a multi-line object literal reports the line the *pattern* opens on,
    not the line of the credential inside it: `cwe-798.js-session-secret-literal` points at
    `app.use(session({` and the secret is on the next line. The vulnerable-corpus run
    (docs/validation/vulnerable-corpus-2026-09.md) found four such sites in two repositories.

    The search never leaves the finding's range, so it can only find a literal the rule
    already matched, and it takes the first one: a second credential in the same object is a
    second finding with a range of its own.
    """
    start = max(1, int(line_start or 1))
    end = max(start, int(line_end or start))
    for line in range(start, end + 1):
        assignment = js_literal_assignment(source, line)
        if assignment is not None:
            return line, assignment
    return None


def js_environment_name(identifier: str) -> str:
    """The environment variable an identifier names: `apiKey` -> `API_KEY`, `API_KEY` -> `API_KEY`."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", identifier)
    return re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9]+", "_", spaced)).strip("_").upper()


def js_module_exports_name(source: str, name: str) -> bool:
    """Whether the module makes `name` readable to a caller under that name."""
    stripped = js_strip_strings(source)
    escaped = re.escape(name)
    patterns = (
        rf"module\.exports\s*=\s*\{{[^}}]*(?<![\w$]){escaped}(?![\w$])",
        rf"module\.exports\.{escaped}\s*=",
        rf"exports\.{escaped}\s*=",
        rf"^\s*export\s+(?:const|let|var)\s+{escaped}(?![\w$])",
        # `export function parse(...)`, with or without `async`: an ESM module's own declaration
        # is its export, and reading it as unexported refused every ESM helper.
        rf"^\s*export\s+(?:default\s+)?(?:async\s+)?function\s*\*?\s+{escaped}(?![\w$])",
        rf"^\s*export\s*\{{[^}}]*(?<![\w$]){escaped}(?![\w$])",
    )
    return any(re.search(pattern, stripped, re.M) for pattern in patterns)


def js_require_line(source: str, module: str) -> tuple[int, str] | None:
    """The 1-based line and text of the top-level require of `module` (with or without node:)."""
    pattern = re.compile(rf"""^(?:const|let|var)\s+.+?=\s*require\(\s*['"](?:node:)?{re.escape(module)}['"]\s*\)""")
    for number, text in enumerate(source.splitlines(), 1):
        if pattern.match(text):
            return number, text
    return None


def js_bound_names(source: str, module: str) -> tuple[str | None, set[str]]:
    """How a module is bound: (`namespace name` or None, {destructured names})."""
    found = js_require_line(source, module)
    if not found:
        return None, set()
    text = found[1]
    braces = re.match(r"^(?:const|let|var)\s+\{([^}]*)\}\s*=", text)
    if braces:
        names = set()
        for part in braces.group(1).split(","):
            item = part.strip()
            if ":" in item:
                item = item.split(":", 1)[1].strip()
            if item:
                names.add(item)
        return None, names
    plain = re.match(r"^(?:const|let|var)\s+([\w$]+)\s*=", text)
    return (plain.group(1) if plain else None), set()


# --- Python ---------------------------------------------------------------------------------

def python_tree(source: str) -> ast.Module:
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        raise SiteError("python_source_not_parsed") from exc


def _route_of(node: ast.AST) -> tuple[str | None, tuple[str, ...]]:
    for decorator in getattr(node, "decorator_list", []):
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        attribute = decorator.func.attr
        if attribute not in ("route", "get", "post", "put", "delete", "patch"):
            continue
        if not decorator.args or not isinstance(decorator.args[0], ast.Constant) or not isinstance(decorator.args[0].value, str):
            continue
        rule = decorator.args[0].value
        methods: tuple[str, ...] = ("GET",)
        if attribute != "route":
            methods = (attribute.upper(),)
        for keyword in decorator.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                methods = tuple(str(item.value).upper() for item in keyword.value.elts if isinstance(item, ast.Constant))
        return rule, methods
    return None, ()


def _direct_return_name(node: ast.AST) -> str | None:
    """The name a function returns when its body is `x = ...; return x` or `return <call>`; else None."""
    body = list(getattr(node, "body", []))
    if not body:
        return None
    last = body[-1]
    if isinstance(last, ast.Return) and isinstance(last.value, ast.Name):
        return last.value.id
    if isinstance(last, ast.Return) and isinstance(last.value, ast.Call):
        return "__return__"
    return None


def python_function_for_line(source: str, line: int) -> PyFunction:
    """The innermost function or Flask view whose body contains `line`."""
    tree = python_tree(source)
    lines = source.splitlines()
    best: ast.AST | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or node.lineno):
            if best is None or node.lineno >= best.lineno:
                best = node
    if best is None:
        raise SiteError("enclosing_function_not_found")
    parameters = tuple(arg.arg for arg in best.args.posonlyargs + best.args.args)
    if best.args.kwonlyargs or best.args.vararg or best.args.kwarg:
        raise SiteError("function_signature_not_supported")
    rule, methods = _route_of(best)
    inputs: list[UntrustedInput] = []
    seen: set[str] = set()
    for number in range(best.lineno, (best.end_lineno or best.lineno) + 1):
        for found in _PY_REQUEST_RE.finditer(lines[number - 1]):
            name = found.group("name") or found.group("getname")
            if not name or found.group(0) in seen:
                continue
            seen.add(found.group(0))
            inputs.append(UntrustedInput(found.group("source"), name, found.group(0), number))
    first_line = lines[best.body[0].lineno - 1] if best.body else ""
    indent = first_line[: len(first_line) - len(first_line.lstrip())]
    return PyFunction(
        best.name,
        best.lineno,
        best.end_lineno or best.lineno,
        parameters,
        indent,
        rule,
        methods,
        tuple(inputs),
        _direct_return_name(best),
        best,
    )


def python_module_assignment(source: str, line: int) -> tuple[str, str, str] | None:
    """`(name, literal, quote)` for a module-level `NAME = "literal"` at `line`, or None."""
    tree = python_tree(source)
    for node in tree.body:
        if not isinstance(node, ast.Assign) or node.lineno != line:
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return None
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return None
        text = source.splitlines()[line - 1]
        match = re.match(r"^(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['\"])(?P<literal>.*)(?P=quote)\s*(?:#.*)?$", text)
        if not match or match.group("name") != node.targets[0].id:
            return None
        return node.targets[0].id, match.group("literal"), match.group("quote")
    return None


def python_import_anchor(source: str, before_line: int | None = None) -> tuple[int, bool]:
    """Where a new top-level import goes: `(line, after)`.

    After the last top-level import that precedes `before_line` (the line that needs the name),
    else after the last import in the module, after the docstring when there is none, else
    before the first line.
    """
    tree = python_tree(source)
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    preceding = [node for node in imports if before_line is None or node.lineno < before_line]
    if preceding:
        return preceding[-1].end_lineno or preceding[-1].lineno, True
    if imports:
        return imports[-1].end_lineno or imports[-1].lineno, True
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
        return tree.body[0].end_lineno or tree.body[0].lineno, True
    return 1, False


def python_flask_app_name(source: str) -> str | None:
    match = re.search(r"^(?P<name>[A-Za-z_]\w*)\s*=\s*Flask\(", source, re.M)
    return match.group("name") if match else None


def python_module_value(source: str, name: str) -> str | None:
    match = re.search(rf"^{re.escape(name)}\s*=\s*(?P<value>[^\n#]+?)\s*$", source, re.M)
    return match.group("value") if match else None


def _py_environment_read(node: ast.AST) -> str | None:
    """The environment name an expression reads, or None: `os.environ[X]`, `.get(X)`, `getenv(X)`."""
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
        key = node.slice
        return key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
        first = node.args[0]
        name = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
        if node.func.attr == "getenv" or (
            node.func.attr == "get" and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "environ"
        ):
            return name
    return None


def _py_argv_index(node: ast.AST) -> str | None:
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "argv"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, int)
    ):
        return str(node.slice.value)
    return None


def python_module_scope(source: str, line: int) -> ModuleScope:
    """The module-scope site for `line`, with how a test can drive the value that reaches it.

    The Python half of `js_module_scope`, over the `ast` rather than the text. Module-level
    assignments are the whole binding table. Two of the three drivers apply here, `os.environ`
    and `sys.argv`: there is no `config` driver, because a Python import names a module by a
    dotted path with no marker of whether it is this repository's or the standard library's,
    and standing in for the wrong one would drive nothing.
    """
    tree = python_tree(source)
    lines = source.splitlines()
    end = len(lines)
    bindings: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            bindings.setdefault(node.targets[0].id, node.value)
    statement = next(
        (node for node in tree.body if node.lineno <= line <= (node.end_lineno or node.lineno)),
        None,
    )
    if statement is None:
        return ModuleScope(end, None)
    queue: list[ast.AST] = [statement]
    seen: set[str] = set()
    for _ in range(_MODULE_TAINT_HOPS):
        if not queue:
            break
        current = queue.pop(0)
        for node in ast.walk(current):
            name = _py_environment_read(node)
            if name:
                return ModuleScope(end, "env", name)
            index = _py_argv_index(node)
            if index is not None:
                return ModuleScope(end, "argv", index)
        for node in ast.walk(current):
            if isinstance(node, ast.Name) and node.id in bindings and node.id not in seen:
                seen.add(node.id)
                queue.append(bindings[node.id])
    return ModuleScope(end, None)


def python_site_for_line(source: str, line: int) -> PyFunction | ModuleScope:
    """The function or Flask view that encloses `line`, else the module it sits at the top of."""
    try:
        return python_function_for_line(source, line)
    except SiteError as exc:
        if exc.code != "enclosing_function_not_found":
            raise
    return python_module_scope(source, line)


def enclosing_site(snapshot: Snapshot, finding: FindingSnapshot, language: str) -> JsRoute | JsFunction | PyFunction | ModuleScope:
    source = snapshot.full_content(finding.affected_path)
    line = _finding_line(finding)
    if language == "python":
        return python_site_for_line(source, line)
    return js_site_for_line(source, line)
