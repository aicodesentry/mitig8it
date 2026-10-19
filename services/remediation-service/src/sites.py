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
# Parameter names that are a continuation the function reports through. A repair of a
# callback-style helper refuses by calling back with an Error, which is how it already
# reports every other failure; throwing at a caller that is waiting on a callback would be
# a behaviour change on top of the repair.
JS_CALLBACK_PARAMETERS = frozenset({"callback", "cb", "done", "next"})
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
class JsParameter:
    """One parameter as written, in the four forms a generated call has to line up with.

    A plain name and a name with a default are both passed positionally. A rest element takes
    however many arguments are left, so a proof passes it nothing. A destructured parameter binds
    no name at all: what the body reads are its `members`, and a proof reaches one of them by
    passing an object literal with that key.
    """

    text: str
    name: str | None = None
    has_default: bool = False
    rest: bool = False
    members: tuple[str, ...] = ()

    @property
    def bound_names(self) -> tuple[str, ...]:
        """Every identifier this parameter puts in the function's scope."""
        return (self.name,) if self.name else self.members


# A parameter list item: `name`, `name = default`, `...rest`, or `{ a, b }`, each with an
# optional TypeScript annotation. Nested destructuring and array patterns are deliberately not
# here: a proof that guessed at their shape would build a call that does not match.
_JS_PARAMETER_RE = re.compile(
    r"^(?P<rest>\.\.\.\s*)?(?:(?P<name>[A-Za-z_$][\w$]*)|\{(?P<members>[^{}]*)\})"
    r"(?:\s*\?)?(?:\s*:\s*(?P<annotation>[^=]+?))?(?:\s*=\s*(?P<default>.+))?$"
)


def js_parameters(declared: str) -> tuple[JsParameter, ...] | None:
    """The parameter list as a model, or None when a form in it cannot be lined up with a call."""
    blanked = js_strip_strings(declared)
    items = _js_split_top_level(declared, blanked, ",")
    if items is None:
        return None
    parsed: list[JsParameter] = []
    for item in items:
        match = _JS_PARAMETER_RE.match(item.strip())
        if not match:
            return None
        members = match.group("members")
        if members is not None:
            names = tuple(
                part.split(":", 1)[-1].strip() if ":" in part else part.strip()
                for part in members.split(",")
                if part.strip()
            )
            if not names or any(not re.fullmatch(r"[A-Za-z_$][\w$]*", name) for name in names):
                return None
            parsed.append(JsParameter(item.strip(), None, match.group("default") is not None, False, names))
            continue
        parsed.append(
            JsParameter(item.strip(), match.group("name"), match.group("default") is not None, bool(match.group("rest")))
        )
    return tuple(parsed)


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
    # Every identifier the parameter list puts in scope, which for a destructured parameter is
    # its members rather than the parameter. Anything that needs a *position* reads
    # `parameter_model` instead, because a destructured parameter contributes no name to this.
    parameters: tuple[str, ...]
    returns_directly: bool = False
    kind: str = "function"  # function | method
    is_async: bool = False
    inputs: tuple[UntrustedInput, ...] = ()
    parameter_model: tuple[JsParameter, ...] = ()

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
        model = js_parameters(declared)
        if model is None:
            raise SiteError("function_parameters_not_plain_names")
        written = [name for parameter in model for name in parameter.bound_names]
        returns = bool(re.match(r"^\s*return\s", lines[line - 1]))
        is_async = bool(re.search(r"(?<![\w$])async(?![\w$])", lines[index][: offset]))
        inputs = _js_function_inputs(lines, index + 1, end + 1, tuple(written))
        # A function whose first parameter is read as `req.params`/`.query`/`.body` is a route
        # handler the module never registered with Express: the repository wires it up somewhere
        # this snapshot may not contain. Calling it with a string would pass a payload where a
        # request object goes, so a proof drives it with a request and a recording response
        # instead, which is what `kind` tells the generator.
        # Read off the positional model, not the bound names: `({ params }, res)` binds `params`
        # first and `res` second, and a handler is a function whose first *parameter* is the
        # request object, which a destructured one is not.
        first = model[0].name if model else None
        handler = bool(inputs) and first is not None and len(model) >= 2 and all(
            item.expression.startswith(first + ".") for item in inputs
        )
        return JsFunction(
            name, index + 1, end + 1, tuple(written), returns, "handler" if handler else kind, is_async, inputs, model
        )
    raise SiteError("enclosing_function_not_found")


def _js_function_inputs(lines: list[str], start: int, end: int, parameters: tuple[str, ...]) -> tuple[UntrustedInput, ...]:
    """The `<parameter>.params|query|body` reads in a function's body, in the order it makes them."""
    inputs: list[UntrustedInput] = []
    seen: set[str] = set()
    for number in range(start, end + 1):
        for found in _JS_INPUT_RE.finditer(lines[number - 1]):
            name = found.group("name") or found.group("bracket")
            if not name or found.group("req") not in parameters or found.group(0) in seen:
                continue
            seen.add(found.group(0))
            inputs.append(UntrustedInput(found.group("source"), name, found.group(0), number))
    return tuple(inputs)


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


# --- signing keys passed as a literal ---------------------------------------------------------
#
# `jwt.encode(payload, "k")`, `hmac.new(b"k", ...)`, `crypto.createHmac("sha256", "k")`: the key
# is not bound to a name, so there is no identifier to derive an environment name from. The
# call names what the key is for instead, and that is the name the repair reads.

@dataclass(frozen=True)
class SigningKeyCall:
    line: int
    start: int  # column of the key literal's first character, including a bytes prefix
    end: int  # column one past its closing quote
    literal: str  # the text between the quotes
    variable: str  # the environment variable the repair reads
    encoded: bool  # a Python bytes literal, so the repair has to encode the str it reads


# (callee, index of the key argument, environment name). The callees are the ones the
# `cwe-798.*-literal-signing-key` rules match, and nothing else.
_PY_SIGNING_CALLS = (
    (re.compile(r"(?<![\w.])jwt\.(?:encode|decode)\s*\("), 1, "JWT_SECRET"),
    (re.compile(r"(?<![\w.])hmac\.new\s*\("), 0, "HMAC_SECRET"),
)
_JS_SIGNING_CALLS = (
    (re.compile(r"(?<![\w$.])(?:crypto\.)?createHmac\s*\("), 1, "HMAC_SECRET"),
    (re.compile(r"(?<![\w$.])crypto\.create(?:Cipher|Decipher)iv\s*\("), 1, "ENCRYPTION_KEY"),
    (re.compile(r"(?<![\w$.])(?:jwt|jsonwebtoken)\.(?:sign|verify)\s*\("), 1, "JWT_SECRET"),
)
_PY_KEY_LITERAL_RE = re.compile(r"(?P<prefix>[bB]?)(?P<quote>['\"])(?P<literal>[^'\"\\\n]+)(?P=quote)(?=\s*(?:[,)]|$))")
_JS_KEY_LITERAL_RE = re.compile(r"(?P<prefix>)(?P<quote>['\"])(?P<literal>[^'\"\\\n]+)(?P=quote)(?=\s*(?:[,)]|$))")


def _skip_call_argument(text: str, i: int) -> int | None:
    """The index of the `,` that ends the argument starting at `i`, or None when it does not end
    on this line or ends the call instead."""
    depth = 0
    quote = None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return None
            depth -= 1
        elif ch == "," and depth == 0:
            return i
        i += 1
    return None


def signing_key_call(source: str, line_start: int | None, line_end: int | None, language: str) -> SigningKeyCall | None:
    """The literal key of a signing or cipher call in the finding's span, or None.

    Only a key written as a plain quoted literal on the same line as its call is recognized: a
    template string, an escape, a concatenation or a key on a continuation line is a shape the
    rewrite cannot place exactly, and the model reads it instead.
    """
    calls, literal_re = (_PY_SIGNING_CALLS, _PY_KEY_LITERAL_RE) if language == "python" else (_JS_SIGNING_CALLS, _JS_KEY_LITERAL_RE)
    lines = source.splitlines()
    start = max(1, int(line_start or 1))
    end = max(start, int(line_end or start))
    for number in range(start, min(end, len(lines)) + 1):
        text = lines[number - 1]
        for callee, index, variable in calls:
            for found in callee.finditer(text):
                i = found.end()
                for _ in range(index):
                    comma = _skip_call_argument(text, i)
                    if comma is None:
                        break
                    i = comma + 1
                else:
                    while i < len(text) and text[i] in " \t":
                        i += 1
                    key = literal_re.match(text, i)
                    if key:
                        return SigningKeyCall(number, key.start(), key.end(), key.group("literal"), variable, bool(key.group("prefix")))
    return None


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


@dataclass(frozen=True)
class JsModuleBinding:
    """How a file already names a core module, or how a new import of it would be written.

    `name` is the namespace identifier a repair writes `name.resolve(...)` against. `present`
    says whether the file already binds it: when it does not, `import_line` is the statement to
    insert and `import_line_number` is where, and both are None once it does.
    """

    name: str
    present: bool
    style: str  # commonjs | esm
    members: frozenset[str] = frozenset()
    import_line: str | None = None
    import_line_number: int | None = None


# `import x from 'm'` and `export ...` are the two statements that make a file a module Node
# loads as ESM regardless of extension, and a file that carries either is one an inserted
# `const x = require(...)` would break.
_JS_ESM_MARKER_RE = re.compile(r"^\s*(?:import\s+[^(]|import\s*\{|import\s+['\"]|export\s+(?:default|const|let|var|function|class|\{|\*))", re.MULTILINE)
_JS_MODULE_IMPORT_RE = re.compile(
    r"^\s*import\s+(?:(?P<default>[A-Za-z_$][\w$]*)|\*\s*as\s+(?P<star>[A-Za-z_$][\w$]*)|\{(?P<named>[^}]*)\})"
    r"(?:\s*,\s*(?:\{(?P<also>[^}]*)\}|\*\s*as\s+(?P<star2>[A-Za-z_$][\w$]*)))?\s+from\s+['\"](?:node:)?(?P<module>[^'\"]+)['\"]"
)
_JS_MODULE_REQUIRE_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+(?:(?P<name>[A-Za-z_$][\w$]*)|\{(?P<named>[^}]*)\})\s*"
    r"(?::\s*[^=]+?)?=\s*require\(\s*['\"](?:node:)?(?P<module>[^'\"]+)['\"]\s*\)"
)
# Any statement that opens a file's import block, so an inserted import lands with the others
# rather than above a licence header or below the first use.
_JS_IMPORT_STATEMENT_RE = re.compile(
    r"^\s*(?:import\s|export\s+.*\sfrom\s|(?:const|let|var)\s+.+?=\s*require\()"
)


def _js_uses_semicolons(blanked_lines: list[str]) -> bool:
    """Whether the file's own import statements end in a semicolon, so an inserted one matches."""
    statements = [text.rstrip() for text in blanked_lines if _JS_IMPORT_STATEMENT_RE.match(text)]
    if not statements:
        return False
    return sum(text.endswith(";") for text in statements) * 2 >= len(statements)


def js_module_style(source: str) -> str:
    """Whether a file is written with `import`/`export` or with `require`."""
    return "esm" if _JS_ESM_MARKER_RE.search(js_strip_strings(source)) else "commonjs"


def _js_destructured_names(text: str) -> set[str]:
    names: set[str] = set()
    for part in text.split(","):
        item = part.strip()
        if ":" in item:
            item = item.split(":", 1)[1].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", item):
            names.add(item)
    return names


def js_import_anchor(source: str) -> int:
    """The 1-based line an inserted import goes before: the top of the file's import block.

    A file opens with a licence header far more often than not, so inserting at line 1 would
    put the import above it. The first import or require statement is the top of the block,
    and a file with neither takes the first line that is not a comment, a directive, or blank.
    """
    lines = js_strip_strings(source).splitlines()
    for number, text in enumerate(lines, 1):
        if _JS_IMPORT_STATEMENT_RE.match(text):
            return number
    in_block_comment = False
    for number, text in enumerate(lines, 1):
        stripped = text.strip()
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            in_block_comment = "*/" not in stripped
            continue
        # `js_strip_strings` has blanked the contents, so a directive prologue such as
        # `'use strict';` reads as an empty quoted statement here rather than by its text.
        if not stripped or stripped.startswith("//") or re.fullmatch(r"['\"][^'\"]*['\"]\s*;?", stripped):
            continue
        return number
    return 1


def js_identifier_is_bound(source: str, name: str) -> bool:
    """Whether the file already declares `name` as something of its own.

    An inserted `import path from 'node:path'` is only correct in a file where nothing else is
    called `path`; `routes/videoHandler.ts` in the vulnerable corpus binds `const path =
    videoPath()` inside its handler, and an import next to that declaration would be shadowed
    at exactly the line the repair rewrites.
    """
    escaped = re.escape(name)
    stripped = js_strip_strings(source)
    patterns = (
        rf"(?:const|let|var)\s+{escaped}(?![\w$])",
        rf"function\s*\*?\s+{escaped}(?![\w$])",
        rf"class\s+{escaped}(?![\w$])",
        # A parameter or a catch binding: the name is introduced by the list it sits in.
        rf"\(\s*{escaped}\s*[,)]",
        rf",\s*{escaped}\s*[,)]\s*(?:=>|\{{)",
        rf"catch\s*\(\s*{escaped}\s*\)",
    )
    return any(re.search(pattern, stripped, re.MULTILINE) for pattern in patterns)


def js_module_binding(source: str, module: str, preferred: str) -> JsModuleBinding:
    """How `module` is bound in `source`, or how an import of it would be written.

    Four binding styles reach this on the vulnerable corpus and all four are recognized: a
    CommonJS require under the module's own name or an alias, a destructuring require, an ESM
    default or namespace import, and an ESM named import. `node:path` and `path` are the same
    module, so either spelling counts as bound.

    When nothing binds it the result says so and carries the statement to insert, written in
    the file's own style so a repair does not mix `require` into an ESM module.
    """
    # Read from the raw lines, not the blanked ones: `js_strip_strings` empties string contents,
    # which is exactly where the module specifier is. A comment that looks like an import is
    # ruled out by the blanked line at the same index instead.
    blanked = js_strip_strings(source).splitlines()
    namespace: str | None = None
    members: set[str] = set()
    for index, text in enumerate(source.splitlines()):
        if index >= len(blanked) or blanked[index].lstrip().startswith(("//", "*", "/*")):
            continue
        for pattern in (_JS_MODULE_IMPORT_RE, _JS_MODULE_REQUIRE_RE):
            match = pattern.match(text)
            if not match or match.group("module") != module:
                continue
            groups = match.groupdict()
            for key in ("default", "star", "star2", "name"):
                if groups.get(key) and namespace is None:
                    namespace = groups[key]
            for key in ("named", "also"):
                if groups.get(key):
                    members |= _js_destructured_names(groups[key])
    style = js_module_style(source)
    if namespace is not None:
        return JsModuleBinding(namespace, True, style, frozenset(members))
    statement = (
        f"import {preferred} from 'node:{module}'" if style == "esm" else f"const {preferred} = require('node:{module}')"
    )
    if _js_uses_semicolons(blanked):
        statement += ";"
    return JsModuleBinding(
        preferred, False, style, frozenset(members), statement, js_import_anchor(source)
    )


@dataclass(frozen=True)
class JsPathJoin:
    """A `path.join`/`path.resolve` call on one line: its text, its base, and its last argument.

    `base` is every argument but the last, exactly as written, because `path.resolve` takes a
    varargs base and a repair re-resolves it unchanged. `user_input` is the last argument, which
    is the one a traversal payload arrives in.
    """

    line: int
    text: str
    base: str
    user_input: str
    # True when the site is a string composition rather than a `path.join` call. Both halves are
    # then already string-typed expressions, so a repair does not wrap them in `String(...)`
    # again, and `text` is the sink's argument rather than a call.
    composed: bool = False


def _js_split_arguments(raw: str, blanked: str) -> list[str] | None:
    """The top-level arguments of an argument list, or None when the brackets do not balance."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, ch in enumerate(blanked):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return None
        elif ch == "," and depth == 0:
            parts.append(raw[start:index].strip())
            start = index + 1
    if depth != 0:
        return None
    parts.append(raw[start:].strip())
    return [part for part in parts if part]


def js_path_join_on_line(text: str, names: tuple[str, ...]) -> JsPathJoin | None:
    """The first `<binding>.join(...)` or `.resolve(...)` on one line, parsed by its brackets.

    A regular expression cannot do this: `path.resolve(__dirname, 'static/create', name)` takes
    three arguments, and a pattern that reads "everything up to the first `)`" as the second one
    silently turns the last two into a comma expression. The vulnerable corpus has 35 findings
    in `dicebear/dicebear` of exactly that shape, so the call is scanned rather than matched.
    """
    blanked_line = js_strip_strings(text)
    for name in dict.fromkeys(names):
        if not name:
            continue
        for match in re.finditer(rf"(?<![\w$.]){re.escape(name)}\s*\.\s*(?:join|resolve)\s*\(", blanked_line):
            open_at = match.end() - 1
            depth = 0
            close_at = None
            for index in range(open_at, len(blanked_line)):
                if blanked_line[index] in "([{":
                    depth += 1
                elif blanked_line[index] in ")]}":
                    depth -= 1
                    if depth == 0:
                        close_at = index
                        break
            if close_at is None:
                continue
            arguments = _js_split_arguments(text[open_at + 1 : close_at], blanked_line[open_at + 1 : close_at])
            if not arguments or len(arguments) < 2:
                continue
            return JsPathJoin(0, text[match.start() : close_at + 1], ", ".join(arguments[:-1]), arguments[-1])
    return None


def js_path_join_in_scope(lines: list[str], start_line: int, end_line: int, line: int, names: tuple[str, ...]) -> JsPathJoin | None:
    """The `path.join`/`path.resolve` nearest the finding inside its scope, or None."""
    for number in scope_lines_near(start_line, end_line, line):
        found = js_path_join_on_line(lines[number - 1], names)
        if found:
            return JsPathJoin(number, found.text, found.base, found.user_input)
    return None


# The calls whose first argument is a filesystem path. A receiver is required not to be `this`,
# because `this.dialog.open(...)` and `this.snackBar.open(...)` are Angular components rather
# than filesystem sinks and the quarantined `path.traversal.user_path` rule reports both.
_JS_PATH_SINK_RE = re.compile(
    r"(?<![\w$.])(?P<receiver>[\w$]+(?:\.[\w$]+)*\.)?(?P<callee>readFile|readFileSync|createReadStream|createWriteStream"
    r"|writeFile|writeFileSync|appendFile|appendFileSync|sendFile|openSync|readdir|readdirSync|stat|statSync|lstat"
    r"|existsSync|unlink|unlinkSync|open)\s*\("
)


def js_path_sink_argument(text: str) -> tuple[str, str] | None:
    """`(call text, first argument)` for the filesystem call on a line, or None.

    The composed-path shapes are only read out of a sink's first argument, never out of any
    string on the line: `src/client/store/mcp-handler.js` in the vulnerable corpus builds a
    user-facing message from a template literal three lines from its finding, and a scan that
    took any composition would repair the message.
    """
    blanked = js_strip_strings(text)
    for match in _JS_PATH_SINK_RE.finditer(blanked):
        if (match.group("receiver") or "").startswith("this."):
            continue
        open_at = match.end() - 1
        depth = 0
        close_at = None
        for index in range(open_at, len(blanked)):
            if blanked[index] in "([{":
                depth += 1
            elif blanked[index] in ")]}":
                depth -= 1
                if depth == 0:
                    close_at = index
                    break
        if close_at is None:
            continue
        arguments = _js_split_arguments(text[open_at + 1 : close_at], blanked[open_at + 1 : close_at])
        if not arguments:
            continue
        return text[match.start() : close_at + 1], arguments[0]
    return None


def _js_concatenation_parts(expression: str) -> list[tuple[str, str]] | None:
    """`'a/' + x + '.y'` and `` `a/${x}.y` `` as [('lit', 'a/'), ('expr', 'x'), ('lit', '.y')]."""
    text = expression.strip()
    blanked = js_strip_strings(text)
    if text.startswith("`") and text.endswith("`") and blanked.count("`") == 2:
        parts: list[tuple[str, str]] = []
        index = 1
        literal: list[str] = []
        while index < len(text) - 1:
            if text.startswith("${", index):
                depth = 1
                end = index + 2
                while end < len(text) and depth:
                    if text[end] == "{":
                        depth += 1
                    elif text[end] == "}":
                        depth -= 1
                    end += 1
                if depth:
                    return None
                parts.append(("lit", "".join(literal)))
                literal = []
                parts.append(("expr", text[index + 2 : end - 1].strip()))
                index = end
                continue
            literal.append(text[index])
            index += 1
        parts.append(("lit", "".join(literal)))
        return [part for part in parts if part[0] == "expr" or part[1]]
    operands = _js_split_top_level(text, blanked, "+")
    if operands is None or len(operands) < 2:
        return None
    parts = []
    for operand in operands:
        quoted = re.fullmatch(r"(['\"])(?P<text>(?:(?!\1).)*)\1", operand)
        parts.append(("lit", quoted.group("text")) if quoted else ("expr", operand))
    return parts


def _js_split_top_level(raw: str, blanked: str, separator: str) -> list[str] | None:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, ch in enumerate(blanked):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return None
        elif ch == separator and depth == 0:
            parts.append(raw[start:index].strip())
            start = index + 1
    if depth != 0:
        return None
    parts.append(raw[start:].strip())
    return [part for part in parts if part]


def js_composed_path(expression: str) -> tuple[str, str] | None:
    """`(base, user input)` for a path built by concatenation or interpolation, or None.

    The split is at the last path separator that a *literal* part carries, because that is the
    last point the code itself fixed: everything up to it is the directory the repair contains
    against, and everything after it is what a traversal payload arrives in.
    `'./data/static/codefixes/' + key + '.info.yml'` splits after the literal directory;
    `` `${base}/${name}` `` splits after the separator between the two.

    A composition with no literal separator has no base to contain against, and one with no
    expression after the separator has nothing untrusted in it. Both are None, and the caller
    names which.
    """
    parts = _js_concatenation_parts(expression)
    if not parts:
        return None
    split_at = None
    for index, (kind, text) in enumerate(parts):
        if kind == "lit" and "/" in text:
            split_at = index
    if split_at is None:
        return None
    literal = parts[split_at][1]
    head, _, tail = literal.rpartition("/")
    base_parts = [*parts[:split_at], ("lit", head + "/")]
    input_parts = ([("lit", tail)] if tail else []) + list(parts[split_at + 1 :])
    if not any(kind == "expr" for kind, _ in input_parts):
        return None
    return _js_render_parts(base_parts), _js_render_parts(input_parts)


def _js_render_parts(parts: list[tuple[str, str]]) -> str:
    rendered = [f"'{text}'" if kind == "lit" else f"String({text})" for kind, text in parts if kind == "expr" or text]
    return " + ".join(rendered) if rendered else "''"


_JS_PLAIN_REFERENCE_RE = re.compile(r"^[\w$]+(?:\.[\w$]+)*$")


def js_path_site_in_scope(
    lines: list[str], start_line: int, end_line: int, line: int, names: tuple[str, ...]
) -> JsPathJoin:
    """Where a path is built inside a scope, or a SiteError naming what the sink does instead.

    Three shapes are repair sites: a `path.join`/`path.resolve` call, a concatenation of a base
    directory and a value, and a template literal that interpolates one. The vulnerable corpus
    carries all three, and before this the second and third were reported as a missing
    `path.join`, which said the template could not find something the code never wrote.

    What is left refuses by what the sink actually does, because those refusals are correct and
    a reader needs to tell them apart from a gap:

    * `path_argument_is_constant` for `fs.readFile('/proc/meminfo')`. There is no untrusted
      component, so there is nothing to contain and no test that could fail before a repair.
    * `path_argument_not_composed_in_scope` for `fs.createReadStream(target)`, where the path
      arrives as one value built somewhere this scope does not show.
    * `path_join_not_found_in_scope` when no filesystem sink is on any line of the scope, which
      is what the quarantined `path.traversal.user_path` rule reports on Angular's
      `dialog.open(...)` and on `new File(...)`.
    """
    found = js_path_join_in_scope(lines, start_line, end_line, line, names)
    if found is not None:
        return found
    constant = False
    uncomposed = False
    for number in scope_lines_near(start_line, end_line, line):
        sink = js_path_sink_argument(lines[number - 1])
        if sink is None:
            continue
        _call, argument = sink
        composed = js_composed_path(argument)
        if composed is not None:
            return JsPathJoin(number, argument, composed[0], composed[1], composed=True)
        if re.fullmatch(r"(['\"])(?:(?!\1).)*\1", argument.strip()):
            constant = True
        elif _JS_PLAIN_REFERENCE_RE.match(argument.strip()):
            uncomposed = True
    if constant:
        raise SiteError("path_argument_is_constant")
    if uncomposed:
        raise SiteError("path_argument_not_composed_in_scope")
    raise SiteError("path_join_not_found_in_scope")


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


# --- GitHub Actions workflows ---------------------------------------------------------------
#
# The site model here is a *step*, not a function. A workflow is a document GitHub interprets,
# so there is no scope to resolve and nothing to walk: what a patch needs to know is where the
# step the finding landed in begins and ends, what its key indentation is, and whether it
# already has an `env:` block. All three are decided by YAML's indentation, which is why this is
# a line scan rather than a parse.
#
# It is deliberately not a YAML parse. A parse would give back a document with the comments and
# the exact whitespace gone, and both matter: a patch that reflows a workflow is a patch a
# maintainer will not read, and the pinning fix puts the version *into* a comment.

# A step begins with a `-` list item under `steps:`.
_STEP_ITEM_RE = re.compile(r"^(?P<indent>[ \t]*)-(?P<gap>[ \t]+)(?P<rest>\S.*)$")
# A mapping key at some indentation: `run:`, `env:`, `with:`, `uses:`.
_YAML_KEY_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<key>[A-Za-z_][\w.-]*)[ \t]*:(?P<rest>.*)$")


@dataclass(frozen=True)
class WorkflowStep:
    """One step of one job, as a span of lines plus the two things a patch has to line up with.

    `key_indent` is the column the step's own keys sit at, which is the `-` column plus the gap
    after it for the first key and the same for every sibling. `env_line` is the 1-based line of
    an existing `env:` key in the step, or None, which is what decides whether the environment
    binding patch inserts a block or extends one.
    """

    start_line: int
    end_line: int
    key_indent: int
    env_line: int | None
    env_indent: int | None

    @property
    def names(self) -> set[str]:
        return set()


def _leading_width(text: str) -> int:
    return len(text) - len(text.lstrip(" \t"))


def workflow_step_for_line(source: str, line: int) -> WorkflowStep:
    """The step that contains `line`, by indentation.

    A step runs from its `-` item to the line before the next item at the same indentation, or
    to the first line indented less than its keys, whichever comes first. A blank line belongs
    to whatever surrounds it.
    """
    lines = source.split("\n")
    if line < 1 or line > len(lines):
        raise SiteError("workflow_line_out_of_range")

    start_index: int | None = None
    key_indent = 0
    for index in range(line - 1, -1, -1):
        match = _STEP_ITEM_RE.match(lines[index])
        if match:
            start_index = index
            key_indent = len(match.group("indent")) + 1 + len(match.group("gap"))
            break
    if start_index is None:
        raise SiteError("workflow_step_not_found")

    item_indent = _leading_width(lines[start_index])
    end_index = len(lines) - 1
    for index in range(start_index + 1, len(lines)):
        text = lines[index]
        if not text.strip():
            continue
        indent = _leading_width(text)
        if indent < key_indent or _STEP_ITEM_RE.match(text) and indent <= item_indent:
            end_index = index - 1
            break
    else:
        end_index = len(lines) - 1

    if not start_index <= line - 1 <= end_index:
        raise SiteError("workflow_step_not_found")

    env_line: int | None = None
    env_indent: int | None = None
    for index in range(start_index, end_index + 1):
        # `- env:` on the item line itself counts, and so does a sibling `env:` at key_indent.
        # Anything deeper is a key of some other block, such as a `with:` entry called `env`.
        text = lines[index].replace("-", " ", 1) if index == start_index else lines[index]
        candidate = _YAML_KEY_RE.match(text)
        if candidate and candidate.group("key") == "env" and len(candidate.group("indent")) == key_indent:
            env_line = index + 1
            env_indent = key_indent
            break

    return WorkflowStep(start_index + 1, end_index + 1, key_indent, env_line, env_indent)


# --- password hashing -----------------------------------------------------------------------
#
# The site is the module's own password-hashing function and every comparison of its result.
# Both have to be found, because the repair changes what the function returns: a salted
# key-derivation result is different on every call, so `hash(attempt) === stored` can never be
# true again and each such comparison has to become a call to a verifier. A module that compares
# the digest somewhere this scan cannot rewrite, or looks it up instead of comparing it, is
# refused by name rather than given a repair that would lock every user out.

JS_PASSWORD_VERIFIER = "verifyPasswordHash"
PY_PASSWORD_VERIFIER = "verify_password_hash"
FAST_DIGESTS = frozenset({"md5", "sha1", "sha-1", "sha224", "sha256", "sha384", "sha512"})
# What reads a value back by equality inside a store: a salted hash can never match there.
_LOOKUP_RE = re.compile(r"\.(?:query|execute|find\w*|where|filter\w*|select|get|exists|count)\s*\(|\bWHERE\b", re.I)
_JS_DIGEST_RE = re.compile(
    r"(?P<module>[A-Za-z_$][\w$]*)\.createHash\(\s*(?P<q1>['\"])(?P<algorithm>[\w-]+)(?P=q1)\s*\)"
    r"\s*\.update\(\s*(?P<argument>[A-Za-z_$][\w$]*)\s*(?:,\s*(?P<q2>['\"])(?:utf8|utf-8)(?P=q2)\s*)?\)"
    r"\s*\.digest\((?P<digest>[^()]*)\)"
)
_JS_ARROW_RE = re.compile(
    r"^(?P<indent>\s*)(?P<head>(?:export\s+)?(?:const|let|var)\s+(?P<name>[\w$]+)\s*=\s*)"
    r"\((?P<params>[^()]*)\)\s*(?::\s*[\w$<>\[\]| ]+?)?\s*=>\s*(?P<expression>.+?);?\s*$"
)
_JS_COMPARISON_OPERATORS = ("===", "!==", "==", "!=")
_JS_REFERENCE = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"
# What may stand on either side of a rewritten comparison without changing what it binds to: an
# operator of lower precedence than equality, a bracket, or a statement boundary.
_JS_BEFORE_OK = re.compile(r"(?:^|[(,;{?:]|&&|\|\||(?<![=!<>])=|=>|\breturn)\s*$")
_JS_AFTER_OK = re.compile(r"^\s*(?:$|[),;}?:]|&&|\|\|)")


@dataclass(frozen=True)
class PasswordComparison:
    line: int
    start: int  # column of the comparison's first character on `line`
    end: int  # column one past its last character
    password: str  # the expression hashed for the attempt
    stored: str  # the expression it is compared with
    negated: bool


@dataclass(frozen=True)
class PasswordHashSite:
    language: str
    function: str
    parameter: str
    start_line: int
    end_line: int
    indent: str
    body_indent: str
    digest_line: int
    algorithm: str
    module: str  # the hashlib/crypto binding the repair calls through
    argument: str  # the expression the digest was fed
    arrow: bool
    head: str  # JS arrow form: `const name = `, with any `export`
    comparisons: tuple[PasswordComparison, ...]
    verifier: str
    typescript: bool = False
    imports_needed: tuple[str, ...] = ()
    keep_lines: tuple[str, ...] = ()  # Python: the def line and docstring kept above the new body


def _js_single_parameter(declared: str) -> str:
    parts = [part.strip() for part in declared.split(",") if part.strip()]
    if len(parts) != 1:
        raise SiteError("password_hash_function_not_single_parameter")
    name = re.match(r"^([A-Za-z_$][\w$]*)\s*(?::\s*[\w$<>\[\]| ]+)?$", parts[0])
    if not name:
        raise SiteError("password_hash_function_not_single_parameter")
    return name.group(1)


def _js_module_stem(path: str) -> str:
    return PurePosixPath(path).stem


def _js_comparisons(lines: list[str], stripped: list[str], name: str, skip: range) -> tuple[list[PasswordComparison], list[int]]:
    """The rewritable comparisons of `name(...)`, and the lines of every other call of it."""
    call = rf"(?<![\w$.]){re.escape(name)}\(\s*(?P<a>{_JS_REFERENCE})\s*\)"
    operator = r"\s*(?P<op>===|!==|==|!=)\s*"
    forward = re.compile(call + operator + rf"(?P<b>{_JS_REFERENCE})(?![\w$.(\[])")
    backward = re.compile(rf"(?<![\w$.])(?P<b>{_JS_REFERENCE})" + operator + call.replace("(?<![\\w$.])", ""))
    any_call = re.compile(rf"(?<![\w$.]){re.escape(name)}\s*\(")
    found: list[PasswordComparison] = []
    others: list[int] = []
    for index, text in enumerate(stripped):
        number = index + 1
        if number in skip:
            continue
        covered: list[tuple[int, int]] = []
        for pattern in (forward, backward):
            for match in pattern.finditer(text):
                if any(start <= match.start() < end for start, end in covered):
                    continue
                if not _JS_BEFORE_OK.search(text[: match.start()]) or not _JS_AFTER_OK.match(text[match.end() :]):
                    raise SiteError("password_comparison_not_rewritable")
                original = lines[index][match.start() : match.end()]
                inner = pattern.match(original)
                if inner is None:
                    raise SiteError("password_comparison_not_rewritable")
                covered.append((match.start(), match.end()))
                found.append(PasswordComparison(number, match.start(), match.end(), inner.group("a"), inner.group("b"), inner.group("op").startswith("!")))
        for match in any_call.finditer(text):
            if not any(start <= match.start() < end for start, end in covered):
                others.append(number)
    return found, others


def js_password_hash_site(source: str, path: str, line_start: int | None, line_end: int | None, others: dict[str, str] | None = None) -> PasswordHashSite:
    """The hashing function a password_hashing finding sits in, and the comparisons of its result."""
    lines = source.splitlines()
    stripped = js_strip_strings(source).splitlines()
    first = max(1, int(line_start or 1))
    last = max(first, int(line_end or first))
    digest = None
    for number in range(first, min(last, len(lines)) + 1):
        digest = _JS_DIGEST_RE.search(lines[number - 1])
        if digest:
            break
    if digest is None:
        raise SiteError("password_digest_not_recognized")
    algorithm = digest.group("algorithm").lower()
    crypto_names = _js_module_bound_to(source, "crypto") | _js_module_bound_to(source, "node:crypto")
    if algorithm not in FAST_DIGESTS or digest.group("module") not in crypto_names:
        # A `createHash` on anything but the crypto module is someone's own hasher, and the
        # repair would call `scryptSync` on it.
        raise SiteError("password_digest_not_recognized")
    if not re.fullmatch(r"\s*(['\"])(?:hex|base64)\1\s*", digest.group("digest")):
        raise SiteError("password_digest_encoding_not_text")
    arrow = _JS_ARROW_RE.match(lines[number - 1])
    if arrow and arrow.group("expression").strip() == digest.group(0):
        name, declared, start, end = arrow.group("name"), arrow.group("params"), number, number
        indent, body_indent, head = arrow.group("indent"), arrow.group("indent") + "  ", arrow.group("head")
    else:
        arrow = None
        head = ""
        for index in range(number - 2, -1, -1):
            declaration = _js_declaration(lines[index])
            if not declaration or "{" not in stripped[index][declaration[3] :]:
                continue
            close = _js_brace_end(stripped, index, declaration[3])
            if close is None or close < number - 1:
                continue
            name, declared, kind, _offset = declaration
            if kind != "function":
                raise SiteError("password_hash_in_method")
            start, end = index + 1, close + 1
            break
        else:
            raise SiteError("password_hash_not_returned_by_function")
        body = [text.strip() for text in lines[start : end - 1] if text.strip() and not text.strip().startswith("//")]
        chain = re.escape(digest.group(0))
        returned = len(body) == 1 and re.fullmatch(rf"return\s+{chain}\s*;?", body[0])
        bound = len(body) == 2 and re.fullmatch(rf"(?:const|let|var)\s+(?P<v>[\w$]+)\s*=\s*{chain}\s*;?", body[0])
        if bound and not re.fullmatch(rf"return\s+{re.escape(bound.group('v'))}\s*;?", body[1]):
            bound = None
        if not returned and not bound:
            raise SiteError("password_hash_not_returned_by_function")
        if lines[end - 1].strip() not in ("}", "};"):
            raise SiteError("password_hash_not_returned_by_function")
        indent = re.match(r"\s*", lines[start - 1]).group(0)
        body_indent = re.match(r"\s*", lines[number - 1]).group(0)
    parameter = _js_single_parameter(declared)
    if digest.group("argument") != parameter:
        raise SiteError("password_hash_input_not_the_parameter")
    if parameter in {"stored", "salt", "scheme", "expected", "actual", "wanted"}:
        raise SiteError("password_parameter_name_collides")
    comparisons, calls = _js_comparisons(lines, stripped, name, range(start, end + 1))
    for number in calls:
        if _LOOKUP_RE.search(lines[number - 1]):
            raise SiteError("password_hash_used_for_lookup")
    stem = re.escape(_js_module_stem(path))
    for other_path, other in (others or {}).items():
        if other_path == path:
            continue
        imports_it = re.search(rf"""(?:require\(|from\s+|import\s*\()\s*['"][^'"]*\b{stem}(?:\.[cm]?[jt]s)?['"]""", other)
        if imports_it and re.search(rf"(?<![\w$]){re.escape(name)}\s*\(", other):
            raise SiteError("password_hash_called_from_other_module")
    if not comparisons:
        raise SiteError("password_verifier_not_found")
    if js_identifier_is_bound(source, JS_PASSWORD_VERIFIER):
        raise SiteError("password_verifier_name_taken")
    return PasswordHashSite(
        "javascript", name, parameter, start, end, indent, body_indent, number, algorithm, digest.group("module"),
        parameter, arrow is not None, head, tuple(comparisons), JS_PASSWORD_VERIFIER,
        typescript=path.endswith((".ts", ".tsx", ".mts", ".cts")),
    )


_PY_HASHLIB_CONSTRUCTORS = frozenset({"md5", "sha1", "sha224", "sha256", "sha384", "sha512"})


def _py_hashlib_bindings(tree: ast.Module) -> tuple[str | None, dict[str, str]]:
    """The name `hashlib` is bound to, and the digest constructors imported from it by name."""
    module = None
    named: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "hashlib":
                    module = alias.asname or "hashlib"
        elif isinstance(node, ast.ImportFrom) and node.module == "hashlib":
            for alias in node.names:
                if alias.name in _PY_HASHLIB_CONSTRUCTORS:
                    named[alias.asname or alias.name] = alias.name
    return module, named


def _py_digest_call(node: ast.AST, module: str | None, named: dict[str, str]) -> tuple[str, ast.AST] | None:
    """`(algorithm, argument)` for `hashlib.md5(x)`, `md5(x)` or `hashlib.new("md5", x)`."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == module:
        if func.attr in _PY_HASHLIB_CONSTRUCTORS and len(node.args) == 1:
            return func.attr, node.args[0]
        if func.attr == "new" and len(node.args) == 2 and isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() in FAST_DIGESTS:
            return str(node.args[0].value).lower(), node.args[1]
    if isinstance(func, ast.Name) and func.id in named and len(node.args) == 1:
        return named[func.id], node.args[0]
    return None


def python_password_hash_site(source: str, path: str, line_start: int | None, others: dict[str, str] | None = None) -> PasswordHashSite:
    """The Python counterpart of `js_password_hash_site`, read from the `ast`."""
    tree = python_tree(source)
    lines = source.splitlines()
    line = max(1, int(line_start or 1))
    module, named = _py_hashlib_bindings(tree)
    function = next(
        (node for node in tree.body if isinstance(node, ast.FunctionDef) and node.lineno <= line <= (node.end_lineno or node.lineno)),
        None,
    )
    if function is None:
        inside_class = any(
            isinstance(node, ast.ClassDef) and node.lineno <= line <= (node.end_lineno or node.lineno) for node in tree.body
        )
        raise SiteError("password_hash_in_method" if inside_class else "password_hash_not_returned_by_function")
    body = list(function.body)
    keep_until = function.lineno
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        keep_until = body[0].end_lineno or body[0].lineno
        body = body[1:]
    chain = None
    if len(body) == 1 and isinstance(body[0], ast.Return):
        chain = body[0].value
    elif (
        len(body) == 2 and isinstance(body[0], ast.Assign) and len(body[0].targets) == 1 and isinstance(body[0].targets[0], ast.Name)
        and isinstance(body[1], ast.Return) and isinstance(body[1].value, ast.Name) and body[1].value.id == body[0].targets[0].id
    ):
        chain = body[0].value
    if not (isinstance(chain, ast.Call) and isinstance(chain.func, ast.Attribute) and not chain.args):
        raise SiteError("password_hash_not_returned_by_function")
    if chain.func.attr == "digest":
        raise SiteError("password_digest_encoding_not_text")
    found = _py_digest_call(chain.func.value, module, named) if chain.func.attr == "hexdigest" else None
    if found is None:
        raise SiteError("password_digest_not_recognized")
    algorithm, argument = found
    arguments = function.args
    if arguments.posonlyargs or arguments.kwonlyargs or arguments.vararg or arguments.kwarg or len(arguments.args) != 1 or arguments.defaults:
        raise SiteError("password_hash_function_not_single_parameter")
    parameter = arguments.args[0].arg
    names = {node.id for node in ast.walk(argument) if isinstance(node, ast.Name)}
    if names != {parameter} or ast.get_source_segment(source, argument) is None:
        raise SiteError("password_hash_input_not_the_parameter")
    if parameter in {"stored", "salt", "scheme", "rest", "expected", "digest"}:
        raise SiteError("password_parameter_name_collides")
    name = function.name
    comparisons: list[PasswordComparison] = []
    counted: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        sides = [node.left, node.comparators[0]]
        for index, side in enumerate(sides):
            if isinstance(side, ast.Call) and isinstance(side.func, ast.Name) and side.func.id == name:
                if not isinstance(node.ops[0], (ast.Eq, ast.NotEq)) or len(side.args) != 1 or side.keywords or node.lineno != node.end_lineno:
                    raise SiteError("password_comparison_not_rewritable")
                other = sides[1 - index]
                text = lines[node.lineno - 1]
                if not text.isascii():
                    raise SiteError("password_comparison_not_rewritable")
                comparisons.append(PasswordComparison(
                    node.lineno, node.col_offset, node.end_col_offset or node.col_offset,
                    ast.get_source_segment(source, side.args[0]) or "", ast.get_source_segment(source, other) or "",
                    isinstance(node.ops[0], ast.NotEq),
                ))
                counted.add(id(side))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name and id(node) not in counted:
            if _LOOKUP_RE.search(lines[node.lineno - 1]):
                raise SiteError("password_hash_used_for_lookup")
    stem = re.escape(PurePosixPath(path).stem)
    for other_path, other in (others or {}).items():
        if other_path == path:
            continue
        if re.search(rf"^\s*from\s+[\w.]*\b{stem}\s+import\s+[^\n]*\b{re.escape(name)}\b", other, re.M) or re.search(rf"\b{stem}\.{re.escape(name)}\s*\(", other):
            raise SiteError("password_hash_called_from_other_module")
    if not comparisons:
        raise SiteError("password_verifier_not_found")
    bound = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    bound |= {target.id for node in ast.walk(tree) if isinstance(node, ast.Assign) for target in node.targets if isinstance(target, ast.Name)}
    if PY_PASSWORD_VERIFIER in bound:
        raise SiteError("password_verifier_name_taken")
    imports = {alias.asname or alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
    needed = tuple(sorted({"hmac", "os"} - imports) + ([] if module else ["hashlib"]))
    def_line = lines[function.lineno - 1]
    first_body = lines[body[0].lineno - 1]
    return PasswordHashSite(
        "python", name, parameter, function.lineno, function.end_lineno or function.lineno,
        def_line[: len(def_line) - len(def_line.lstrip())], first_body[: len(first_body) - len(first_body.lstrip())],
        chain.lineno, algorithm, module or "hashlib", ast.get_source_segment(source, argument) or parameter, False, "",
        tuple(comparisons), PY_PASSWORD_VERIFIER, imports_needed=needed,
        keep_lines=tuple(lines[function.lineno - 1 : keep_until]),
    )


def other_sources(snapshot: Snapshot, path: str) -> dict[str, str]:
    """Every other snapshot file in the same toolchain, for the cross-module refusal."""
    suffixes = (".py",) if path.endswith(".py") else (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
    return {other: snapshot.full_content(other) for other in snapshot.paths if other != path and other.endswith(suffixes)}


def password_hash_site(snapshot: Snapshot, finding: FindingSnapshot, language: str) -> PasswordHashSite:
    path = finding.affected_path
    source = snapshot.full_content(path)
    if language == "python":
        return python_password_hash_site(source, path, finding.line_start, other_sources(snapshot, path))
    return js_password_hash_site(source, path, finding.line_start, finding.line_end, other_sources(snapshot, path))


# --- cookie flags ---------------------------------------------------------------------------
#
# The site is the options a cookie is set with, rewritten in place: HttpOnly, Secure and
# SameSite are set and every other key is kept as written. The shapes are the ones the rules
# report: the `cookie` object of an express-session call, the options of a cookie-session call,
# the third argument of `res.cookie`, a Flask `set_cookie` call, and a Django or Flask setting
# assigned False. Options the code builds somewhere else, a spread that could override what the
# repair sets, and a flag computed at runtime are refused by name, because the rewrite could
# not say what the cookie ends up carrying. SameSite=None is refused too: it is how a cookie is
# made to travel cross-site on purpose.

COOKIE_SETTINGS = frozenset({"SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY", "CSRF_COOKIE_SECURE"})
_JS_FLAG_FALSE_RE = re.compile(r"(?<![\w$])(?:secure|httpOnly)\s*:\s*false(?![\w$])")
_JS_SAMESITE_NONE_RE = re.compile(r"(?<![\w$])sameSite\s*:\s*(['\"])none\1", re.I)
_JS_COOKIE_FLAGS = (("httpOnly", "true"), ("secure", "true"), ("sameSite", None))


@dataclass(frozen=True)
class CookieSite:
    language: str
    kind: str  # express-session | cookie-session | res.cookie | set_cookie | setting | flask_config
    name: str | None  # the cookie's literal name, or the setting the finding names
    start_line: int
    original: tuple[str, ...]
    replacement: tuple[str, ...]
    app: str | None = None  # the Flask application a config setting is read back from


def _js_module_bound_to(source: str, module: str) -> set[str]:
    names = set(re.findall(rf"""(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['"]{re.escape(module)}['"]\s*\)""", source))
    names |= set(re.findall(rf"""import\s+([\w$]+)\s+from\s+['"]{re.escape(module)}['"]""", source))
    return names


def _matching(stripped: str, start: int, opening: str, closing: str, step: int) -> int | None:
    """The offset of the bracket that balances the one at `start`, scanning by `step`."""
    depth = 0
    index = start
    while 0 <= index < len(stripped):
        ch = stripped[index]
        if ch == (opening if step > 0 else closing):
            depth += 1
        elif ch == (closing if step > 0 else opening):
            depth -= 1
            if depth == 0:
                return index
        index += step
    return None


def _enclosing(stripped: str, offset: int, opening: str, closing: str) -> int | None:
    """The offset of the unbalanced `opening` bracket that encloses `offset`."""
    depth = 0
    for index in range(offset - 1, -1, -1):
        ch = stripped[index]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                return index if ch == opening else None
            depth -= 1
    return None


def _js_object_entries(stripped: str, start: int, end: int) -> list[tuple[str, int, int, int]]:
    """`(key, entry start, value start, entry end)` for each top-level entry of `{...}`."""
    entries: list[tuple[str, int, int, int]] = []
    depth = 0
    piece = start + 1
    for index in range(start + 1, end + 1):
        ch = stripped[index]
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and index != end:
            depth -= 1
        if (ch == "," and depth == 0) or index == end:
            text = stripped[piece:index]
            if text.strip():
                lead = len(text) - len(text.lstrip())
                found = re.match(r"([A-Za-z_$][\w$]*)\s*:\s*", text[lead:])
                if text.strip().startswith("..."):
                    raise SiteError("cookie_options_spread")
                if not found:
                    raise SiteError("cookie_options_not_recognized")
                body_end = piece + len(text.rstrip())
                entries.append((found.group(1), piece + lead, piece + lead + found.end(), body_end))
            piece = index + 1
    return entries


def _js_cookie_object(source: str, stripped: str, open_brace: int, close_brace: int) -> str:
    """The object literal with httpOnly, secure and sameSite set and every other key kept."""
    entries = _js_object_entries(stripped, open_brace, close_brace)
    quote = "\"" if re.search(r"\"[^\"\n]*\"", source[open_brace:close_brace]) and "'" not in source[open_brace:close_brace] else "'"
    edits: list[tuple[int, int, str]] = []
    present = {key for key, *_ in entries}
    for key, _start, value_start, end in entries:
        value = source[value_start:end].strip()
        if key in ("httpOnly", "secure"):
            if value not in ("true", "false"):
                raise SiteError("cookie_flag_value_not_literal")
            if value == "false":
                edits.append((value_start, end, "true"))
        elif key == "sameSite":
            lowered = value.strip("'\"").lower()
            if lowered == "none":
                raise SiteError("cookie_samesite_none_is_deliberate")
            if value == "false":
                edits.append((value_start, end, f"{quote}lax{quote}"))
            elif value != "true" and not re.fullmatch(r"(['\"])(?:lax|strict)\1", value, re.I):
                raise SiteError("cookie_flag_value_not_literal")
    missing = [(key, value or f"{quote}lax{quote}") for key, value in _JS_COOKIE_FLAGS if key not in present]
    text = source[open_brace : close_brace + 1]
    base = open_brace
    for start, end, value in sorted(edits, reverse=True):
        text = text[: start - base] + value + text[end - base :]
        delta = len(value) - (end - start)
        close_brace += delta
    if not missing:
        return text
    if not entries:
        return "{ " + ", ".join(f"{key}: {value}" for key, value in missing) + " }"
    inner = text[1:-1]
    multiline = "\n" in inner
    last_end = len(inner.rstrip())
    trailing_comma = inner[:last_end].endswith(",")
    if multiline:
        last_line = inner[: last_end].rsplit("\n", 1)[-1]
        indent = last_line[: len(last_line) - len(last_line.lstrip())]
        added = "".join(f"\n{indent}{key}: {value}," for key, value in missing)
        if trailing_comma:
            inner = inner[:last_end] + added + inner[last_end:]
        else:
            inner = inner[:last_end] + "," + added[:-1] + inner[last_end:]
    else:
        added = ", ".join(f"{key}: {value}" for key, value in missing)
        body = inner[:last_end].rstrip(",")
        inner = body + ", " + added + inner[last_end:]
    return "{" + inner + "}"


def js_cookie_site(source: str, line_start: int | None, line_end: int | None) -> CookieSite:
    """The cookie options a cookie_flags finding names, and their repaired text."""
    lines = source.splitlines()
    stripped = js_strip_strings(source)
    offsets = [0]
    for text in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(text))
    first = max(1, int(line_start or 1))
    last = min(len(lines), max(first, int(line_end or first)))
    region = stripped[offsets[first - 1] : offsets[last]]
    original_region = source[offsets[first - 1] : offsets[last]]
    flag = _JS_FLAG_FALSE_RE.search(region)
    if flag is None:
        if _JS_SAMESITE_NONE_RE.search(original_region):
            raise SiteError("cookie_samesite_none_is_deliberate")
        raise SiteError("cookie_flag_not_found")
    key_offset = offsets[first - 1] + flag.start()
    open_brace = _enclosing(stripped, key_offset, "{", "}")
    if open_brace is None:
        raise SiteError("cookie_options_not_recognized")
    close_brace = _matching(stripped, open_brace, "{", "}", 1)
    if close_brace is None:
        raise SiteError("cookie_options_not_recognized")
    before = stripped[:open_brace].rstrip()
    name: str | None = None
    if re.search(r"(?<![\w$])cookie\s*:$", before):
        outer = _enclosing(stripped, open_brace, "{", "}")
        paren = _enclosing(stripped, outer, "(", ")") if outer is not None else None
        callee = re.search(r"([\w$]+)\s*$", stripped[:paren]) if paren is not None else None
        if not callee or callee.group(1) not in _js_module_bound_to(source, "express-session"):
            raise SiteError("cookie_options_not_recognized")
        kind = "express-session"
    elif before.endswith("("):
        callee = re.search(r"([\w$]+)$", before[:-1].rstrip())
        if not callee or callee.group(1) not in _js_module_bound_to(source, "cookie-session"):
            raise SiteError("cookie_options_not_recognized")
        kind = "cookie-session"
    elif before.endswith(","):
        paren = _enclosing(stripped, open_brace, "(", ")")
        if paren is None or not re.search(r"[\w$]+\.cookie\s*$", stripped[:paren]):
            raise SiteError("cookie_options_not_recognized")
        arguments = stripped[paren + 1 : open_brace]
        depth = 0
        commas = 0
        for ch in arguments:
            depth += ch in "([{"
            depth -= ch in ")]}"
            commas += ch == "," and depth == 0
        if commas != 2:
            raise SiteError("cookie_options_not_recognized")
        literal = re.match(r"\s*(['\"])([^'\"\n]+)\1\s*,", source[paren + 1 : open_brace])
        name = literal.group(2) if literal else None
        kind = "res.cookie"
    else:
        raise SiteError("cookie_options_not_recognized")
    repaired = _js_cookie_object(source, stripped, open_brace, close_brace)
    start_line = source.count("\n", 0, open_brace) + 1
    end_line = source.count("\n", 0, close_brace) + 1
    head = source[offsets[start_line - 1] : open_brace]
    tail = source[close_brace + 1 : offsets[end_line]].rstrip("\n")
    return CookieSite(
        "javascript", kind, name, start_line, tuple(lines[start_line - 1 : end_line]),
        tuple((head + repaired + tail).split("\n")),
    )


def python_cookie_site(source: str, line_start: int | None, line_end: int | None) -> CookieSite:
    """The Python counterpart: a set_cookie call, a Django setting, or a Flask config key."""
    tree = python_tree(source)
    lines = source.splitlines()
    first = max(1, int(line_start or 1))
    last = max(first, int(line_end or first))
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not first <= node.lineno <= last or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in COOKIE_SETTINGS:
            setting, app = target.id, None
        elif (
            isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute) and target.value.attr == "config"
            and isinstance(target.value.value, ast.Name) and isinstance(target.slice, ast.Constant) and target.slice.value in COOKIE_SETTINGS
        ):
            setting, app = str(target.slice.value), target.value.value.id
        else:
            continue
        if not (isinstance(node.value, ast.Constant) and node.value.value is False) or node.lineno != node.end_lineno:
            raise SiteError("cookie_flag_value_not_literal")
        text = lines[node.lineno - 1]
        rewritten = text[: node.value.col_offset] + "True" + text[node.value.end_col_offset :]
        return CookieSite("python", "setting" if app is None else "flask_config", setting, node.lineno, (text,), (rewritten,), app)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie"):
            continue
        if not first <= node.lineno <= last:
            continue
        if len(node.args) > 2 or any(isinstance(arg, ast.Starred) for arg in node.args):
            raise SiteError("cookie_flags_passed_positionally")
        if any(keyword.arg is None for keyword in node.keywords):
            raise SiteError("cookie_options_spread")
        segment = lines[node.lineno - 1 : node.end_lineno]
        if not all(text.isascii() for text in segment):
            raise SiteError("cookie_options_not_recognized")
        offsets = [0]
        for text in segment:
            offsets.append(offsets[-1] + len(text) + 1)
        call_text = "\n".join(segment)
        position = lambda line, col: offsets[line - node.lineno] + col  # noqa: E731
        edits: list[tuple[int, int, str]] = []
        present = set()
        for keyword in node.keywords:
            present.add(keyword.arg)
            value = keyword.value
            if keyword.arg in ("secure", "httponly"):
                if not (isinstance(value, ast.Constant) and isinstance(value.value, bool)):
                    raise SiteError("cookie_flag_value_not_literal")
                if value.value is False:
                    edits.append((position(value.lineno, value.col_offset), position(value.end_lineno, value.end_col_offset), "True"))
            elif keyword.arg == "samesite":
                if not (isinstance(value, ast.Constant) and (value.value is None or isinstance(value.value, str))):
                    raise SiteError("cookie_flag_value_not_literal")
                if isinstance(value.value, str) and value.value.lower() == "none":
                    raise SiteError("cookie_samesite_none_is_deliberate")
                if value.value is None:
                    edits.append((position(value.lineno, value.col_offset), position(value.end_lineno, value.end_col_offset), '"Lax"'))
        missing = [f"{key}={value}" for key, value in (("secure", "True"), ("httponly", "True"), ("samesite", '"Lax"')) if key not in present]
        arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
        last_argument = max(arguments, key=lambda item: (item.end_lineno, item.end_col_offset))
        insert_at = position(last_argument.end_lineno, last_argument.end_col_offset)
        if missing:
            after = call_text[insert_at:]
            comma = re.match(r"\s*,", after)
            if node.end_lineno != node.lineno:
                last_text = segment[last_argument.end_lineno - node.lineno]
                indent = last_text[: len(last_text) - len(last_text.lstrip())]
                added = "".join(f"\n{indent}{item}," for item in missing)
                if comma:
                    insert_at += comma.end()
                    edits.append((insert_at, insert_at, added))
                else:
                    edits.append((insert_at, insert_at, "," + added[:-1]))
            else:
                edits.append((insert_at, insert_at, ", " + ", ".join(missing)))
        for start, end, value in sorted(edits, reverse=True):
            call_text = call_text[:start] + value + call_text[end:]
        name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) else None
        return CookieSite("python", "set_cookie", name, node.lineno, tuple(segment), tuple(call_text.split("\n")))
    raise SiteError("cookie_flag_not_found")


def cookie_site(snapshot: Snapshot, finding: FindingSnapshot, language: str) -> CookieSite:
    source = snapshot.full_content(finding.affected_path)
    if language == "python":
        return python_cookie_site(source, finding.line_start, finding.line_end)
    return js_cookie_site(source, finding.line_start, finding.line_end)
