"""Where a finding lives: the enclosing Express route handler or Python function.

The proof generator and the template patcher both need the same facts about a finding's
surroundings: which route or function encloses it, how untrusted input enters it, and which
names the handler binds. This module derives them lexically (JavaScript) or from the `ast`
(Python) over the exact snapshot. It never guesses: when the enclosing site cannot be derived,
it says why, and the caller falls back to the model-written test.
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


def enclosing_site(snapshot: Snapshot, finding: FindingSnapshot, language: str) -> JsRoute | PyFunction:
    source = snapshot.full_content(finding.affected_path)
    line = _finding_line(finding)
    if language == "python":
        return python_function_for_line(source, line)
    return js_route_for_line(source, line)
