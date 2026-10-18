"""Template-first patches: a deterministic hunk per family, tried before any model call.

Most supported findings are one of a few textual shapes: a query built from a template literal
or concatenation, an `exec` of a command string, a `path.join` of a base directory and a request
value, a secret literal, an `eval` of a parameter. Each generator here recognizes exactly that
shape at the finding, over the exact snapshot, and emits the hunks that fix it. The candidate is
verified with the service-generated proof through the normal verifier, so a template never
ships on its own say-so; when the shape is not recognized or the proof fails, the model is asked
for the hunk instead and the evidence records which path produced each candidate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .families import (
    CODE_INJECTION_EVAL,
    COMMAND_ARGUMENTS,
    COOKIE_FLAGS,
    HARDCODED_CREDENTIAL,
    JAVASCRIPT,
    PASSWORD_HASHING,
    PATH_CONTAINMENT,
    PYTHON,
    SQL_PARAMETERIZATION,
    WORKFLOW,
    WORKFLOW_HARDENING,
    is_workflow_path,
)
from .gates import PYTHON_SQL_DRIVERS, python_imports
from .models import FindingSnapshot
from .retrieval import Snapshot
from .sites import (
    JS_CALLBACK_PARAMETERS,
    JS_EVAL_ARGUMENT_RE,
    cookie_site,
    JsFunction,
    JsRoute,
    ModuleScope,
    PasswordHashSite,
    PyFunction,
    SiteError,
    js_bound_names,
    js_environment_name,
    js_eval_site,
    password_hash_site,
    js_literal_assignment,
    js_literal_assignment_in_span,
    js_names_in,
    js_identifier_is_bound,
    js_module_binding,
    js_path_site_in_scope,
    js_require_line,
    js_site_for_line,
    scope_lines_near,
    python_site_for_line,
    python_import_anchor,
    python_module_assignment,
    WorkflowStep,
    workflow_step_for_line,
)

TEMPLATE = "template"
MODEL = "model"


class TemplateError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TemplatePatch:
    finding_id: str
    family: str
    changes: list[dict[str, Any]]
    description: str


@dataclass(frozen=True)
class TemplateFallback:
    finding_id: str
    family: str
    reason: str


@dataclass
class _Segments:
    """A string expression as literal and interpolated parts."""

    parts: list[tuple[str, str]] = field(default_factory=list)

    def add(self, kind: str, text: str) -> None:
        if kind == "lit" and self.parts and self.parts[-1][0] == "lit":
            self.parts[-1] = ("lit", self.parts[-1][1] + text)
        elif text or kind == "expr":
            self.parts.append((kind, text))


# --- expression parsing ---------------------------------------------------------------------

def _read_quoted(expr: str, i: int, quote: str) -> tuple[str, int]:
    """The raw contents of the string starting at `i` (its opening quote) and the index after it."""
    j = i + 1
    buf: list[str] = []
    while j < len(expr) and expr[j] != quote:
        if expr[j] == "\\":
            buf.append(expr[j : j + 2])
            j += 2
            continue
        buf.append(expr[j])
        j += 1
    if j >= len(expr):
        raise TemplateError("unterminated_string")
    return "".join(buf), j + 1


def _read_braced(expr: str, i: int) -> tuple[str, int]:
    """The expression inside `{...}` starting at `i` (its opening brace) and the index after it."""
    depth = 1
    k = i + 1
    while k < len(expr) and depth:
        if expr[k] == "{":
            depth += 1
        elif expr[k] == "}":
            depth -= 1
        k += 1
    if depth:
        raise TemplateError("unterminated_interpolation")
    inner = expr[i + 1 : k - 1].strip()
    if not inner or any(q in inner for q in "'\"`"):
        raise TemplateError("interpolation_not_supported")
    return inner, k


def _read_template(expr: str, i: int, segments: _Segments, marker: str) -> int:
    quote = expr[i]
    j = i + 1
    buf: list[str] = []
    while j < len(expr) and expr[j] != quote:
        if expr[j] == "\\":
            buf.append(expr[j : j + 2])
            j += 2
            continue
        if expr.startswith(marker, j):
            segments.add("lit", "".join(buf))
            buf = []
            inner, j = _read_braced(expr, j + len(marker) - 1)
            segments.add("expr", inner)
            continue
        if marker == "{" and expr.startswith("}}", j):
            buf.append("}")
            j += 2
            continue
        if marker == "{" and expr.startswith("{{", j):
            buf.append("{")
            j += 2
            continue
        buf.append(expr[j])
        j += 1
    if j >= len(expr):
        raise TemplateError("unterminated_string")
    segments.add("lit", "".join(buf))
    return j + 1


def _read_operand_expression(expr: str, i: int, stop: str) -> tuple[str, int]:
    depth = 0
    j = i
    while j < len(expr):
        ch = expr[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in "'\"`":
            raise TemplateError("nested_string_in_expression")
        elif ch == stop and depth == 0:
            break
        j += 1
    text = expr[i:j].strip()
    if not text:
        raise TemplateError("empty_operand")
    return text, j


def js_segments(expr: str) -> list[tuple[str, str]]:
    """`'a' + x + \"b\"` or `` `a${x}b` `` as [('lit', 'a'), ('expr', 'x'), ('lit', 'b')]."""
    segments = _Segments()
    i = 0
    expect_operand = True
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if expect_operand:
            if ch in "'\"":
                text, i = _read_quoted(expr, i, ch)
                segments.add("lit", text)
            elif ch == "`":
                i = _read_template(expr, i, segments, "${")
            else:
                text, i = _read_operand_expression(expr, i, "+")
                segments.add("expr", text)
            expect_operand = False
        elif ch == "+":
            expect_operand = True
            i += 1
        else:
            raise TemplateError("expression_shape_not_supported")
    if expect_operand or not segments.parts:
        raise TemplateError("expression_shape_not_supported")
    return segments.parts


_PY_PREFIX_RE = re.compile(r"[fFrRbBuU]{0,2}")


def py_segments(expr: str) -> list[tuple[str, str]]:
    """`"a" + x`, `f"a{x}"`, `"a%s" % x`, `"a{}".format(x)` as literal and expression parts."""
    segments = _Segments()
    i = 0
    expect_operand = True
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if expect_operand:
            prefix = _PY_PREFIX_RE.match(expr, i).group(0)
            quote_at = i + len(prefix)
            if quote_at < len(expr) and expr[quote_at] in "'\"":
                if expr.startswith(expr[quote_at] * 3, quote_at):
                    raise TemplateError("triple_quoted_string_not_supported")
                if "b" in prefix.lower():
                    raise TemplateError("bytes_literal_not_supported")
                if "f" in prefix.lower():
                    i = _read_template(expr, quote_at, segments, "{")
                else:
                    text, i = _read_quoted(expr, quote_at, expr[quote_at])
                    segments.add("lit", text)
                # `"..." % (a, b)` and `"...".format(a, b)` bind to this literal.
                rest = expr[i:].lstrip()
                if rest.startswith("%") and not rest.startswith("%="):
                    i = _apply_percent(expr, i + (len(expr[i:]) - len(rest)) + 1, segments)
                elif rest.startswith(".format("):
                    i = _apply_format(expr, i + (len(expr[i:]) - len(rest)) + len(".format("), segments)
            else:
                text, i = _read_operand_expression(expr, i, "+")
                segments.add("expr", text)
            expect_operand = False
        elif ch == "+":
            expect_operand = True
            i += 1
        else:
            raise TemplateError("expression_shape_not_supported")
    if expect_operand or not segments.parts:
        raise TemplateError("expression_shape_not_supported")
    return segments.parts


def _split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _replace_literal_placeholders(segments: _Segments, pattern: re.Pattern[str], arguments: list[str]) -> None:
    """Splits the last literal on `pattern`, interleaving the arguments in order."""
    if not segments.parts or segments.parts[-1][0] != "lit":
        raise TemplateError("format_target_not_literal")
    literal = segments.parts.pop()[1]
    pieces = pattern.split(literal)
    if len(pieces) - 1 != len(arguments):
        raise TemplateError("format_argument_count_mismatch")
    for index, piece in enumerate(pieces):
        segments.add("lit", piece)
        if index < len(arguments):
            segments.add("expr", arguments[index])


def _apply_percent(expr: str, i: int, segments: _Segments) -> int:
    rest = expr[i:].lstrip()
    offset = i + (len(expr[i:]) - len(rest))
    if rest.startswith("("):
        inner, j = _read_parenthesized(rest)
        arguments = _split_top_level(inner)
        end = offset + j
    else:
        text, j = _read_operand_expression(expr, offset, "+")
        arguments = [text]
        end = j
    if any(q in argument for argument in arguments for q in "'\"") or not arguments:
        raise TemplateError("format_arguments_not_supported")
    _replace_literal_placeholders(segments, re.compile(r"%[sdr]"), arguments)
    return end


def _read_parenthesized(text: str) -> tuple[str, int]:
    depth = 0
    for k, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[1:k], k + 1
    raise TemplateError("unterminated_parenthesis")


def _apply_format(expr: str, i: int, segments: _Segments) -> int:
    inner, j = _read_parenthesized("(" + expr[i:])
    arguments = _split_top_level(inner)
    if any(q in argument or "=" in argument for argument in arguments for q in "'\"") or not arguments:
        raise TemplateError("format_arguments_not_supported")
    _replace_literal_placeholders(segments, re.compile(r"\{\d*\}"), arguments)
    return i + j - 1


def split_first_argument(text: str, start: int) -> tuple[str, str]:
    """The first call argument starting at `start` and the rest of the line from the `,` or `)`."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch in "'\"`":
            _, i = _read_quoted(text, i, ch) if ch != "`" else _skip_template(text, i)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text[start:i].strip(), text[i:]
            depth -= 1
        elif ch == "," and depth == 0:
            return text[start:i].strip(), text[i:]
        i += 1
    raise TemplateError("call_spans_lines")


def _skip_template(text: str, i: int) -> tuple[str, int]:
    depth = 0
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text.startswith("${", j):
            depth += 1
            j += 2
            continue
        if depth and text[j] == "}":
            depth -= 1
        elif not depth and text[j] == "`":
            return text[i + 1 : j], j + 1
        j += 1
    raise TemplateError("unterminated_string")


# --- placeholders ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BoundValue:
    expression: str
    prefix: str = ""
    suffix: str = ""


def bind_placeholders(segments: list[tuple[str, str]], placeholder: Callable[[int], str]) -> tuple[str, list[BoundValue]]:
    """The query text with each interpolation replaced by a placeholder, and the bound values.

    An interpolation wrapped in single quotes (`'${x}'`, `'%${x}%'`) loses the quotes, since a
    bound parameter is never quoted; any wildcard prefix or suffix travels into the value.
    """
    parts = list(segments)
    out: list[str] = []
    values: list[BoundValue] = []
    index = 0
    while index < len(parts):
        kind, text = parts[index]
        if kind == "lit":
            out.append(text)
            index += 1
            continue
        prefix = suffix = ""
        previous = out[-1] if out and parts[index - 1][0] == "lit" else None
        following = parts[index + 1][1] if index + 1 < len(parts) and parts[index + 1][0] == "lit" else None
        if previous is not None and "'" in previous:
            at = previous.rfind("'")
            candidate_prefix = previous[at + 1 :]
            if not re.search(r"\s", candidate_prefix):
                if following is None or "'" not in following:
                    raise TemplateError("unbalanced_quote_around_input")
                close = following.index("'")
                candidate_suffix = following[:close]
                if re.search(r"\s", candidate_suffix):
                    raise TemplateError("unbalanced_quote_around_input")
                prefix, suffix = candidate_prefix, candidate_suffix
                out[-1] = previous[:at]
                parts[index + 1] = ("lit", following[close + 1 :])
        values.append(BoundValue(text, prefix, suffix))
        out.append(placeholder(len(values)))
        index += 1
    return "".join(out), values


def js_string_literal(text: str) -> str:
    if "'" not in text:
        return f"'{text}'"
    if '"' not in text:
        return f'"{text}"'
    if "`" not in text and "${" not in text:
        return f"`{text}`"
    raise TemplateError("query_text_not_quotable")


def py_string_literal(text: str) -> str:
    if '"' not in text:
        return f'"{text}"'
    if "'" not in text:
        return f"'{text}'"
    raise TemplateError("query_text_not_quotable")


def js_value(value: BoundValue) -> str:
    if not value.prefix and not value.suffix:
        return value.expression
    return f"`{value.prefix}${{{value.expression}}}{value.suffix}`"


def py_value(value: BoundValue) -> str:
    if not value.prefix and not value.suffix:
        return value.expression
    return "f" + py_string_literal(f"{value.prefix}{{{value.expression}}}{value.suffix}")


def _hunk(path: str, finding_id: str, start: int, original: list[str], replacement: list[str]) -> dict[str, Any]:
    return {"path": path, "finding_id": finding_id, "start_line": start, "original_lines": list(original), "replacement_lines": list(replacement)}


def _finding_line(finding: FindingSnapshot) -> int:
    return max(1, int(finding.line_start or 1))


def _assignment(line: str) -> tuple[str, str, str, bool] | None:
    """`(prefix, name, expression, has_semicolon)` for `const name = expr;` or `name = expr`."""
    match = re.match(r"^(?P<prefix>\s*(?:(?:const|let|var)\s+)?)(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>.+?)(?P<semi>;?)\s*$", line)
    if not match or match.group("expr").endswith("=") or "==" in match.group("expr").split("(")[0][:2]:
        return None
    return match.group("prefix"), match.group("name"), match.group("expr"), bool(match.group("semi"))


def _require_literal_query(segments: list[tuple[str, str]]) -> None:
    """The query must carry SQL text of its own, not just be one computed expression.

    `db.query(sql)` after `const sql = buildLookup(id)` parses as a single interpolated part with
    no literal around it. Binding that as a parameter would send an empty statement and pass the
    whole query as data. The text is built somewhere this scan cannot see, so nothing here knows
    what is literal and what is input, and the model reads the builder instead.
    """
    if not any(kind == "lit" and text.strip() for kind, text in segments):
        raise TemplateError("query_text_not_literal")


def _sink_and_source(lines: list[str], line: int, start: int, end: int, sink_re: re.Pattern[str]) -> tuple[int, int | None, str, str, str]:
    """`(sink_line, assignment_line, sink_prefix, expression, sink_rest)` for the query call.

    The finding may point at the call or at the assignment of the string the call receives;
    either way the expression is located and both lines are known.
    """
    text = lines[line - 1]
    sink = sink_re.search(text)
    if sink:
        argument, rest = split_first_argument(text, sink.end())
        if re.fullmatch(r"[A-Za-z_$][\w$]*", argument):
            for number in range(line - 1, start, -1):
                assignment = _assignment(lines[number - 1])
                if assignment and assignment[1] == argument:
                    return line, number, text[: sink.end()], assignment[2], rest
            raise TemplateError("query_variable_not_assigned_in_scope")
        return line, None, text[: sink.end()], argument, rest
    assignment = _assignment(text)
    if assignment is None:
        raise TemplateError("sink_not_recognized")
    for number in range(line + 1, end + 1):
        candidate = lines[number - 1]
        found = sink_re.search(candidate)
        if found:
            argument, rest = split_first_argument(candidate, found.end())
            if argument == assignment[1]:
                return number, line, candidate[: found.end()], assignment[2], rest
    raise TemplateError("query_call_not_found_after_assignment")


def _reject_fragments(values: list[BoundValue], lines: list[str], scope_start: int, sink_line: int, parameters: tuple[str, ...], segments_of: Callable[[str], list[tuple[str, str]]]) -> None:
    """A bound value must be data, never SQL text.

    An interpolated name assigned from a string expression in the same scope (`clause = "WHERE
    id = '" + id + "'"`) is a query fragment: binding it as a parameter would silently break the
    query, so the template declines and the model reads the code instead.
    """
    for value in values:
        root = re.match(r"[A-Za-z_$][\w$]*", value.expression)
        if not root:
            raise TemplateError("bound_value_shape_not_supported")
        name = root.group(0)
        if name in ("req", "request") or name in parameters:
            continue
        for number in range(sink_line - 1, scope_start, -1):
            assignment = _assignment(lines[number - 1])
            if assignment is None or assignment[1] != name:
                continue
            try:
                parts = segments_of(assignment[2])
            except TemplateError:
                break
            if any(kind == "lit" for kind, _ in parts):
                raise TemplateError("interpolated_sql_fragment")
            break


# --- JavaScript -----------------------------------------------------------------------------

_JS_QUERY_RE = re.compile(r"\.query\s*\(")
_JS_EXEC_RE = re.compile(r"(?P<callee>(?:[\w$]+\.)?exec(?P<sync>Sync)?)\s*\((?!File)")
_JS_SPAWN_RE = re.compile(r"(?P<callee>(?:[\w$]+\.)?spawn(?P<sync>Sync)?)\s*\(")
_JS_SHELL_OPTION_RE = re.compile(r"shell\s*:\s*true")
# The options object of a process call. Its properties split on commas because it carries no
# nested object; one that does makes the shape unrecognized rather than mis-parsed.
_JS_OPTIONS_RE = re.compile(r",\s*\{(?P<body>[^{}]*)\}")
def _js_sql(snapshot: Snapshot, finding: FindingSnapshot, site: JsRoute | JsFunction | ModuleScope) -> TemplatePatch:
    """Interpolated SQL becomes a parameterized query, wherever the query is built.

    The enclosing scope is only ever read as bounds: how far back to look for the assignment
    that feeds the call, and which names in it are the untrusted ones. A route handler and a
    plain function answer both questions, so the rewrite is the same in either.
    """
    path = finding.affected_path
    lines = snapshot.full_content(path).splitlines()
    sink_line, assign_line, sink_prefix, expression, rest = _sink_and_source(lines, _finding_line(finding), site.start_line, site.end_line, _JS_QUERY_RE)
    if not rest.startswith(")"):
        raise TemplateError("query_call_has_extra_arguments")
    segments = js_segments(expression)
    if not any(kind == "expr" for kind, _ in segments):
        raise TemplateError("no_interpolated_input")
    _require_literal_query(segments)
    text, values = bind_placeholders(segments, lambda n: f"${n}")
    _reject_fragments(values, lines, site.start_line, sink_line, site.parameters, js_segments)
    literal = js_string_literal(text)
    array = "[" + ", ".join(js_value(value) for value in values) + "]"
    if assign_line is None:
        replacement = [f"{sink_prefix}{literal}, {array}{rest}"]
        return TemplatePatch(finding.stable_id, SQL_PARAMETERIZATION, [_hunk(path, finding.stable_id, sink_line, [lines[sink_line - 1]], replacement)], f"pg placeholders {', '.join(f'${i}' for i in range(1, len(values) + 1))} with a values array")
    prefix, name, _, semicolon = _assignment(lines[assign_line - 1])
    first, last = min(assign_line, sink_line), max(assign_line, sink_line)
    original = lines[first - 1 : last]
    replacement = list(original)
    replacement[assign_line - first] = f"{prefix}{name} = {literal}{';' if semicolon else ''}"
    replacement[sink_line - first] = f"{sink_prefix}{name}, {array}{rest}"
    return TemplatePatch(finding.stable_id, SQL_PARAMETERIZATION, [_hunk(path, finding.stable_id, first, original, replacement)], f"pg placeholders {', '.join(f'${i}' for i in range(1, len(values) + 1))} with a values array")


def _tokens(segments: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    """Whitespace-separated command tokens, each a list of literal and expression parts."""
    tokens: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    for kind, text in segments:
        if kind == "expr":
            current.append((kind, text))
            continue
        for piece in re.split(r"(\s+)", text):
            if not piece:
                continue
            if piece.isspace():
                if current:
                    tokens.append(current)
                    current = []
                continue
            current.append(("lit", piece))
    if current:
        tokens.append(current)
    return tokens


def _unquote_token(token: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """`'${x}'` and `"literal"` inside a command string lose their shell quotes."""
    if len(token) >= 2 and token[0][0] == "lit" and token[-1][0] == "lit":
        head, tail = token[0][1], token[-1][1]
        for quote in ("'", '"'):
            if head.startswith(quote) and tail.endswith(quote) and (len(token) > 1 or len(head) > 1):
                inner = [("lit", head[1:])] + token[1:-1] + [("lit", tail[:-1])] if len(token) > 1 else [("lit", head[1:-1])]
                return [part for part in inner if part[0] == "expr" or part[1]]
    if len(token) == 1 and token[0][0] == "lit":
        text = token[0][1]
        for quote in ("'", '"'):
            if len(text) >= 2 and text.startswith(quote) and text.endswith(quote):
                return [("lit", text[1:-1])]
    return token


def _js_argv_element(token: list[tuple[str, str]]) -> str:
    token = _unquote_token(token)
    if len(token) == 1:
        kind, text = token[0]
        return js_string_literal(text) if kind == "lit" else text
    return "`" + "".join(text if kind == "lit" else f"${{{text}}}" for kind, text in token) + "`"


def _py_argv_element(token: list[tuple[str, str]]) -> str:
    token = _unquote_token(token)
    if len(token) == 1:
        kind, text = token[0]
        return py_string_literal(text) if kind == "lit" else text
    return "f" + py_string_literal("".join(text if kind == "lit" else f"{{{text}}}" for kind, text in token))


def _js_without_shell_option(rest: str) -> str:
    """Removes `shell: true` from a process call's options object, and the object once it empties.

    `, { shell: true });` becomes `);`, while `, { shell: true, cwd: base });` keeps the `cwd`.
    """
    match = _JS_OPTIONS_RE.search(rest)
    if match is None:
        raise TemplateError("shell_option_object_not_found")
    kept = [
        item.strip()
        for item in match.group("body").split(",")
        if item.strip() and not _JS_SHELL_OPTION_RE.fullmatch(item.strip())
    ]
    replacement = ", { " + ", ".join(kept) + " }" if kept else ""
    return rest[: match.start()] + replacement + rest[match.end() :]


def _js_command(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """`exec` of a command string becomes `execFile` with an argument array.

    The rewrite reads and replaces the one call, so it needs no enclosing scope at all: a
    command built in a helper, a CLI entry point or a route handler is the same edit.

    `spawn(command, { shell: true })` takes the same rewrite with the shell option dropped and
    the callee left alone, because `spawn` already takes a file and an argument array: the shell
    was the only thing putting the interpolated value back within reach of a command separator.
    The gate has already refused a command whose literal text carries shell syntax an argument
    list cannot express, so what arrives here is a command name and its arguments.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    text = lines[line - 1]
    shell_mode = False
    sink = _JS_EXEC_RE.search(text)
    if not sink:
        sink = _JS_SPAWN_RE.search(text)
        if not sink:
            raise TemplateError("exec_call_not_found")
        shell_mode = True
    argument, rest = split_first_argument(text, sink.end())
    if _JS_SHELL_OPTION_RE.search(rest):
        if not shell_mode:
            # `exec` runs a shell whatever its options say, so the option is not what makes this
            # call shell-mode and removing it would repair nothing.
            raise TemplateError("shell_option_set")
        rest = _js_without_shell_option(rest)
    elif shell_mode:
        # `spawn` without the option already takes an argument array, so this is a different
        # shape (`spawn('sh', ['-c', command])`) that this rewrite does not recognize.
        raise TemplateError("spawn_without_shell_option")
    segments = js_segments(argument)
    tokens = _tokens(segments)
    if not tokens or len(tokens[0]) != 1 or tokens[0][0][0] != "lit":
        raise TemplateError("command_name_not_literal")
    command = js_string_literal(_unquote_token(tokens[0])[0][1])
    argv = "[" + ", ".join(_js_argv_element(token) for token in tokens[1:]) + "]"
    callee = sink.group("callee")
    sync = bool(sink.group("sync"))
    if shell_mode:
        new_name = "spawnSync" if sync else "spawn"
    else:
        new_name = "execFileSync" if sync else "execFile"
    changes: list[dict[str, Any]] = []
    if "." in callee:
        namespace = callee.rsplit(".", 1)[0]
        new_callee = f"{namespace}.{new_name}"
    else:
        new_callee = new_name
        alias, names = js_bound_names(source, "child_process")
        if alias is not None or not names:
            raise TemplateError("child_process_binding_not_recognized")
        if new_name not in names:
            number, require_line = js_require_line(source, "child_process")
            widened = re.sub(r"\{([^}]*)\}", lambda m: "{" + m.group(1).rstrip() + (", " if m.group(1).strip() else " ") + new_name + " }", require_line, count=1)
            changes.append(_hunk(path, finding.stable_id, number, [require_line], [widened]))
    replacement = f"{text[: sink.start()]}{new_callee}({command}, {argv}{rest}"
    changes.append(_hunk(path, finding.stable_id, line, [text], [replacement]))
    summary = (
        f"{callee} of a command string loses shell: true and takes an argument array"
        if shell_mode
        else f"{callee} of a command string becomes {new_callee} with an argument array"
    )
    return TemplatePatch(finding.stable_id, COMMAND_ARGUMENTS, changes, summary)


# What a repaired path helper does when the resolved path leaves its base directory. A caller
# that does not catch gets a 500 instead of somebody else's file, which is the trade the family
# is for; `contracts/repair-v1.md` states it under path_containment.
PATH_ESCAPE_MESSAGE = "path escapes base directory"


def _js_rejection(site: JsRoute | JsFunction | ModuleScope) -> str:
    """The statement that refuses a path escaping the base directory.

    A route handler owns the response, so it answers 400, which is the contract it already has.
    A plain function has no response to write, so it throws: the one behaviour a caller cannot
    mistake for a valid path, where returning a sentinel would be read as one.
    """
    if isinstance(site, JsRoute):
        return f"return {site.res}.status(400).end();"
    # A route handler the module never registered owns a response just the same, and its second
    # parameter is it: answering 400 is the contract its caller already has.
    if isinstance(site, JsFunction) and site.kind == "handler" and len(site.parameter_model) >= 2:
        # The response is the second *parameter*, which a destructured first parameter would
        # push out of line if this counted bound names instead.
        second = site.parameter_model[1].name
        if second:
            return f"return {second}.status(400).end();"
    # A function that takes a continuation reports the refusal through it, for the same reason:
    # that is how it already reports every other failure, and throwing at a caller that is
    # waiting on a callback is a behaviour change on top of the repair.
    if isinstance(site, JsFunction):
        callback = next((name for name in site.parameters if name in JS_CALLBACK_PARAMETERS), None)
        if callback:
            return f"return {callback}(new Error({js_string_literal(PATH_ESCAPE_MESSAGE)}));"
    return f"throw new Error({js_string_literal(PATH_ESCAPE_MESSAGE)});"


def _js_containment_summary(site: JsRoute | JsFunction | ModuleScope) -> str:
    if isinstance(site, JsRoute) or (
        isinstance(site, JsFunction) and site.kind == "handler" and len(site.parameter_model) >= 2
        and site.parameter_model[1].name
    ):
        tail = "answers 400"
    elif isinstance(site, JsFunction) and any(name in JS_CALLBACK_PARAMETERS for name in site.parameters):
        tail = "calls back with an error"
    else:
        tail = "throws"
    return f"path.resolve with a containment check that {tail} before any read"


def _js_traversal(snapshot: Snapshot, finding: FindingSnapshot, site: JsRoute | JsFunction | ModuleScope) -> TemplatePatch:
    """A `path.join` of untrusted input becomes a resolve plus a containment check.

    The check is the same wherever the join is; only how it refuses differs, which is what
    `_js_rejection` decides from the site.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    # The join is looked for before the import, not after it. Reading the import first reported
    # `path_module_not_required` for every path finding whose file happens not to import `path`,
    # including the ones whose sink takes a constant and has nothing to contain at all; the
    # vulnerable-corpus run of 24 September 2026 collected 65 findings under that one reason.
    # Which sink this is decides whether the import matters, so the sink is found first.
    binding = js_module_binding(source, "path", "path")
    join = js_path_site_in_scope(lines, site.start_line, site.end_line, line, (binding.name, "path"))
    join_line = join.line
    rejection = _js_rejection(site)
    changes: list[dict[str, Any]] = []
    if not binding.present:
        # A file that does not import `path` can still be repaired, as long as the name the
        # repair introduces is free: the import is part of the same patch. A file that binds
        # `path` to something else of its own cannot, because the repair's `path.resolve` would
        # read that binding instead of the module.
        if js_identifier_is_bound(source, binding.name):
            raise TemplateError("path_identifier_shadowed")
        anchor = lines[binding.import_line_number - 1]
        changes.append(_hunk(path, finding.stable_id, binding.import_line_number, [anchor], [binding.import_line, anchor]))
    text = lines[join_line - 1]
    base, user_input = join.base, join.user_input
    indent = text[: len(text) - len(text.lstrip())]
    taken = js_names_in(lines[site.start_line - 1 : site.end_line])
    base_name = next(name for name in ("baseDir", "containedBase", "resolvedBase") if name not in taken)
    assignment = _assignment(text)
    if assignment and assignment[2].strip() == join.text:
        target = assignment[1]
        tail: list[str] = []
    else:
        target = next(name for name in ("target", "safeTarget", "resolvedTarget") if name not in taken)
        tail = [text.replace(join.text, target, 1)]
    module = binding.name
    # A composed path arrives as string-typed expressions already, so wrapping it again would
    # read as `String(String(name) + '.yml')`.
    coerced = user_input if join.composed else f"String({user_input})"
    head = [
        f"{indent}const {base_name} = {module}.resolve({base});",
        f"{indent}const {target} = {module}.resolve({base_name}, {coerced});",
        f"{indent}if ({target} !== {base_name} && !{target}.startsWith({base_name} + {module}.sep)) {rejection}",
    ]
    last = max(join_line, line)
    original = lines[join_line - 1 : last]
    replacement = head + tail + lines[join_line:last]
    changes.append(_hunk(path, finding.stable_id, join_line, original, replacement))
    return TemplatePatch(finding.stable_id, PATH_CONTAINMENT, changes, _js_containment_summary(site))


# --- Python ---------------------------------------------------------------------------------

_PY_EXECUTE_RE = re.compile(r"\.(?:execute|exec_driver_sql)\s*\(")
_PY_SUBPROCESS_RE = re.compile(r"(?P<callee>subprocess\.(?:run|call|check_call|check_output|Popen))\s*\(")
_PY_JOIN_RE = re.compile(r"os\.path\.join\(\s*(?P<base>[^,()]+?)\s*,\s*(?P<input>[^()]+?)\s*\)")
_PLACEHOLDERS: dict[str, Callable[[int], str]] = {
    "sqlite3": lambda n: "?",
    "aiosqlite": lambda n: "?",
    "psycopg2": lambda n: "%s",
    "psycopg": lambda n: "%s",
    "pymysql": lambda n: "%s",
    "MySQLdb": lambda n: "%s",
    "mysql.connector": lambda n: "%s",
    "asyncpg": lambda n: f"${n}",
    "sqlalchemy": lambda n: f":p{n}",
}


def _py_driver(snapshot: Snapshot, path: str) -> str:
    modules = python_imports(snapshot.full_content(path))
    for name in sorted(modules):
        for driver in PYTHON_SQL_DRIVERS:
            if name == driver or name.startswith(driver + "."):
                return driver
    from .gates import _local_module_paths

    for name in sorted(modules):
        for local in _local_module_paths(snapshot, path, name):
            for imported in python_imports(snapshot.full_content(local)):
                for driver in PYTHON_SQL_DRIVERS:
                    if imported == driver or imported.startswith(driver + "."):
                        return driver
    raise TemplateError("sql_driver_not_identified")


def _py_import_hunk(source: str, path: str, finding_id: str, module: str, before_line: int | None = None) -> dict[str, Any] | None:
    if module in python_imports(source):
        return None
    lines = source.splitlines()
    line, after = python_import_anchor(source, before_line)
    anchor = lines[line - 1]
    return _hunk(path, finding_id, line, [anchor], [anchor, f"import {module}"] if after else [f"import {module}", anchor])


def _py_sql(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> TemplatePatch:
    path = finding.affected_path
    lines = snapshot.full_content(path).splitlines()
    driver = _py_driver(snapshot, path)
    sink_line, assign_line, sink_prefix, expression, rest = _sink_and_source(lines, _finding_line(finding), function.start_line, function.end_line, _PY_EXECUTE_RE)
    if not rest.startswith(")"):
        raise TemplateError("execute_call_has_extra_arguments")
    segments = py_segments(expression)
    if not any(kind == "expr" for kind, _ in segments):
        raise TemplateError("no_interpolated_input")
    _require_literal_query(segments)
    text, values = bind_placeholders(segments, _PLACEHOLDERS[driver])
    _reject_fragments(values, lines, function.start_line, sink_line, function.parameters, py_segments)
    literal = py_string_literal(text)
    if driver == "sqlalchemy":
        params = "{" + ", ".join(f'"p{i}": {py_value(value)}' for i, value in enumerate(values, 1)) + "}"
        if "text(" in expression or "text(" in sink_prefix:
            raise TemplateError("sqlalchemy_text_shape_not_supported")
    else:
        rendered = [py_value(value) for value in values]
        params = f"({rendered[0]},)" if len(rendered) == 1 else "(" + ", ".join(rendered) + ")"
    if assign_line is None:
        replacement = [f"{sink_prefix}{literal}, {params}{rest}"]
        return TemplatePatch(finding.stable_id, SQL_PARAMETERIZATION, [_hunk(path, finding.stable_id, sink_line, [lines[sink_line - 1]], replacement)], f"{driver} placeholders with bound parameters")
    prefix, name, _, _ = _assignment(lines[assign_line - 1])
    first, last = min(assign_line, sink_line), max(assign_line, sink_line)
    original = lines[first - 1 : last]
    replacement = list(original)
    replacement[assign_line - first] = f"{prefix}{name} = {literal}"
    replacement[sink_line - first] = f"{sink_prefix}{name}, {params}{rest}"
    return TemplatePatch(finding.stable_id, SQL_PARAMETERIZATION, [_hunk(path, finding.stable_id, first, original, replacement)], f"{driver} placeholders with bound parameters")


def _js_credential(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """`const apiKey = "sk-live-…"` becomes `const apiKey = process.env.API_KEY`.

    The environment name is derived from the identifier the literal is bound to, so the
    repair does not invent a name the author has to look up, and `process.env` needs no
    import. A config key (`apiKey: "sk-live-…"`) takes the same rewrite on the value.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    found = js_literal_assignment_in_span(source, finding.line_start, finding.line_end)
    if found is None:
        raise TemplateError("string_literal_assignment_not_found")
    line, (name, literal, quote, _kind) = found
    variable = js_environment_name(name)
    if not variable:
        raise TemplateError("environment_name_not_derived")
    text = source.splitlines()[line - 1]
    needle = f"{quote}{literal}{quote}"
    if text.count(needle) != 1:
        # More than one occurrence means the rewrite would have to choose, and choosing
        # wrong rewrites a different value on the same line.
        raise TemplateError("literal_not_uniquely_placed")
    replacement = text.replace(needle, f"process.env.{variable}", 1)
    if replacement == text:
        raise TemplateError("assignment_not_rewritten")
    return TemplatePatch(
        finding.stable_id,
        HARDCODED_CREDENTIAL,
        [_hunk(path, finding.stable_id, line, [text], [replacement])],
        f"{name} read from process.env.{variable} instead of a literal",
    )


def _js_eval(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """`eval(raw)` of a request value becomes `JSON.parse(raw)`.

    This is the JavaScript reading of the decision the Python family makes with
    `ast.literal_eval`: when the string is a document the code reads back as a value, parsing it
    as data preserves what the function returns and removes the interpreter. When the string is
    a program, the gate has already refused the finding, so what arrives here is the data shape.
    `eval` of anything but a single identifier, or of an identifier that does not come from a
    parameter, is left to the model, because the template cannot say what the string holds.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    line = _finding_line(finding)
    try:
        _function, _untrusted, _members = js_eval_site(source, line)
    except SiteError as exc:
        raise TemplateError(exc.code) from exc
    text = source.splitlines()[line - 1]
    found = JS_EVAL_ARGUMENT_RE.search(text)
    if not found:
        raise TemplateError("eval_argument_not_an_identifier")
    replacement = text[: found.start()] + f"JSON.parse({found.group('arg')})" + text[found.end() :]
    return TemplatePatch(
        finding.stable_id,
        CODE_INJECTION_EVAL,
        [_hunk(path, finding.stable_id, line, [text], [replacement])],
        f"eval({found.group('arg')}) becomes JSON.parse({found.group('arg')})",
    )


def _py_credential(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    path = finding.affected_path
    source = snapshot.full_content(path)
    line = _finding_line(finding)
    assignment = python_module_assignment(source, line)
    if assignment is None:
        raise TemplateError("module_level_string_assignment_not_found")
    name, literal, quote = assignment
    text = source.splitlines()[line - 1]
    replacement = re.sub(rf"^(\s*{re.escape(name)}\s*=\s*){re.escape(quote)}{re.escape(literal)}{re.escape(quote)}", rf'\1os.environ["{name}"]', text, count=1)
    if replacement == text:
        raise TemplateError("assignment_not_rewritten")
    changes = [_hunk(path, finding.stable_id, line, [text], [replacement])]
    import_hunk = _py_import_hunk(source, path, finding.stable_id, "os", line)
    if import_hunk:
        changes.insert(0, import_hunk)
    return TemplatePatch(finding.stable_id, HARDCODED_CREDENTIAL, changes, f"{name} read from the environment instead of a literal")


def _py_eval(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> TemplatePatch:
    path = finding.affected_path
    source = snapshot.full_content(path)
    line = _finding_line(finding)
    text = source.splitlines()[line - 1]
    found = re.search(r"(?<![\w.])eval\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)", text)
    if not found or found.group("arg") not in function.parameters:
        raise TemplateError("eval_argument_not_a_parameter")
    replacement = text[: found.start()] + f"ast.literal_eval({found.group('arg')})" + text[found.end() :]
    changes = [_hunk(path, finding.stable_id, line, [text], [replacement])]
    import_hunk = _py_import_hunk(source, path, finding.stable_id, "ast", line)
    if import_hunk:
        changes.insert(0, import_hunk)
    return TemplatePatch(finding.stable_id, CODE_INJECTION_EVAL, changes, "ast.literal_eval instead of eval")


def _py_command(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> TemplatePatch:
    path = finding.affected_path
    source = snapshot.full_content(path)
    line = _finding_line(finding)
    text = source.splitlines()[line - 1]
    sink = _PY_SUBPROCESS_RE.search(text)
    if not sink:
        raise TemplateError("subprocess_call_not_found")
    argument, rest = split_first_argument(text, sink.end())
    if not re.search(r"shell\s*=\s*True", rest):
        raise TemplateError("shell_true_not_present")
    tokens = _tokens(py_segments(argument))
    if not tokens or len(tokens[0]) != 1 or tokens[0][0][0] != "lit":
        raise TemplateError("command_name_not_literal")
    argv = "[" + ", ".join(_py_argv_element(token) for token in tokens) + "]"
    cleaned = re.sub(r",\s*shell\s*=\s*True", "", rest, count=1)
    if cleaned == rest:
        cleaned = re.sub(r"shell\s*=\s*True\s*,?\s*", "", rest, count=1)
    replacement = f"{text[: sink.end()]}{argv}{cleaned}"
    return TemplatePatch(finding.stable_id, COMMAND_ARGUMENTS, [_hunk(path, finding.stable_id, line, [text], [replacement])], f"{sink.group('callee')} with an argv list and no shell")


def _py_traversal(snapshot: Snapshot, finding: FindingSnapshot, function: PyFunction) -> TemplatePatch:
    """The same containment rewrite as `_js_traversal`, refusing the same way.

    A Flask view aborts 400; a plain function raises `ValueError`, for the reason
    `_js_rejection` gives on the JavaScript side.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    if "os" not in python_imports(source):
        raise TemplateError("os_not_imported")
    flask_import = re.search(r"^from flask import (?P<names>[^\n#]+)$", source, re.M) if function.route else None
    if function.route and not flask_import:
        raise TemplateError("flask_import_not_found")
    join_line = None
    for number in scope_lines_near(function.start_line, function.end_line, line):
        if _PY_JOIN_RE.search(lines[number - 1]):
            join_line = number
            break
    if join_line is None:
        raise TemplateError("path_join_not_found_in_scope")
    text = lines[join_line - 1]
    found = _PY_JOIN_RE.search(text)
    base, user_input = found.group("base"), found.group("input")
    indent = text[: len(text) - len(text.lstrip())]
    assignment = _assignment(text)
    body_text = "\n".join(lines[function.start_line - 1 : function.end_line])
    base_name = next(name for name in ("base_dir", "contained_base") if not re.search(rf"(?<!\w){name}(?!\w)", body_text))
    if assignment and assignment[2].strip() == found.group(0):
        target = assignment[1]
        tail: list[str] = []
    else:
        target = next(name for name in ("target", "safe_target") if not re.search(rf"(?<!\w){name}(?!\w)", body_text))
        tail = [text.replace(found.group(0), target, 1)]
    rejection = "abort(400)" if function.route else f"raise ValueError({py_string_literal(PATH_ESCAPE_MESSAGE)})"
    head = [
        f"{indent}{base_name} = os.path.realpath({base})",
        f"{indent}{target} = os.path.realpath(os.path.join({base_name}, {user_input}))",
        f"{indent}if {target} != {base_name} and not {target}.startswith({base_name} + os.sep):",
        f"{indent}    {rejection}",
    ]
    last = max(join_line, line)
    changes = [_hunk(path, finding.stable_id, join_line, lines[join_line - 1 : last], head + tail + lines[join_line:last])]
    if flask_import is not None:
        names = [item.strip() for item in flask_import.group("names").split(",")]
        if "abort" not in names:
            number = source[: flask_import.start()].count("\n") + 1
            changes.insert(0, _hunk(path, finding.stable_id, number, [flask_import.group(0)], [f"from flask import {', '.join(names + ['abort'])}"]))
    tail_text = "aborts 400" if function.route else "raises ValueError"
    return TemplatePatch(finding.stable_id, PATH_CONTAINMENT, changes, f"os.path.realpath with a containment check that {tail_text} before any file access")


# --- GitHub Actions workflows ---------------------------------------------------------------
#
# Four shapes, and only four, because only four are unambiguous: a mutable action reference, an
# interpolation inside a `run:` script, an `actions/checkout` of the pull request's revision under
# a privileged trigger, and a write grant under `pull_request_target`.
#
# The last two were design decisions until the rules that report them were narrowed to the point
# where the edit is the whole answer. `cwe-829.gha-pwn-request-checkout` only fires on a `ref:`
# that is an input to `actions/checkout`, so pointing it at the base revision (or removing it)
# is exactly the change GitHub's own advisory gives. `cwe-732.gha-write-grant-on-pull-request-target`
# only fires on three grants under the one trigger a stranger can fire, and dropping the grant is
# the repair its message asks for. The wider rules those two narrow keep no template, because
# what they report is not always a checkout or not always unwanted.
#
# Everything else the workflow rules find is still a design decision rather than an edit. Moving
# a build out of `pull_request_target` changes which revision CI runs; replacing a self-hosted
# runner changes where it runs; an artifact that is executed belongs in the other workflow; a
# script piped from a URL needs a pinned install whose shape depends on how the tool is published.
# A patch cannot make those choices for a maintainer, so those findings carry the explanation and
# no candidate.

# `uses: owner/repo@ref`, with the leading list dash and surrounding quotes optional, and any
# trailing comment kept so a version note survives the rewrite.
_ACTION_USES_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?:-[ \t]+)?uses[ \t]*:[ \t]*)"
    r"(?P<quote>['\"]?)(?P<repo>[^\s'\"@]+)@(?P<ref>[^\s'\"#]+)(?P=quote)"
    r"(?P<tail>[ \t]*(?:#.*)?)$"
)
_FULL_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# The interpolations the workflow injection rule reports, as they appear in a script.
_GHA_EXPRESSION_RE = re.compile(r"\$\{\{(?P<body>[^}]*?)\}\}")
_GHA_FIELD_RE = re.compile(r"(?:github|inputs|needs|steps|env|vars|matrix)(?:\.[\w-]+|\[[^\]]*\])+")

# The rule ids whose findings these templates repair, by the fragment of the id that names them.
PWN_REQUEST_RULE = "gha-pwn-request-checkout"
WRITE_GRANT_RULE = "gha-write-grant-on-pull-request-target"

# A trigger key, at the indentation the rules match it at. The same approximation as the rules,
# and deliberately so: the repair has to decide which trigger the finding was reported under,
# and deciding it differently from the rule would repair a workflow the rule did not mean.
_PULL_REQUEST_TARGET_RE = re.compile(r"^[ \t]{0,4}pull_request_target[ \t]*:", re.M)
_WORKFLOW_RUN_RE = re.compile(r"^[ \t]{0,4}workflow_run[ \t]*:", re.M)
_CHECKOUT_USES_RE = re.compile(r"^[ \t]*(?:-[ \t]+)?uses[ \t]*:[ \t]*['\"]?actions/checkout@")
_REF_LINE_RE = re.compile(r"^(?P<prefix>[ \t]*ref[ \t]*:[ \t]*)(?P<value>[^#]*?)(?P<tail>[ \t]+#.*)?[ \t]*$")
# The values the pwn request rule reports, copied from its pattern.
_UNTRUSTED_REF_RE = re.compile(
    r"\$\{\{[ \t]*github\.event\.pull_request\.(?:head\.(?:sha|ref)|merge_commit_sha)"
    r"|\$\{\{[ \t]*github\.event\.workflow_run\.head_(?:sha|branch)"
    r"|\$\{\{[ \t]*github\.head_ref"
    r"|refs/pull/"
)
BASE_REVISION = "${{ github.event.pull_request.base.sha }}"
_WRITE_ALL_RE = re.compile(r"^(?P<indent>[ \t]*)permissions[ \t]*:[ \t]*(?P<quote>['\"]?)write-all(?P=quote)(?P<tail>[ \t]*(?:#.*)?)$")
_SCOPE_WRITE_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<scope>contents|id-token)[ \t]*:[ \t]*(?P<quote>['\"]?)write(?P=quote)(?P<tail>[ \t]*(?:#.*)?)$")
_PERMISSIONS_KEY_RE = re.compile(r"^(?P<indent>[ \t]*)permissions[ \t]*:[ \t]*(?:#.*)?$")
_WITH_KEY_RE = re.compile(r"^[ \t]*(?:-[ \t]+)?with[ \t]*:[ \t]*(?:#.*)?$")

ACTION_DIGEST_UNRESOLVED = "action_digest_unresolved"
WORKFLOW_NOT_A_WORKFLOW = "not_a_workflow_path"


def _finding_extra(finding: FindingSnapshot) -> dict[str, Any]:
    """`evidence_details.extra` off a finding, which allows extra fields, or an empty mapping."""
    details = getattr(finding, "evidence_details", None) or {}
    if not isinstance(details, dict):
        return {}
    extra = details.get("extra")
    return extra if isinstance(extra, dict) else {}


def environment_variable_name(expression: str) -> str:
    """A shell-safe environment variable name for one `${{ ... }}` body.

    Derived from the expression's own field path so the name says where the value came from:
    `github.event.pull_request.title` becomes `PR_TITLE` and `github.event.comment.body` becomes
    `COMMENT_BODY`. It is deterministic, because the patch that writes it and the reviewer who
    reads it both have to agree on it.
    """
    field = _GHA_FIELD_RE.search(expression or "")
    path = (field.group(0) if field else (expression or "")).strip()
    parts = [part for part in re.split(r"[^\w]+", path) if part]
    # `github` and `event` carry no meaning in a variable name, and neither does an index.
    meaningful = [part for part in parts if part.lower() not in {"github", "event"} and not part.isdigit()]
    tail = meaningful[-2:] if len(meaningful) >= 2 else meaningful
    if tail[:1] == ["pull_request"]:
        tail = ["pr"] + tail[1:]
    name = re.sub(r"[^A-Z0-9_]", "_", "_".join(tail).upper()).strip("_")
    if not name or name[0].isdigit():
        name = f"GHA_{name}" if name else "UNTRUSTED_INPUT"
    return name


def _workflow_pin_action(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """Replace `uses: owner/repo@v3` with the digest that ref resolves to, keeping the tag as a note.

    The digest is not resolved here. It is resolved at analysis time, where the product still has
    the network, and carried on the finding as `resolved_action_digest`: the repair sandbox has no
    egress by design, so a template that reached for the GitHub API would either fail or prove the
    sandbox does not hold.
    """
    path = finding.affected_path
    line = _finding_line(finding)
    lines = snapshot.full_content(path).split("\n")
    if line > len(lines):
        raise TemplateError("workflow_line_out_of_range")
    original = lines[line - 1]
    match = _ACTION_USES_RE.match(original)
    if not match:
        raise TemplateError("action_reference_not_found")
    if _FULL_DIGEST_RE.match(match.group("ref")):
        raise TemplateError("action_already_pinned")

    digest = str(_finding_extra(finding).get("resolved_action_digest") or "").strip()
    if not _FULL_DIGEST_RE.match(digest):
        # Refused, not guessed. Writing a digest nobody resolved would change which code runs.
        raise TemplateError(ACTION_DIGEST_UNRESOLVED)

    ref = match.group("ref")
    existing_comment = (match.group("tail") or "").strip()
    if existing_comment.startswith("#"):
        note = existing_comment if ref in existing_comment else f"{existing_comment} ({ref})"
    else:
        note = f"# {ref}"
    quote = match.group("quote")
    replacement = f"{match.group('prefix')}{quote}{match.group('repo')}@{digest.lower()}{quote} {note}"
    return TemplatePatch(
        finding.stable_id,
        WORKFLOW_HARDENING,
        [_hunk(path, finding.stable_id, line, [original], [replacement])],
        f"{match.group('repo')} pinned to the commit {ref} resolves to, with {ref} kept as a comment",
    )


def _workflow_env_binding(snapshot: Snapshot, finding: FindingSnapshot, step: WorkflowStep) -> TemplatePatch:
    """Move every attacker-controlled `${{ ... }}` out of a `run:` script into the step's `env:`.

    The script then reads `"$VAR"`, which the shell expands as one word and never re-parses, and
    the expression is evaluated by Actions into an environment value that no shell ever sees as
    source. This is the fix GitHub itself documents, and it is the one the rule was written to go
    quiet on, which is what lets the static assertion level prove it.
    """
    path = finding.affected_path
    line = _finding_line(finding)
    lines = snapshot.full_content(path).split("\n")
    if line > len(lines):
        raise TemplateError("workflow_line_out_of_range")
    original = lines[line - 1]

    bindings: list[tuple[str, str]] = []
    claimed: dict[str, str] = {}

    def substitute(match: re.Match[str]) -> str:
        body = match.group("body").strip()
        name = environment_variable_name(body)
        # Two different expressions that derive the same name would collide, so the second gets a
        # suffix rather than silently taking the first one's value.
        if claimed.get(name, body) != body:
            index = 2
            while claimed.get(f"{name}_{index}", body) != body:
                index += 1
            name = f"{name}_{index}"
        claimed[name] = body
        if all(existing != name for existing, _ in bindings):
            bindings.append((name, body))
        return f'"${name}"'

    rewritten = _GHA_EXPRESSION_RE.sub(substitute, original)
    if not bindings:
        raise TemplateError("no_interpolation_at_finding")
    # `echo "${{ x }}"` would become `echo ""$X""`: the quotes the author already wrote around the
    # interpolation are now redundant, so they are collapsed rather than doubled.
    rewritten = re.sub(r'"(")(\$[A-Z0-9_]+)"(")', r'"\2"', rewritten)

    changes = [_hunk(path, finding.stable_id, line, [original], [rewritten])]

    pad = " " * step.key_indent
    entries = [f"{pad}  {name}: ${{{{ {body} }}}}" for name, body in bindings]
    if step.env_line is not None:
        anchor = lines[step.env_line - 1]
        changes.insert(0, _hunk(path, finding.stable_id, step.env_line, [anchor], [anchor, *entries]))
    else:
        # A new block, anchored on the step's first line so it reads before the script that uses
        # it and the hunk stays one line wide.
        anchor = lines[step.start_line - 1]
        changes.insert(
            0,
            _hunk(path, finding.stable_id, step.start_line, [anchor], [anchor, f"{pad}env:", *entries]),
        )

    names = ", ".join(name for name, _ in bindings)
    return TemplatePatch(
        finding.stable_id,
        WORKFLOW_HARDENING,
        changes,
        f"the interpolated event data bound to {names} in the step's env block and read as a quoted shell variable",
    )


def _workflow_rule_ids(finding: FindingSnapshot) -> list[str]:
    """The finding's own rule id and every rule the clusterer merged into it, lower-cased.

    The pwn request rule and the wider checkout rule match the same line and share an internal
    type, so they arrive as one finding whose surviving `rule_id` depends on the clusterer. The
    union travels in `evidence_details.extra.merged_rule_ids`, and that is what decides whether the
    narrower rule saw this line.
    """
    ids = [str(finding.rule_id or "").lower()]
    merged = _finding_extra(finding).get("merged_rule_ids")
    if isinstance(merged, list):
        ids.extend(str(item or "").lower() for item in merged)
    return ids


def _leading(text: str) -> int:
    return len(text) - len(text.lstrip(" \t"))


def _parent_index(lines: list[str], index: int) -> int | None:
    """The 0-based index of the nearest line above `index` indented less than it, or None."""
    indent = _leading(lines[index])
    for candidate in range(index - 1, -1, -1):
        text = lines[candidate]
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        if _leading(text) < indent:
            return candidate
    return None


def _has_sibling_key(lines: list[str], parent: int, index: int) -> bool:
    """Whether the block under `parent` has a key other than the one on line `index`."""
    indent = _leading(lines[index])
    for candidate in range(parent + 1, len(lines)):
        text = lines[candidate]
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        if _leading(text) < indent:
            break
        if candidate != index and _leading(text) == indent:
            return True
    return False


def _workflow_checkout_base_revision(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """Point a privileged checkout at the base revision, or let it take the default branch.

    Under `pull_request_target` the base revision is `github.event.pull_request.base.sha`, which
    is the commit the workflow itself was read from, so the job checks out code the repository
    already trusts. Under `workflow_run` there is no pull request in the event, so the `ref:` line
    is removed and the checkout falls back to the default branch. A workflow that declares both
    triggers gets the removal, because the base revision expression is empty under the second.

    Either way the job no longer has the contributor's revision on disk. Whatever it did with
    that revision (a preview build, a test run, a label from a file in the branch) now happens on
    the base, and that is the intended change: the job keeps its secrets and loses the stranger's
    code, which is what GitHub's own advice for this trigger says to do.
    """
    path = finding.affected_path
    line = _finding_line(finding)
    content = snapshot.full_content(path)
    lines = content.split("\n")
    if line > len(lines):
        raise TemplateError("workflow_line_out_of_range")
    original = lines[line - 1]
    match = _REF_LINE_RE.match(original)
    if not match or not _UNTRUSTED_REF_RE.search(match.group("value")):
        raise TemplateError("untrusted_ref_not_found")
    # The rule asks for the checkout step, and so does the repair: the same `ref:` under any other
    # action means something else, which is the google/slo-generator false positive.
    step = workflow_step_for_line(content, line)
    if not any(_CHECKOUT_USES_RE.match(text) for text in lines[step.start_line - 1 : step.end_line]):
        raise TemplateError("ref_not_under_checkout")

    target = bool(_PULL_REQUEST_TARGET_RE.search(content))
    workflow_run = bool(_WORKFLOW_RUN_RE.search(content))
    if not target and not workflow_run:
        raise TemplateError("privileged_trigger_not_found")

    if target and not workflow_run:
        value = match.group("value").strip()
        quote = value[0] if value[:1] in {"'", '"'} and value[-1:] == value[:1] else ""
        replacement = f"{match.group('prefix')}{quote}{BASE_REVISION}{quote}{match.group('tail') or ''}"
        return TemplatePatch(
            finding.stable_id,
            WORKFLOW_HARDENING,
            [_hunk(path, finding.stable_id, line, [original], [replacement])],
            "actions/checkout pointed at the pull request's base revision instead of its head",
        )

    # `workflow_run`: the line goes. If it was the only input under `with:`, the `with:` goes too,
    # because an empty `with:` is a null mapping and Actions rejects it.
    parent = _parent_index(lines, line - 1)
    if parent is not None and _WITH_KEY_RE.match(lines[parent]) and not _has_sibling_key(lines, parent, line - 1):
        if lines[parent].lstrip().startswith("-"):
            # `- with:` opens the step; removing it would remove the step's list item.
            raise TemplateError("checkout_with_opens_the_step")
        start = parent + 1
        removed = lines[parent : line]
    else:
        start = line
        removed = [original]
    return TemplatePatch(
        finding.stable_id,
        WORKFLOW_HARDENING,
        [_hunk(path, finding.stable_id, start, removed, [])],
        "the ref: input removed, so actions/checkout takes the default branch rather than the triggering run's head",
    )


def _workflow_drop_write_grant(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """Remove the write half of a grant under `pull_request_target`.

    `write-all` becomes `read-all`, `contents: write` becomes `contents: read`, and `id-token:
    write` is deleted, because `id-token` has no read level. If that leaves the `permissions:`
    block empty it becomes `permissions: {}`, which grants nothing, rather than a bare key, which
    YAML reads as null and Actions rejects.

    This can break the job, and that is said in the description rather than hidden: a step that
    pushed a branch or minted a cloud credential will now fail. The rule is quarantined on exactly
    that observation (each job it was measured on used the scope it asked for), so this template
    is what a re-enabled rule would ship, not what ships today.
    """
    path = finding.affected_path
    line = _finding_line(finding)
    lines = snapshot.full_content(path).split("\n")
    if line > len(lines):
        raise TemplateError("workflow_line_out_of_range")
    original = lines[line - 1]
    description = (
        "the write grant removed from a pull_request_target workflow; a step that needed it will "
        "now fail, and whether that step belongs under this trigger is the maintainer's call"
    )

    write_all = _WRITE_ALL_RE.match(original)
    if write_all:
        replacement = f"{write_all.group('indent')}permissions: read-all{write_all.group('tail') or ''}"
        return TemplatePatch(
            finding.stable_id, WORKFLOW_HARDENING, [_hunk(path, finding.stable_id, line, [original], [replacement])], description
        )

    scope = _SCOPE_WRITE_RE.match(original)
    if not scope:
        raise TemplateError("write_grant_not_found")
    parent = _parent_index(lines, line - 1)
    if parent is None or not _PERMISSIONS_KEY_RE.match(lines[parent]):
        raise TemplateError("write_grant_not_under_permissions")

    if scope.group("scope") == "contents":
        replacement = f"{scope.group('indent')}contents: read{scope.group('tail') or ''}"
        return TemplatePatch(
            finding.stable_id, WORKFLOW_HARDENING, [_hunk(path, finding.stable_id, line, [original], [replacement])], description
        )

    if _has_sibling_key(lines, parent, line - 1):
        return TemplatePatch(
            finding.stable_id, WORKFLOW_HARDENING, [_hunk(path, finding.stable_id, line, [original], [])], description
        )
    indent = _PERMISSIONS_KEY_RE.match(lines[parent]).group("indent")
    return TemplatePatch(
        finding.stable_id,
        WORKFLOW_HARDENING,
        [_hunk(path, finding.stable_id, parent + 1, lines[parent : line], [f"{indent}permissions: {{}}"])],
        description,
    )


def _workflow(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """Dispatch on which of the four repairable shapes this finding is."""
    path = finding.affected_path
    if not is_workflow_path(path):
        raise TemplateError(WORKFLOW_NOT_A_WORKFLOW)
    rule = str(finding.rule_id or "").lower()
    internal_type = str(getattr(finding, "internal_type", "") or "").lower()
    rule_ids = _workflow_rule_ids(finding)
    # By rule id and never by internal type: the pwn request rule shares `untrusted_code_checkout`
    # with the wider checkout rule and the write grant rule shares `excessive_workflow_permissions`
    # with two others, and neither template is right for what those report.
    if any(PWN_REQUEST_RULE in item for item in rule_ids):
        return _workflow_checkout_base_revision(snapshot, finding)
    if any(WRITE_GRANT_RULE in item for item in rule_ids):
        return _workflow_drop_write_grant(snapshot, finding)
    if "unpinned-action" in rule or internal_type == "unpinned_action_reference":
        return _workflow_pin_action(snapshot, finding)
    if "run-untrusted-interpolation" in rule or internal_type == "workflow_script_injection":
        step = workflow_step_for_line(snapshot.full_content(path), _finding_line(finding))
        return _workflow_env_binding(snapshot, finding, step)
    # Every other workflow finding is a design decision, not an edit.
    raise TemplateError("workflow_shape_not_templated")


# --- password hashing -----------------------------------------------------------------------
#
# The stored format becomes `scrypt$<16-byte salt hex>$<32-byte key hex>`, 104 characters: the
# salt travels with the hash, so the verifier needs nothing but the stored string. scrypt is in both standard
# libraries (Node `crypto.scryptSync`, Python `hashlib.scrypt`), so the repair adds no
# dependency, and its default cost (N=2^14, r=8, p=1) is the one both document.
#
# What the repair cannot do is convert digests already stored: they no longer verify, so the
# description says so, and a maintainer applies it knowing those accounts need a reset.

PASSWORD_MIGRATION_NOTE = (
    "digests stored before this change no longer verify and need a password reset, and the stored "
    "value is now 104 characters"
)


def _rewrite_comparisons(path: str, finding_id: str, lines: list[str], site: PasswordHashSite, negate: str) -> list[dict[str, Any]]:
    by_line: dict[int, list[Any]] = {}
    for comparison in site.comparisons:
        by_line.setdefault(comparison.line, []).append(comparison)
    changes = []
    for number, items in sorted(by_line.items()):
        text = lines[number - 1]
        rewritten = text
        for comparison in sorted(items, key=lambda item: item.start, reverse=True):
            call = f"{site.verifier}({comparison.password}, {comparison.stored})"
            rewritten = rewritten[: comparison.start] + (negate + call if comparison.negated else call) + rewritten[comparison.end :]
        changes.append(_hunk(path, finding_id, number, [text], [rewritten]))
    return changes


def _js_password(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """A fast digest of a password becomes `crypto.scryptSync` with a random per-call salt."""
    path = finding.affected_path
    lines = snapshot.full_content(path).splitlines()
    site = password_hash_site(snapshot, finding, JAVASCRIPT)
    c, p, i, b = site.module, site.parameter, site.indent, site.body_indent
    body = [
        f"{b}const salt = {c}.randomBytes(16).toString('hex');",
        f"{b}return ['scrypt', salt, {c}.scryptSync({p}, salt, 32).toString('hex')].join('$');",
    ]
    if site.arrow:
        declaration = lines[site.start_line - 1]
        head = declaration[: declaration.index("=>") + 2]
        function = [f"{head} {{", *body, f"{i}}};"]
    else:
        function = [lines[site.start_line - 1], *body, lines[site.end_line - 1]]
    signature = f"{p}: string, stored: string): boolean" if site.typescript else f"{p}, stored)"
    verifier = [
        "",
        f"{i}function {site.verifier}({signature} {{",
        f"{b}const [scheme, salt, expected] = String(stored).split('$');",
        f"{b}if (scheme !== 'scrypt' || !salt || !expected) return false;",
        f"{b}const actual = {c}.scryptSync({p}, salt, 32);",
        f"{b}const wanted = Buffer.from(expected, 'hex');",
        f"{b}return wanted.length === actual.length && {c}.timingSafeEqual(actual, wanted);",
        f"{i}}}",
    ]
    original = lines[site.start_line - 1 : site.end_line]
    changes = [_hunk(path, finding.stable_id, site.start_line, original, function + verifier)]
    changes += _rewrite_comparisons(path, finding.stable_id, lines, site, "!")
    return TemplatePatch(
        finding.stable_id, PASSWORD_HASHING, sorted(changes, key=lambda change: change["start_line"]),
        f"{site.function} derives a salted scrypt key instead of a {site.algorithm} digest, and each comparison "
        f"calls {site.verifier}; {PASSWORD_MIGRATION_NOTE}",
    )


def _py_password(snapshot: Snapshot, finding: FindingSnapshot) -> TemplatePatch:
    """The Python counterpart: `hashlib.scrypt` with an `os.urandom` salt, verified with hmac."""
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    site = password_hash_site(snapshot, finding, PYTHON)
    h, p, a, i, b = site.module, site.parameter, site.argument, site.indent, site.body_indent
    cost = "n=2**14, r=8, p=1, dklen=32"
    function = [
        *site.keep_lines,
        f"{b}salt = os.urandom(16)",
        f"{b}digest = {h}.scrypt({a}, salt=salt, {cost})",
        f'{b}return "scrypt$" + salt.hex() + "$" + digest.hex()',
        "",
        "",
        f"{i}def {site.verifier}({p}, stored):",
        f'{b}scheme, _, rest = str(stored).partition("$")',
        f'{b}salt, _, expected = rest.partition("$")',
        f'{b}if scheme != "scrypt" or not salt or not expected:',
        f"{b}    return False",
        f"{b}try:",
        f"{b}    digest = {h}.scrypt({a}, salt=bytes.fromhex(salt), {cost})",
        f"{b}except ValueError:",
        f"{b}    return False",
        f"{b}return hmac.compare_digest(digest.hex(), expected)",
    ]
    original = lines[site.start_line - 1 : site.end_line]
    changes = [_hunk(path, finding.stable_id, site.start_line, original, function)]
    changes += _rewrite_comparisons(path, finding.stable_id, lines, site, "not ")
    if site.imports_needed:
        line, after = python_import_anchor(source, site.start_line)
        anchor = lines[line - 1]
        added = [f"import {module}" for module in sorted(site.imports_needed)]
        if line in {change["start_line"] for change in changes}:
            raise TemplateError("import_anchor_overlaps_repair")
        changes.append(_hunk(path, finding.stable_id, line, [anchor], [anchor, *added] if after else [*added, anchor]))
    return TemplatePatch(
        finding.stable_id, PASSWORD_HASHING, sorted(changes, key=lambda change: change["start_line"]),
        f"{site.function} derives a salted scrypt key instead of a {site.algorithm} digest, and each comparison "
        f"calls {site.verifier}; {PASSWORD_MIGRATION_NOTE}",
    )


# --- cookie flags ---------------------------------------------------------------------------

def _cookie(snapshot: Snapshot, finding: FindingSnapshot, language: str) -> TemplatePatch:
    """HttpOnly, Secure and SameSite=Lax on the options the code already passes, other keys kept.

    Lax rather than Strict, because Strict withholds the cookie on every top-level navigation
    from another site, so a user arriving from a link is signed out; Lax still withholds it from
    the cross-site POSTs and subresource requests CSRF depends on.
    """
    site = cookie_site(snapshot, finding, language)
    if list(site.original) == list(site.replacement):
        raise TemplateError("cookie_flags_already_set")
    path = finding.affected_path
    if site.kind in ("setting", "flask_config"):
        description = f"{site.name} set to True"
    elif language == PYTHON:
        description = 'set_cookie with secure=True, httponly=True and samesite="Lax"'
    else:
        description = f"{site.kind} cookie options with httpOnly: true, secure: true and sameSite: 'lax'"
    return TemplatePatch(
        finding.stable_id, COOKIE_FLAGS,
        [_hunk(path, finding.stable_id, site.start_line, list(site.original), list(site.replacement))],
        description + "; a cookie marked Secure is no longer sent over plain HTTP, so a development server without TLS stops keeping the session",
    )


# --- entry points ---------------------------------------------------------------------------

def generate_template(snapshot: Snapshot, finding: FindingSnapshot, family: str, language: str) -> TemplatePatch | TemplateFallback:
    """The deterministic hunks for one finding, or the reason the model has to write them."""
    path = finding.affected_path
    try:
        if language == WORKFLOW:
            # A workflow has no enclosing scope to resolve, so it is answered before the
            # language branches that look for one.
            return _workflow(snapshot, finding)
        if language == JAVASCRIPT:
            # A secret literal is not inside any function, and neither is a parser a route
            # calls, so both are recognized before the enclosing-scope lookup.
            if family == HARDCODED_CREDENTIAL:
                return _js_credential(snapshot, finding)
            if family == CODE_INJECTION_EVAL:
                return _js_eval(snapshot, finding)
            if family == PASSWORD_HASHING:
                return _js_password(snapshot, finding)
            if family == COOKIE_FLAGS:
                return _cookie(snapshot, finding, JAVASCRIPT)
            if family == COMMAND_ARGUMENTS:
                # The rewrite replaces one call in place, so it needs no enclosing scope.
                return _js_command(snapshot, finding)
            site = js_site_for_line(snapshot.full_content(path), _finding_line(finding))
            if family == SQL_PARAMETERIZATION:
                return _js_sql(snapshot, finding, site)
            if family == PATH_CONTAINMENT:
                return _js_traversal(snapshot, finding, site)
        elif language == PYTHON:
            if family == HARDCODED_CREDENTIAL:
                return _py_credential(snapshot, finding)
            if family == PASSWORD_HASHING:
                return _py_password(snapshot, finding)
            if family == COOKIE_FLAGS:
                return _cookie(snapshot, finding, PYTHON)
            function = python_site_for_line(snapshot.full_content(path), _finding_line(finding))
            if family == SQL_PARAMETERIZATION:
                return _py_sql(snapshot, finding, function)
            if family == CODE_INJECTION_EVAL:
                return _py_eval(snapshot, finding, function)
            if family == COMMAND_ARGUMENTS:
                return _py_command(snapshot, finding, function)
            if family == PATH_CONTAINMENT:
                return _py_traversal(snapshot, finding, function)
    except (SiteError, TemplateError) as exc:
        return TemplateFallback(finding.stable_id, family, getattr(exc, "code", str(exc)))
    except (IndexError, ValueError, StopIteration) as exc:
        return TemplateFallback(finding.stable_id, family, f"template_error:{type(exc).__name__}")
    return TemplateFallback(finding.stable_id, family, "family_not_templated")


def _is_import_insertion(change: dict[str, Any]) -> bool:
    original = list(change["original_lines"])
    replacement = list(change["replacement_lines"])
    added = [line for line in replacement if line not in original]
    return bool(added) and all(line in replacement for line in original) and all(
        re.match(r"^\s*(?:import\s+\S|from\s+\S+\s+import\s+\S|(?:const|let|var)\s+.+?=\s*require\()", line) for line in added
    )


def combine_templates(patches: list[TemplatePatch]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """One change list for a group: identical hunks deduplicated, import insertions on one anchor
    merged, and a finding whose hunks would overlap another's dropped with the reason."""
    combined: list[dict[str, Any]] = []
    dropped: dict[str, str] = {}
    for patch in patches:
        staged: list[dict[str, Any]] = []
        merges: list[tuple[int, dict[str, Any]]] = []
        conflict = None
        for change in patch.changes:
            start = int(change["start_line"])
            end = start + len(change["original_lines"]) - 1
            match = None
            for index, existing in enumerate(combined):
                if existing["path"] != change["path"]:
                    continue
                existing_end = int(existing["start_line"]) + len(existing["original_lines"]) - 1
                if start > existing_end or end < int(existing["start_line"]):
                    continue
                match = (index, existing)
                break
            if match is None:
                staged.append(change)
                continue
            index, existing = match
            if existing["start_line"] == change["start_line"] and existing["original_lines"] == change["original_lines"]:
                if existing["replacement_lines"] == change["replacement_lines"]:
                    continue
                if _is_import_insertion(existing) and _is_import_insertion(change):
                    merged = dict(existing)
                    extra = [line for line in change["replacement_lines"] if line not in existing["replacement_lines"]]
                    anchor_index = next((i for i, line in enumerate(existing["replacement_lines"]) if line in existing["original_lines"]), None)
                    lines = list(existing["replacement_lines"])
                    if anchor_index is not None and existing["replacement_lines"][0] in existing["original_lines"]:
                        lines = lines + extra
                    else:
                        lines = extra + lines
                    merged["replacement_lines"] = lines
                    merges.append((index, merged))
                    continue
            conflict = f"template_conflict_with_{existing['finding_id']}"
            break
        if conflict:
            dropped[patch.finding_id] = conflict
            continue
        for index, merged in merges:
            combined[index] = merged
        combined.extend(staged)
    return combined, dropped
