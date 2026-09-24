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
    HARDCODED_CREDENTIAL,
    JAVASCRIPT,
    PATH_CONTAINMENT,
    PYTHON,
    SQL_PARAMETERIZATION,
)
from .gates import PYTHON_SQL_DRIVERS, python_imports
from .models import FindingSnapshot
from .retrieval import Snapshot
from .sites import (
    JS_EVAL_ARGUMENT_RE,
    JsFunction,
    JsRoute,
    PyFunction,
    SiteError,
    js_bound_names,
    js_environment_name,
    js_eval_site,
    js_literal_assignment,
    js_literal_assignment_in_span,
    js_names_in,
    js_require_line,
    js_site_for_line,
    scope_lines_near,
    python_function_for_line,
    python_import_anchor,
    python_module_assignment,
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
_JS_JOIN_RE = re.compile(r"path\.join\(\s*(?P<base>[^,()]+?)\s*,\s*(?P<input>[^()]+?)\s*\)")


def _js_sql(snapshot: Snapshot, finding: FindingSnapshot, site: JsRoute | JsFunction) -> TemplatePatch:
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


def _js_rejection(site: JsRoute | JsFunction) -> str:
    """The statement that refuses a path escaping the base directory.

    A route handler owns the response, so it answers 400, which is the contract it already has.
    A plain function has no response to write, so it throws: the one behaviour a caller cannot
    mistake for a valid path, where returning a sentinel would be read as one.
    """
    if isinstance(site, JsRoute):
        return f"return {site.res}.status(400).end();"
    return f"throw new Error({js_string_literal(PATH_ESCAPE_MESSAGE)});"


def _js_containment_summary(site: JsRoute | JsFunction) -> str:
    tail = "answers 400" if isinstance(site, JsRoute) else "throws"
    return f"path.resolve with a containment check that {tail} before any read"


def _js_traversal(snapshot: Snapshot, finding: FindingSnapshot, site: JsRoute | JsFunction) -> TemplatePatch:
    """A `path.join` of untrusted input becomes a resolve plus a containment check.

    The check is the same wherever the join is; only how it refuses differs, which is what
    `_js_rejection` decides from the site.
    """
    path = finding.affected_path
    source = snapshot.full_content(path)
    lines = source.splitlines()
    line = _finding_line(finding)
    if js_require_line(source, "path") is None:
        raise TemplateError("path_module_not_required")
    rejection = _js_rejection(site)
    join_line = None
    for number in scope_lines_near(site.start_line, site.end_line, line):
        found = _JS_JOIN_RE.search(lines[number - 1])
        if found:
            join_line = number
            break
    if join_line is None:
        raise TemplateError("path_join_not_found_in_scope")
    text = lines[join_line - 1]
    found = _JS_JOIN_RE.search(text)
    base, user_input = found.group("base"), found.group("input")
    indent = text[: len(text) - len(text.lstrip())]
    taken = js_names_in(lines[site.start_line - 1 : site.end_line])
    base_name = next(name for name in ("baseDir", "containedBase", "resolvedBase") if name not in taken)
    assignment = _assignment(text)
    if assignment and assignment[2].strip() == found.group(0):
        target = assignment[1]
        tail: list[str] = []
    else:
        target = next(name for name in ("target", "safeTarget", "resolvedTarget") if name not in taken)
        tail = [text.replace(found.group(0), target, 1)]
    head = [
        f"{indent}const {base_name} = path.resolve({base});",
        f"{indent}const {target} = path.resolve({base_name}, String({user_input}));",
        f"{indent}if ({target} !== {base_name} && !{target}.startsWith({base_name} + path.sep)) {rejection}",
    ]
    last = max(join_line, line)
    original = lines[join_line - 1 : last]
    replacement = head + tail + lines[join_line:last]
    return TemplatePatch(finding.stable_id, PATH_CONTAINMENT, [_hunk(path, finding.stable_id, join_line, original, replacement)], _js_containment_summary(site))


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


# --- entry points ---------------------------------------------------------------------------

def generate_template(snapshot: Snapshot, finding: FindingSnapshot, family: str, language: str) -> TemplatePatch | TemplateFallback:
    """The deterministic hunks for one finding, or the reason the model has to write them."""
    path = finding.affected_path
    try:
        if language == JAVASCRIPT:
            # A secret literal is not inside any function, and neither is a parser a route
            # calls, so both are recognized before the enclosing-scope lookup.
            if family == HARDCODED_CREDENTIAL:
                return _js_credential(snapshot, finding)
            if family == CODE_INJECTION_EVAL:
                return _js_eval(snapshot, finding)
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
            function = python_function_for_line(snapshot.full_content(path), _finding_line(finding))
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
