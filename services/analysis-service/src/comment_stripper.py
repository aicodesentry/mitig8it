"""Comment and string awareness for the tier 1 regex pass.

Tier 1 is a line-oriented regex pass with no parser, so before this module it read a
JSDoc block, a `//` note and a Python docstring as if they were code. The September 2026
real-repository replay found six of thirty hand-read findings on text that never
executes, two of them at `high`:

* `* Calling \\`pool.destroy()\\` on the connection from here does not throw` (JSDoc)
* ` *    res.location('../login');` (a usage example in a JSDoc block)
* `// Replaced by Sequelize's global option`

The stripper classifies every character of a line as code, comment, string delimiter or
string body, then blanks the classes a rule must not see. Blanking, rather than deleting,
keeps both the line count and the column offsets, so a finding still reports the line
number and the original text the reviewer will see on GitHub.

Two deliberate limits:

* **Conservative when unsure.** An unrecognised file extension is not stripped at all, and
  a block comment that opened outside the visible hunk is not treated as a comment unless
  the JSDoc continuation heuristic below recognises it. Leaving text in can only keep a
  finding that the pass made before; taking text out could hide a real one.
* **Per hunk, not per file.** Tier 1 sees a diff, not a file, so the scanner state
  (open block comment, open docstring) is reset at every hunk boundary. A comment that
  spans a hunk boundary is therefore only partly recognised.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

CODE = "c"
COMMENT = "m"
STRING_BODY = "s"
STRING_QUOTE = "q"


@dataclass(frozen=True)
class LanguageSyntax:
    name: str
    line_comments: Tuple[str, ...] = ()
    block_comment: Optional[Tuple[str, str]] = None
    quotes: Tuple[str, ...] = ()
    # Quotes that legally span a newline (JS template literals, Go raw strings).
    multiline_quotes: Tuple[str, ...] = ()
    triple_quotes: Tuple[str, ...] = ()
    # Ruby's `=begin` / `=end`, which are only comments at column zero.
    line_block_comment: Optional[Tuple[str, str]] = None
    # `\` escapes the next character inside a string literal.
    escape_in_strings: bool = True
    # A line whose first non-space character is `*` is a block-comment continuation.
    # True only where a statement can never start with `*`, which rules out C and C++.
    star_continuation: bool = False


_C_STYLE_QUOTES = ("\"", "'")

JAVASCRIPT = LanguageSyntax(
    name="javascript",
    line_comments=("//",),
    block_comment=("/*", "*/"),
    quotes=("\"", "'", "`"),
    multiline_quotes=("`",),
    star_continuation=True,
)
GO = LanguageSyntax(
    name="go",
    line_comments=("//",),
    block_comment=("/*", "*/"),
    quotes=("\"", "'", "`"),
    multiline_quotes=("`",),
    star_continuation=True,
)
JAVA = LanguageSyntax(
    name="java",
    line_comments=("//",),
    block_comment=("/*", "*/"),
    quotes=_C_STYLE_QUOTES,
    star_continuation=True,
)
CSHARP = LanguageSyntax(
    name="csharp",
    line_comments=("//",),
    block_comment=("/*", "*/"),
    quotes=_C_STYLE_QUOTES,
    star_continuation=True,
)
PHP = LanguageSyntax(
    name="php",
    line_comments=("//", "#"),
    block_comment=("/*", "*/"),
    quotes=_C_STYLE_QUOTES,
    star_continuation=True,
)
RUBY = LanguageSyntax(
    name="ruby",
    line_comments=("#",),
    quotes=_C_STYLE_QUOTES,
    line_block_comment=("=begin", "=end"),
)
PYTHON = LanguageSyntax(
    name="python",
    line_comments=("#",),
    quotes=_C_STYLE_QUOTES,
    triple_quotes=("\"\"\"", "'''"),
)

LANGUAGE_BY_EXTENSION: Dict[str, LanguageSyntax] = {
    "js": JAVASCRIPT,
    "jsx": JAVASCRIPT,
    "mjs": JAVASCRIPT,
    "cjs": JAVASCRIPT,
    "ts": JAVASCRIPT,
    "tsx": JAVASCRIPT,
    "mts": JAVASCRIPT,
    "cts": JAVASCRIPT,
    "go": GO,
    "java": JAVA,
    "cs": CSHARP,
    "php": PHP,
    "rb": RUBY,
    "rake": RUBY,
    "py": PYTHON,
    "pyi": PYTHON,
}


def language_for_path(path: Any) -> Optional[LanguageSyntax]:
    """The syntax to use for `path`, or None when the extension is not one we model.

    None means "leave every character alone": an unmodelled language is never stripped.
    """
    text = str(path or "").replace("\\", "/")
    name = text.rsplit("/", 1)[-1]
    if "." not in name:
        return None
    return LANGUAGE_BY_EXTENSION.get(name.rsplit(".", 1)[-1].lower())


class _ScanState:
    """Scanner state that survives from one line to the next inside one hunk."""

    __slots__ = ("block", "triple", "triple_is_docstring", "multiline_quote", "line_block")

    def __init__(self) -> None:
        self.block = False
        self.triple: Optional[str] = None
        self.triple_is_docstring = False
        self.multiline_quote: Optional[str] = None
        self.line_block = False


def _mark(marks: List[str], start: int, end: int, kind: str) -> None:
    for index in range(start, min(end, len(marks))):
        marks[index] = kind


def _scan_quoted(line: str, start: int, quote: str, syntax: LanguageSyntax, marks: List[str]) -> Tuple[int, bool]:
    """Classify a quoted run beginning at `start`. Returns (next index, still open)."""
    marks[start] = STRING_QUOTE
    index = start + len(quote)
    # A Go raw string (backtick) has no escape sequences; every other literal does.
    escapes = syntax.escape_in_strings and not (quote == "`" and syntax.name == "go")
    while index < len(line):
        char = line[index]
        if escapes and char == "\\":
            marks[index] = STRING_BODY
            if index + 1 < len(line):
                marks[index + 1] = STRING_BODY
            index += 2
            continue
        if line.startswith(quote, index):
            _mark(marks, index, index + len(quote), STRING_QUOTE)
            return index + len(quote), False
        marks[index] = STRING_BODY
        index += 1
    return len(line), True


def _classify_line(line: str, syntax: LanguageSyntax, state: _ScanState) -> str:
    marks = [CODE] * len(line)

    if syntax.line_block_comment is not None:
        opener, closer = syntax.line_block_comment
        if state.line_block:
            if line.startswith(closer):
                state.line_block = False
            return COMMENT * len(line)
        if line.startswith(opener):
            state.line_block = True
            return COMMENT * len(line)

    index = 0
    # A block comment that is still open from an earlier line in the same hunk.
    if state.block and syntax.block_comment is not None:
        closer = syntax.block_comment[1]
        position = line.find(closer)
        if position == -1:
            return COMMENT * len(line)
        _mark(marks, 0, position + len(closer), COMMENT)
        state.block = False
        index = position + len(closer)
    elif state.triple is not None:
        delimiter = state.triple
        body_kind = COMMENT if state.triple_is_docstring else STRING_BODY
        quote_kind = COMMENT if state.triple_is_docstring else STRING_QUOTE
        position = line.find(delimiter)
        if position == -1:
            return body_kind * len(line)
        _mark(marks, 0, position, body_kind)
        _mark(marks, position, position + len(delimiter), quote_kind)
        state.triple = None
        state.triple_is_docstring = False
        index = position + len(delimiter)
    elif state.multiline_quote is not None:
        quote = state.multiline_quote
        position = line.find(quote)
        if position == -1:
            return STRING_BODY * len(line)
        _mark(marks, 0, position, STRING_BODY)
        _mark(marks, position, position + len(quote), STRING_QUOTE)
        state.multiline_quote = None
        index = position + len(quote)
    elif syntax.star_continuation and _looks_like_block_comment_continuation(line):
        # The opening `/**` sits above the hunk we were handed. A line that begins with
        # `*` is not a statement in any language that sets this flag, so reading it as a
        # comment continuation is safe; this is what catches the JSDoc examples the
        # replay found (` *    res.location('../login');`).
        if line.lstrip().startswith("*/"):
            stripped_index = len(line) - len(line.lstrip())
            _mark(marks, 0, stripped_index + 2, COMMENT)
            index = stripped_index + 2
        else:
            return COMMENT * len(line)

    while index < len(line):
        matched_line_comment = False
        for token in syntax.line_comments:
            if line.startswith(token, index):
                _mark(marks, index, len(line), COMMENT)
                matched_line_comment = True
                break
        if matched_line_comment:
            break

        if syntax.block_comment is not None and line.startswith(syntax.block_comment[0], index):
            opener, closer = syntax.block_comment
            position = line.find(closer, index + len(opener))
            if position == -1:
                _mark(marks, index, len(line), COMMENT)
                state.block = True
                break
            _mark(marks, index, position + len(closer), COMMENT)
            index = position + len(closer)
            continue

        matched_triple = False
        for delimiter in syntax.triple_quotes:
            if line.startswith(delimiter, index):
                # A triple-quoted literal is a docstring only when nothing precedes it on
                # the line. `sql = """SELECT ..."""` is a value the rules must still see;
                # a bare `"""..."""` opening a module, class or function is prose.
                is_docstring = not line[:index].strip()
                body_kind = COMMENT if is_docstring else STRING_BODY
                quote_kind = COMMENT if is_docstring else STRING_QUOTE
                _mark(marks, index, index + len(delimiter), quote_kind)
                position = line.find(delimiter, index + len(delimiter))
                if position == -1:
                    _mark(marks, index + len(delimiter), len(line), body_kind)
                    state.triple = delimiter
                    state.triple_is_docstring = is_docstring
                    index = len(line)
                else:
                    _mark(marks, index + len(delimiter), position, body_kind)
                    _mark(marks, position, position + len(delimiter), quote_kind)
                    index = position + len(delimiter)
                matched_triple = True
                break
        if matched_triple:
            continue

        char = line[index]
        if char in syntax.quotes:
            index, still_open = _scan_quoted(line, index, char, syntax, marks)
            if still_open and char in syntax.multiline_quotes:
                state.multiline_quote = char
            continue

        index += 1

    return "".join(marks)


def _looks_like_block_comment_continuation(line: str) -> bool:
    stripped = line.lstrip()
    if not stripped.startswith("*"):
        return False
    if stripped.startswith("*/"):
        return True
    rest = stripped[1:]
    # `*foo` could be a dereference or a glob; `* foo`, `**` and a bare `*` could not.
    return rest == "" or rest[0].isspace() or rest[0] == "*"


def classify_lines(lines: Sequence[str], syntax: LanguageSyntax) -> List[str]:
    """Per-character classification for each line, scanned in order as one hunk."""
    state = _ScanState()
    return [_classify_line(str(line or ""), syntax, state) for line in lines]


def _blank(line: str, marks: str, kinds: Sequence[str]) -> str:
    if not marks:
        return line
    return "".join(
        " " if mark in kinds else char
        for char, mark in zip(line, marks)
    )


def strip_lines(
    lines: Sequence[str],
    path: Any,
    *,
    blank_strings: bool = False,
) -> List[str]:
    """Blank comments (and optionally string bodies) across `lines`, keeping positions.

    `lines` must be one hunk in file order. An unmodelled extension returns the lines
    unchanged.
    """
    syntax = language_for_path(path)
    text_lines = [str(line or "") for line in lines]
    if syntax is None:
        return text_lines

    kinds = (COMMENT, STRING_BODY) if blank_strings else (COMMENT,)
    marks = classify_lines(text_lines, syntax)
    return [_blank(line, mark, kinds) for line, mark in zip(text_lines, marks)]
