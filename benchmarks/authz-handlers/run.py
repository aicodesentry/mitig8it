#!/usr/bin/env python3
"""Can a model reading a whole route handler see a missing authorization check?

The vulnerable corpus (benchmarks/vulnerable-corpus) labels lines, and a broken
authorization check or an IDOR has no line: the defect is the absence of a check. This
runner gives a model one route handler at a time, with its surrounding context, its route
registration line and a short grep-based summary of how the repository does authentication,
and asks for a verdict with a quote from the handler as evidence. The quote is checked
against the source; an answer whose quote is not in the handler is rejected.

Scoring over the labelled set in cases.json:

* precision = vulnerable verdicts on labelled-vulnerable handlers / all vulnerable verdicts
* recall    = vulnerable verdicts on labelled-vulnerable handlers / all labelled-vulnerable
* `uncertain`, rejected and failed answers count as not-vulnerable for precision and as a
  miss for recall, with Wilson 95 percent intervals on both.

The model is reached through services/analysis-service/src/llm_client.py (`call_llm`), so
the provider, key and model come from the same environment variables the service uses
(LLM_PROVIDER, OPENAI_API_KEY, GEMINI_API_KEY, LLM_MODEL). Nothing here reads a key from
anywhere else, and no key is ever printed.

Runs are deterministic (temperature 0, cases in id order, one fixed prompt), cached (one
file per model and prompt and case under .cache/), resumable (the report is rewritten
after every case and rows for the same fixture, prompt and model are kept) and bounded by
--max-cost, which stops the run before a request that would take the estimated spend past
the budget.

    PY=~/.pyenv/versions/3.11.6/bin/python
    $PY -I benchmarks/authz-handlers/run.py --trees <dir outside the repo> --fetch
    $PY -I benchmarks/authz-handlers/run.py --trees <dir with the fetched snapshots> --dry-run
    $PY -I benchmarks/authz-handlers/run.py --trees <dir> --input-price 0.15 --output-price 0.6 --max-cost 1.0

The fetched source trees are untrusted data: this script reads them as text and never
imports or executes anything from them. The snapshot cache layout is the one
scripts/replay/corpus.py produces (<trees>/<owner>__<repo>/<ref>/<single extracted dir>).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SERVICE_SRC = ROOT / "services" / "analysis-service" / "src"

VERDICTS = ("vulnerable", "safe", "uncertain")
CONTROLS = ("ownership_check", "role_check", "none")
NOT_VULNERABLE = ("safe", "uncertain", "rejected", "error")

CONTEXT_LINES = 20  # before and after the handler: 40 lines of context at most
SOURCE_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".py"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "coverage", "__pycache__", ".cache"}
MAX_SOURCE_BYTES = 2_000_000
AUTH_GREP_TERMS = ("passport", "isAuthenticated", "login_required", "@permission_required")
# A quote shorter than this (a lone brace, `res`) is in every handler and proves nothing.
MIN_EVIDENCE_CHARS = 12
REGISTRATION_NOISE = {
    "app", "router", "get", "post", "put", "patch", "delete", "use", "all", "path", "views", "name",
    "utils", "asyncHandler", "require", "function", "req", "res", "next", "return",
}

# Comments and calls through which a teaching application names its own vulnerability. They
# are removed from what the model sees, so the measurement is of code reading, not of
# comment reading. The count of removals is recorded per case.
HINT_WORDS_RE = re.compile(
    r"fix for|insecur|vulnerab|idor|access control|no checking|challenge|secure way|\bA[1-9]\b|\bA10\b",
    re.IGNORECASE,
)
HINT_IMPORT_RE = re.compile(r"^[ \t]*import .*(challengeUtils|datacache).*$", re.MULTILINE)
ROUTE_NAME_KWARG_RE = re.compile(r",\s*name\s*=\s*(['\"]).*?\1")
USE_PREFIX_RE = re.compile(r"\.use\(\s*(['\"])([^'\"]+)\1")
FIRST_STRING_RE = re.compile(r"(['\"])([^'\"]+)\1")
TRAILING_MARKER_RE = re.compile(r"\s*//\s*vuln-code-snippet.*$", re.MULTILINE)
LINE_COMMENT_RE = re.compile(r"^\s*(//|#).*$")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
CHALLENGE_CALL_RE = re.compile(r"challengeUtils\.(solveIf|solve)\(")

SYSTEM_PROMPT = """You are reviewing one HTTP route handler for a missing authorization decision.

You are shown: a short summary of how the repository authenticates requests (middleware names found by grep and the definitions of the middleware named on this route), the line that registers the route, up to 20 lines of code before and after the handler, and the handler itself.

Decide whether the handler, together with the middleware on its registration line, makes the authorization decision it needs:
- ownership_check: the handler reads or writes a record that belongs to a user, and the record is selected or filtered by a client-controlled value (URL parameter, body field, query string, cookie, header) that is never compared to the authenticated identity. A value that a middleware on the registration line sets from the verified session or token (for example a UserId appended from the token) counts as the authenticated identity, not as client input.
- role_check: the handler performs a privileged or administrative action, or returns data about users other than the caller, and neither the handler nor the registration line checks the caller's role. A role taken from a cookie, a header or any other client-controlled value is not a role check.
- none: the control is present, or the handler touches nothing that needs one.

Authentication alone (the caller is logged in) is not authorization. Other defect classes (injection, eval, XSS, weak regex, hardcoded credentials) are out of scope: do not report them and do not let them change your verdict.

Answer with one JSON object and nothing else:
{"verdict": "vulnerable" | "safe" | "uncertain",
 "missing_control": "ownership_check" | "role_check" | "none",
 "evidence": "<a short verbatim quote copied from the handler source shown, the line that selects the record or performs the action>",
 "reasoning": "<two sentences at most>"}

Rules: verdict "vulnerable" requires missing_control other than "none"; verdict "safe" requires "none". "evidence" must be copied exactly from the handler block, not from the context or the registration line. Say "uncertain" when the handler's inputs or the middleware semantics are not visible."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def save(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        temporary = Path(stream.name)
    temporary.replace(path)


# ----------------------------------------------------------------------------- snapshots

def snapshot_root(trees: Path, repo: str, ref: str) -> Path:
    """The extracted tree for (repo, ref) in the scripts/replay/corpus.py cache layout."""
    target = trees / repo.replace("/", "__") / ref
    if not target.is_dir():
        raise FileNotFoundError(
            f"no snapshot for {repo}@{ref} under {trees}; fetch it with scripts/replay/corpus.py "
            f"(see benchmarks/vulnerable-corpus/README.md) into a directory outside the repository"
        )
    children = [child for child in target.iterdir() if child.is_dir()]
    if len(children) != 1:
        raise FileNotFoundError(f"expected one extracted directory under {target}, found {len(children)}")
    return children[0]


def _snapshot_cache(trees: Path):
    replay = str(ROOT / "scripts" / "replay")
    if replay not in sys.path:
        sys.path.insert(0, replay)
    from corpus import SnapshotCache  # the replay harness's pinned, path-checked downloader

    return SnapshotCache(trees)


def fetch_trees(suite: dict, trees: Path, cache_factory=_snapshot_cache) -> list[str]:
    """Download every (repo, ref) the cases name into `trees`, which must be outside the
    repository. Extraction is scripts/replay/corpus.py's, which refuses a member whose path
    escapes the extraction root; nothing fetched is imported or run."""
    resolved = trees.resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise SystemExit(f"--trees must be outside the repository, got {trees}")
    cache = cache_factory(trees)
    pairs = sorted({(case["repo"], case["ref"]) for case in suite["cases"]})
    return [str(cache.tree(repo, ref)) for repo, ref in pairs]


def iter_source_files(tree: Path):
    for path in sorted(tree.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(tree).parts):
            continue
        if path.is_file() and path.suffix in SOURCE_SUFFIXES and path.stat().st_size <= MAX_SOURCE_BYTES:
            yield path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


# ------------------------------------------------------------------------------ redaction

def _remove_balanced_calls(text: str) -> tuple[str, int]:
    """Remove `challengeUtils.solveIf(...)` / `challengeUtils.solve(...)` statements, however many
    lines they span, by counting parentheses from the opening one."""
    removed = 0
    while True:
        match = CHALLENGE_CALL_RE.search(text)
        if not match:
            return text, removed
        depth, index = 0, match.end() - 1
        while index < len(text):
            char = text[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        end = index + 1
        # Drop the rest of the line when the call was the whole statement.
        line_end = text.find("\n", end)
        line_end = len(text) if line_end == -1 else line_end
        line_start = text.rfind("\n", 0, match.start()) + 1
        before = text[line_start:match.start()]
        after = text[end:line_end]
        if before.strip() == "" and (after.strip() == "" or after.strip().startswith("//")):
            text = text[:line_start] + text[line_end + 1:]
        else:
            text = text[:match.start()] + text[end:]
        removed += 1


def redact_hints(text: str) -> tuple[str, int]:
    """Strip the ways a teaching application labels its own vulnerability in the source.

    Returns the redacted text and how many removals were made, so a case whose handler
    carried hints can be told apart from one that did not.
    """
    removed = 0
    text, count = _remove_balanced_calls(text)
    removed += count

    def drop_block(match: re.Match) -> str:
        nonlocal removed
        if HINT_WORDS_RE.search(match.group(0)):
            removed += 1
            return ""
        return match.group(0)

    text = BLOCK_COMMENT_RE.sub(drop_block, text)
    text, count = TRAILING_MARKER_RE.subn("", text)
    removed += count
    text, count = HINT_IMPORT_RE.subn("", text)
    removed += count
    kept = []
    for line in text.split("\n"):
        if LINE_COMMENT_RE.match(line) and HINT_WORDS_RE.search(line):
            removed += 1
            continue
        kept.append(line)
    text = "\n".join(kept)
    # Collapse the blank runs that removals leave behind.
    text = re.sub(r"\n[ \t]*\n([ \t]*\n)+", "\n\n", text)
    return text, removed


# ----------------------------------------------------------------------------- extraction

def extract_handler(tree: Path, case: dict, context_lines: int = CONTEXT_LINES) -> dict:
    """The handler block, up to `context_lines` lines on each side, and the registration line."""
    path = tree / case["path"]
    lines = read_text(path).split("\n")
    start, end = case["line_range"]
    if not (1 <= start <= end <= len(lines)):
        raise ValueError(f"{case['id']}: line_range {case['line_range']} is outside {case['path']} ({len(lines)} lines)")
    handler_raw = "\n".join(lines[start - 1:end])
    before_raw = "\n".join(lines[max(0, start - 1 - context_lines):start - 1])
    after_raw = "\n".join(lines[end:end + context_lines])
    handler, redacted = redact_hints(handler_raw)
    before, count = redact_hints(before_raw)
    redacted += count
    after, count = redact_hints(after_raw)
    redacted += count
    registration = find_registration(tree, case.get("registration"))
    return {
        "path": case["path"],
        "handler_name": case.get("handler"),
        "line_range": [start, end],
        "handler": handler,
        "context_before": before,
        "context_after": after,
        "registration": registration,
        "redactions": redacted,
    }


def find_registration(tree: Path, spec: dict | None) -> dict | None:
    if not spec:
        return None
    path = tree / spec["path"]
    if not path.is_file():
        return None
    lines = read_text(path).split("\n")
    for number, line in enumerate(lines, start=1):
        if spec["pattern"] in line:
            text, _ = redact_hints(line)
            # A Django route's name= kwarg is documentation, not code the request passes through.
            text = ROUTE_NAME_KWARG_RE.sub("", text).strip()
            return {"path": spec["path"], "line": number, "text": text,
                    "path_middleware": find_path_middleware(lines, text)}
    return None


def _segments_match(prefix: str, route: str) -> bool:
    """Express `app.use(prefix)` applies to every request whose path starts with prefix, so a
    prefix matches a route when each of its segments equals the route's or is a parameter."""
    prefix_parts = [part for part in prefix.strip("/").split("/") if part]
    route_parts = [part for part in route.strip("/").split("/") if part]
    if len(prefix_parts) > len(route_parts):
        return False
    return all(p == r or p.startswith(":") or r.startswith(":") for p, r in zip(prefix_parts, route_parts))


def find_path_middleware(lines: list[str], registration_text: str) -> list[dict]:
    """`app.use(prefix, ...)` lines in the registration file whose prefix covers this route."""
    route = FIRST_STRING_RE.search(registration_text)
    if not route or not route.group(2).startswith("/"):
        return []
    found = []
    for number, line in enumerate(lines, start=1):
        match = USE_PREFIX_RE.search(line)
        if match and _segments_match(match.group(2), route.group(2)):
            text, _ = redact_hints(line)
            found.append({"line": number, "text": text.strip()})
    return found


def registration_names(registration: dict | None, handler_name: str | None) -> list[str]:
    """Identifiers on the registration line, and on the path-scoped middleware lines that cover
    it, that could be middleware: not the handler, not a framework verb, not a module
    qualifier (`security` in `security.appendUserId()`), not a string."""
    if not registration:
        return []
    names = []
    texts = [registration["text"]] + [m["text"] for m in registration.get("path_middleware", [])]
    for text in texts:
        text = re.sub(r"(['\"]).*?\1", "", text)
        for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)(\s*\.)?", text):
            token, qualifier = match.group(1), match.group(2)
            if qualifier or token in REGISTRATION_NOISE or token == handler_name or token in names:
                continue
            names.append(token)
    return names


DEFINITION_TEMPLATE = (
    r"^[ \t]*(?:export\s+)?(?:const|let|var)\s+{name}\s*=|"
    r"^[ \t]*(?:export\s+)?(?:async\s+)?function\s+{name}\b|"
    r"^[ \t]*def\s+{name}\b|"
    r"^[ \t]*(?:module\.)?exports\.{name}\s*=|"
    r"^[ \t]*this\.{name}\s*="
)


def find_definition(tree: Path, name: str, max_lines: int = 12) -> dict | None:
    pattern = re.compile(DEFINITION_TEMPLATE.format(name=re.escape(name)), re.MULTILINE)
    for path in iter_source_files(tree):
        text = read_text(path)
        match = pattern.search(text)
        if not match:
            continue
        lines = text.split("\n")
        line_number = text.count("\n", 0, match.start()) + 1
        snippet, _ = redact_hints("\n".join(lines[line_number - 1:line_number - 1 + max_lines]))
        return {"name": name, "path": str(path.relative_to(tree)), "line": line_number, "text": snippet}
    return None


def auth_summary(tree: Path, registration: dict | None, handler_name: str | None,
                 grep_cache: dict | None = None) -> dict:
    """What a simple grep knows about authentication in this repository, plus the definition of
    every middleware named on the route's registration line."""
    key = str(tree)
    if grep_cache is not None and key in grep_cache:
        counts = grep_cache[key]
    else:
        counts = {term: {"files": 0, "occurrences": 0} for term in AUTH_GREP_TERMS}
        for path in iter_source_files(tree):
            text = read_text(path)
            for term in AUTH_GREP_TERMS:
                hits = text.count(term)
                if hits:
                    counts[term]["files"] += 1
                    counts[term]["occurrences"] += hits
        if grep_cache is not None:
            grep_cache[key] = counts
    middleware = []
    for name in registration_names(registration, handler_name):
        definition = find_definition(tree, name)
        if definition:
            middleware.append(definition)
    return {"grep": counts, "middleware": middleware}


# --------------------------------------------------------------------------------- prompt

def language_of(path: str) -> str:
    suffix = Path(path).suffix
    return {".py": "Python", ".ts": "TypeScript", ".js": "JavaScript", ".cjs": "JavaScript", ".mjs": "JavaScript"}.get(suffix, "unknown")


def build_user_prompt(case: dict, extraction: dict, summary: dict) -> str:
    grep_lines = [f"- `{term}`: {c['occurrences']} occurrences in {c['files']} files"
                  for term, c in summary["grep"].items() if c["occurrences"]] or ["- none of the grep terms were found"]
    middleware = summary["middleware"]
    middleware_text = "\n\n".join(
        f"`{m['name']}` ({m['path']}:{m['line']}):\n```\n{m['text']}\n```" for m in middleware
    ) or "(no middleware named on the registration line could be resolved to a definition)"
    registration = extraction["registration"]
    registration_text = (f"{registration['path']}:{registration['line']}\n```\n{registration['text']}\n```"
                         if registration else "(registration line not found)")
    if registration and registration.get("path_middleware"):
        covering = "\n".join(f"{registration['path']}:{m['line']}  {m['text']}" for m in registration["path_middleware"])
        registration_text += f"\n\nPath-scoped middleware in the same file that also runs for this route:\n```\n{covering}\n```"
    start, end = extraction["line_range"]
    return f"""Repository: {case['repo']} (language: {language_of(case['path'])})
File: {case['path']}, handler `{extraction.get('handler_name') or ''}` at lines {start}-{end}

## Authentication in this repository (grep)
{chr(10).join(grep_lines)}

## Middleware named on the registration line
{middleware_text}

## Route registration
{registration_text}

## Context before the handler
```
{extraction['context_before']}
```

## Handler (quote your evidence from this block only)
```
{extraction['handler']}
```

## Context after the handler
```
{extraction['context_after']}
```"""


# -------------------------------------------------------------------------------- parsing

def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_response(text: str, handler_source: str) -> tuple[dict | None, str | None]:
    """Strict parse: the schema, the enums, the verdict/control agreement and the quote.

    Returns (record, None) or (None, rejection_reason). A quote that is not in the handler
    is a rejection: the model is not allowed to be right for a reason it cannot point at.
    """
    try:
        data = json.loads(_strip_fences(text))
    except (json.JSONDecodeError, TypeError):
        return None, "not_json"
    if not isinstance(data, dict):
        return None, "not_object"
    missing = [key for key in ("verdict", "missing_control", "evidence", "reasoning") if key not in data]
    if missing:
        return None, "missing_fields:" + ",".join(missing)
    verdict, control, evidence = data["verdict"], data["missing_control"], data["evidence"]
    if verdict not in VERDICTS:
        return None, "bad_verdict"
    if control not in CONTROLS:
        return None, "bad_missing_control"
    if verdict == "vulnerable" and control == "none":
        return None, "vulnerable_without_control"
    if verdict == "safe" and control != "none":
        return None, "safe_with_control"
    if not isinstance(evidence, str) or not evidence.strip():
        return None, "empty_evidence"
    if len(_normalize(evidence)) < MIN_EVIDENCE_CHARS:
        return None, "evidence_too_short"
    if _normalize(evidence) not in _normalize(handler_source):
        return None, "evidence_not_in_handler"
    return {
        "verdict": verdict,
        "missing_control": control,
        "evidence": evidence.strip(),
        "reasoning": str(data["reasoning"])[:600],
    }, None


# -------------------------------------------------------------------------------- scoring

def wilson(successes: int, total: int, z: float = 1.959964) -> dict | None:
    """Wilson score interval for a binomial proportion; None when there is nothing to divide by."""
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return {"point": round(p, 4), "low": round(max(0.0, centre - half), 4), "high": round(min(1.0, centre + half), 4),
            "successes": successes, "total": total}


def classify(label: str, observed: str) -> str:
    """Confusion cell. `uncertain`, `rejected` and `error` are not-vulnerable verdicts."""
    predicted_vulnerable = observed == "vulnerable"
    if label == "vulnerable":
        return "tp" if predicted_vulnerable else "fn"
    return "fp" if predicted_vulnerable else "tn"


def score(rows: list[dict]) -> dict:
    cells = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    control_agreement = {"agree": 0, "total": 0}
    outcomes: dict[str, int] = {}
    for row in rows:
        observed = row.get("observed") or "error"
        outcomes[observed] = outcomes.get(observed, 0) + 1
        cell = classify(row["label"], observed)
        cells[cell] += 1
        if cell == "tp":
            control_agreement["total"] += 1
            control_agreement["agree"] += int(row.get("observed_missing_control") == row["label_missing_control"])
    tp, fp, fn = cells["tp"], cells["fp"], cells["fn"]
    return {
        "cases": len(rows),
        "labelled_vulnerable": tp + fn,
        "labelled_safe": cells["fp"] + cells["tn"],
        "confusion": cells,
        "outcomes": outcomes,
        "precision": wilson(tp, tp + fp),
        "recall": wilson(tp, tp + fn),
        "missing_control_agreement_on_true_positives": control_agreement,
    }


# -------------------------------------------------------------------------------- provider

def _service_call_llm(**kwargs):
    if str(SERVICE_SRC) not in sys.path:
        sys.path.insert(0, str(SERVICE_SRC))
    import llm_client  # noqa: WPS433  (the service's own provider adapter)

    return llm_client.call_llm(**kwargs)


PROVIDER = _service_call_llm  # tests replace this with a fake


def provider_configured() -> bool:
    if str(SERVICE_SRC) not in sys.path:
        sys.path.insert(0, str(SERVICE_SRC))
    import llm_client

    return llm_client.is_llm_configured()


def provider_model_name() -> str:
    if str(SERVICE_SRC) not in sys.path:
        sys.path.insert(0, str(SERVICE_SRC))
    import llm_client

    provider = llm_client._normalized_provider()
    return f"{provider}/{llm_client._model_for(provider)}"


class BudgetExhausted(RuntimeError):
    pass


class CostGuard:
    """Stops before a request whose estimated cost would take the run past the budget.

    The pre-request estimate is deliberately generous (input chars / 3 plus the full output
    allowance); once the provider reports real usage the reservation is replaced by the
    real cost. A response without usage keeps its reservation.
    """

    def __init__(self, max_cost: float, input_price: float, output_price: float):
        self.max_cost, self.input_price, self.output_price = max_cost, input_price, output_price
        self.spent_or_reserved = 0.0

    def reserve(self, prompt_chars: int, max_output_tokens: int) -> float:
        estimate = (prompt_chars / 3 + 256) * self.input_price + max_output_tokens * self.output_price
        reservation = estimate / 1e6
        if self.spent_or_reserved + reservation > self.max_cost:
            raise BudgetExhausted(
                f"budget {self.max_cost:.4f} USD would be exceeded: spent_or_reserved={self.spent_or_reserved:.4f}, "
                f"next request reserves {reservation:.4f}")
        self.spent_or_reserved += reservation
        return reservation

    def settle(self, reservation: float, input_tokens: int, output_tokens: int) -> float | None:
        if input_tokens <= 0:
            return None
        cost = (input_tokens * self.input_price + output_tokens * self.output_price) / 1e6
        self.spent_or_reserved += cost - reservation
        return cost


# ------------------------------------------------------------------------------------ run

def load_cases(path: Path) -> dict:
    suite = json.loads(path.read_text(encoding="utf-8"))
    ids = [case["id"] for case in suite["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids")
    for case in suite["cases"]:
        if case["verdict"] not in ("vulnerable", "safe"):
            raise ValueError(f"{case['id']}: verdict must be vulnerable or safe")
        if case["missing_control"] not in CONTROLS:
            raise ValueError(f"{case['id']}: unknown missing_control")
        if (case["verdict"] == "vulnerable") == (case["missing_control"] == "none"):
            raise ValueError(f"{case['id']}: verdict and missing_control disagree")
    suite["cases"] = sorted(suite["cases"], key=lambda case: case["id"])
    return suite


def cache_path(cache_dir: Path, model: str, prompt_digest: str, case_id: str, user_prompt: str) -> Path:
    key = hashlib.sha256(f"{model}\n{prompt_digest}\n{case_id}\n{user_prompt}".encode()).hexdigest()
    return cache_dir / re.sub(r"[^A-Za-z0-9_.-]", "_", model) / f"{case_id}-{key[:16]}.json"


def build_row(case: dict, extraction: dict, summary: dict, user_prompt: str) -> dict:
    return {
        "case_id": case["id"],
        "repo": case["repo"],
        "path": case["path"],
        "line_range": case["line_range"],
        "label": case["verdict"],
        "label_missing_control": case["missing_control"],
        "redactions": extraction["redactions"],
        "registration_found": extraction["registration"] is not None,
        "middleware_resolved": [m["name"] for m in summary["middleware"]],
        "prompt_chars": len(user_prompt) + len(SYSTEM_PROMPT),
        "handler_lines": case["line_range"][1] - case["line_range"][0] + 1,
    }


def ask(user_prompt: str, *, max_output_tokens: int, timeout_seconds: int):
    return PROVIDER(system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=timeout_seconds,
                    temperature=0, max_output_tokens=max_output_tokens)


def run(args) -> dict:
    suite = load_cases(args.cases)
    cases = [case for case in suite["cases"] if not args.case or case["id"] in set(args.case)]
    if args.case:
        unknown = set(args.case) - {case["id"] for case in suite["cases"]}
        if unknown:
            raise SystemExit(f"unknown case ids: {', '.join(sorted(unknown))}")
    fixture_digest = digest(suite["cases"])
    prompt_digest = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()
    model = args.model or ("dry-run" if args.dry_run else provider_model_name())
    if args.model:
        os.environ["LLM_MODEL"] = args.model

    previous = {}
    if args.output.exists() and not args.fresh:
        try:
            old = json.loads(args.output.read_text(encoding="utf-8"))
            if (old.get("fixture_digest") == fixture_digest and old.get("prompt_digest") == prompt_digest
                    and old.get("model") == model):
                # An error row (transport failure, budget stop) is retried, never carried over.
                previous = {row["case_id"]: row for row in old.get("rows", [])
                            if row.get("observed") and row["observed"] not in ("error", "dry_run")}
        except (json.JSONDecodeError, KeyError, TypeError):
            previous = {}

    report = {
        "schema_version": 1,
        "kind": "authz_handler_review",
        "status": "in_progress",
        "started_at": now(),
        "model": model,
        "dry_run": bool(args.dry_run),
        "fixture_digest": fixture_digest,
        "prompt_digest": prompt_digest,
        "context_lines_each_side": CONTEXT_LINES,
        "max_cost_usd": args.max_cost,
        "prices_per_million": {"input": args.input_price, "output": args.output_price},
        "planned_cases": len(cases),
        "resumed_rows": len([case for case in cases if case["id"] in previous]),
        "rows": [],
    }
    guard = CostGuard(args.max_cost, args.input_price or 0.0, args.output_price or 0.0)
    grep_cache: dict = {}
    stopped = None
    for case in cases:
        tree = snapshot_root(args.trees, case["repo"], case["ref"])
        extraction = extract_handler(tree, case)
        summary = auth_summary(tree, extraction["registration"], extraction["handler_name"], grep_cache)
        user_prompt = build_user_prompt(case, extraction, summary)
        row = build_row(case, extraction, summary, user_prompt)
        if case["id"] in previous:
            row = {**previous[case["id"]], "resumed": True}
        elif args.dry_run:
            row["observed"] = "dry_run"
            if args.show_prompts:
                row["user_prompt"] = user_prompt
        elif stopped:
            row["observed"] = "error"
            row["error"] = stopped
        else:
            cached = cache_path(args.cache, model, prompt_digest, case["id"], user_prompt)
            started = time.perf_counter()
            try:
                if cached.exists() and not args.fresh:
                    payload = json.loads(cached.read_text(encoding="utf-8"))
                    row["from_cache"] = True
                else:
                    reservation = guard.reserve(row["prompt_chars"], args.max_output_tokens)
                    response = ask(user_prompt, max_output_tokens=args.max_output_tokens, timeout_seconds=args.timeout)
                    payload = {"text": response.text, "input_tokens": response.input_tokens,
                               "output_tokens": response.output_tokens, "provider": response.provider,
                               "model": response.model, "fetched_at": now()}
                    cost = guard.settle(reservation, response.input_tokens, response.output_tokens)
                    payload["estimated_cost_usd"] = cost
                    cached.parent.mkdir(parents=True, exist_ok=True)
                    cached.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                parsed, rejection = parse_response(payload["text"], extraction["handler"])
                row.update(usage={"input_tokens": payload.get("input_tokens"), "output_tokens": payload.get("output_tokens")},
                           estimated_cost_usd=payload.get("estimated_cost_usd"), raw_response=payload["text"])
                if parsed:
                    row.update(observed=parsed["verdict"], observed_missing_control=parsed["missing_control"],
                               evidence=parsed["evidence"], reasoning=parsed["reasoning"])
                else:
                    row.update(observed="rejected", rejection=rejection)
            except BudgetExhausted as error:
                stopped = str(error)
                row.update(observed="error", error=stopped)
            except Exception as error:  # provider or transport failure: recorded, never re-raised mid-run
                row.update(observed="error", error=type(error).__name__)
            row["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
        report["rows"].append(row)
        report["spent_or_reserved_usd"] = round(guard.spent_or_reserved, 6)
        if not args.dry_run:
            report["summary"] = score(report["rows"])
        save(args.output, report)
        print(json.dumps({k: row.get(k) for k in ("case_id", "label", "observed", "observed_missing_control",
                                                   "rejection", "redactions", "registration_found", "error")}), flush=True)
    report["status"] = "stopped:budget" if stopped else ("dry_run" if args.dry_run else "complete")
    report["finished_at"] = now()
    save(args.output, report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", type=Path, default=HERE / "cases.json")
    parser.add_argument("--case", action="append", help="run only this case id (repeatable)")
    parser.add_argument("--trees", type=Path, required=True,
                        help="snapshot cache directory in the scripts/replay/corpus.py layout, outside the repository")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "results" / "authz-handlers.json")
    parser.add_argument("--cache", type=Path, default=HERE / ".cache")
    parser.add_argument("--model", help="overrides LLM_MODEL for this run and names the cache bucket")
    parser.add_argument("--input-price", type=float, help="USD per million input tokens (required for a live run)")
    parser.add_argument("--output-price", type=float, help="USD per million output tokens (required for a live run)")
    parser.add_argument("--max-cost", type=float, default=1.0)
    parser.add_argument("--max-output-tokens", type=int, default=600)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--dry-run", action="store_true", help="extract and build every prompt without calling a model")
    parser.add_argument("--show-prompts", action="store_true", help="with --dry-run, write each prompt into the report")
    parser.add_argument("--fresh", action="store_true", help="ignore the cache and any earlier report")
    parser.add_argument("--fetch", action="store_true",
                        help="download the pinned snapshots into --trees (outside the repository) and exit")
    args = parser.parse_args(argv)

    if args.fetch:
        for path in fetch_trees(load_cases(args.cases), args.trees):
            print(path)
        return 0

    if not args.dry_run:
        if not provider_configured():
            parser.error("no provider is configured (LLM_PROVIDER / OPENAI_API_KEY / GEMINI_API_KEY); use --dry-run")
        prices = (args.input_price, args.output_price, args.max_cost)
        if any(value is None or not math.isfinite(value) or value <= 0 for value in prices):
            parser.error("a live run needs positive --input-price, --output-price and --max-cost")
    report = run(args)
    if "summary" in report:
        print(json.dumps(report["summary"], indent=2))
    print(json.dumps({"status": report["status"], "output": str(args.output), "model": report["model"],
                      "spent_or_reserved_usd": report.get("spent_or_reserved_usd")}))
    return 0 if report["status"] in ("complete", "dry_run") else 1


if __name__ == "__main__":
    raise SystemExit(main())
