"""Repair families: which one a finding belongs to, and what its regression test must assert.

The engine uses the family to decide support; the agent loop names it in the task prompt and in
a coverage revision, with the harness assertion that proves a repair of that family, so the
model never has to infer either from the scanner's wording.

A family is language-independent: the same CWE-89 finding is `sql_parameterization` in a Node
router and in a Flask view. What differs per language is the toolchain (Node or Python) and the
harness assertion, so both are looked up by the affected file's language.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

SQL_PARAMETERIZATION = "sql_parameterization"
COMMAND_ARGUMENTS = "command_arguments"
PATH_CONTAINMENT = "path_containment"
HARDCODED_CREDENTIAL = "hardcoded_credential"
CODE_INJECTION_EVAL = "code_injection_eval"
# GitHub Actions workflow hardening. It is a family rather than part of another one because
# what it repairs is not a program: the four shapes it can patch are a mutable action reference,
# an expression interpolation inside a `run:` script, a privileged checkout of the pull
# request's revision, and a write grant under `pull_request_target`, and none of them has a call
# site, a parameter list or a module to load.
WORKFLOW_HARDENING = "workflow_hardening"
# A password digested with a fast unsalted hash (MD5, SHA-1, SHA-256), repaired to a salted
# key-derivation function from the standard library: `crypto.scryptSync` in Node,
# `hashlib.scrypt` in Python. The repair changes the stored format, so the family also rewrites
# the module's own comparisons of the digest into a verifier, and refuses by name a module that
# looks a digest up instead of comparing it, because a salted hash cannot be looked up.
PASSWORD_HASHING = "password_hashing"
# A session or response cookie set without HttpOnly, Secure, or SameSite. The repair sets all
# three on the options the code already passes (`httpOnly: true, secure: true, sameSite: 'lax'`,
# Flask `secure=True, httponly=True, samesite="Lax"`), keeping every other key, or turns the one
# Django or Flask setting the finding names to True. SameSite is Lax rather than Strict: Strict
# drops the cookie on every top-level navigation from another site, so a user following a link
# into the application arrives signed out, while Lax still withholds it from the cross-site
# POSTs and subresource requests that CSRF relies on, and it is what browsers already default to.
COOKIE_FLAGS = "cookie_flags"

ALL_FAMILIES = (
    SQL_PARAMETERIZATION,
    COMMAND_ARGUMENTS,
    PATH_CONTAINMENT,
    HARDCODED_CREDENTIAL,
    CODE_INJECTION_EVAL,
    WORKFLOW_HARDENING,
    PASSWORD_HASHING,
    COOKIE_FLAGS,
)

# The families the sandbox toolchains can repair *and prove by running a regression test*. This
# is what `ALL_FAMILIES` used to mean, and it stopped meaning it when the workflow family
# arrived: a workflow cannot be proven that way at all.
SANDBOX_PROVEN_FAMILIES = (
    SQL_PARAMETERIZATION,
    COMMAND_ARGUMENTS,
    PATH_CONTAINMENT,
    HARDCODED_CREDENTIAL,
    CODE_INJECTION_EVAL,
    PASSWORD_HASHING,
    COOKIE_FLAGS,
)

JAVASCRIPT = "javascript"
PYTHON = "python"
# Not a programming language: the toolchain that "checks" a workflow is the scanner itself,
# through the static assertion verification level. It is in this position because everything
# downstream -- the family table, the grouping, the skip reasons -- is keyed by the affected
# file's language, and a workflow needs its own key rather than a pretend Python one.
WORKFLOW = "workflow"
SUPPORTED_LANGUAGES = (JAVASCRIPT, PYTHON, WORKFLOW)

JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
PYTHON_SUFFIXES = frozenset({".py"})
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})
# Mirrors WORKFLOW_DIRECTORY in services/analysis-service/src/test_code_scope.py. A `.yml` file
# anywhere else is not a workflow and must not be handed to these templates.
WORKFLOW_DIRECTORY = ".github/workflows/"

# How a repair of each family is shown to be a repair.
#
# `sandbox_regression_test` is the original contract: a test that fails on the original tree and
# passes on the patched one, run in the sandbox. `static_assertion` is the weaker level
# `feat/static-assertion-verification` is adding: the rule that produced the finding fires on
# the original file, does not fire on the patched file, and nothing else in the file changed. It
# executes nothing.
#
# The workflow family can only ever use the second. No unit test can demonstrate that a
# workflow is secure: the thing being repaired is a document GitHub interprets, there is no
# module to load and no call to observe, and running the workflow would mean running CI.
SANDBOX_REGRESSION_TEST = "sandbox_regression_test"
STATIC_ASSERTION = "static_assertion"

FAMILY_VERIFICATION: dict[str, str] = {
    SQL_PARAMETERIZATION: SANDBOX_REGRESSION_TEST,
    COMMAND_ARGUMENTS: SANDBOX_REGRESSION_TEST,
    PATH_CONTAINMENT: SANDBOX_REGRESSION_TEST,
    HARDCODED_CREDENTIAL: SANDBOX_REGRESSION_TEST,
    CODE_INJECTION_EVAL: SANDBOX_REGRESSION_TEST,
    WORKFLOW_HARDENING: STATIC_ASSERTION,
    PASSWORD_HASHING: SANDBOX_REGRESSION_TEST,
    COOKIE_FLAGS: SANDBOX_REGRESSION_TEST,
}

# The families each toolchain can repair and prove. A family is listed for a language only once
# the harness can observe the repair: `hardcoded_credential` joined JavaScript when the Node
# harness could record an environment read (`h.assert.envRead`), and `code_injection_eval`
# joined it when the harness could record `eval`, `new Function`, the `vm` compile calls, and a
# string timer without running any of them (`h.assert.noCode`). Both toolchains now repair every
# family; what still decides support per finding is the static gate, which refuses a site that
# compiles a program rather than reading a value.
LANGUAGE_FAMILIES: dict[str, frozenset[str]] = {
    JAVASCRIPT: frozenset(SANDBOX_PROVEN_FAMILIES),
    PYTHON: frozenset(SANDBOX_PROVEN_FAMILIES),
    WORKFLOW: frozenset({WORKFLOW_HARDENING}),
}

# The assertion each family's regression test makes with the sandbox harness
# (contracts/test-harness-v1.md). Quoted to the model verbatim, so it stays short and exact.
FAMILY_ASSERTIONS: dict[str, str] = {
    SQL_PARAMETERIZATION: (
        "const q = h.pg.queries[0]; h.assert.notIncludes(q.text, payload); "
        "h.assert.includes(JSON.stringify(q.values || []), payload)"
    ),
    COMMAND_ARGUMENTS: (
        "h.assert.argv(h.child_process.calls[0], payload) with payload the injected input you sent "
        "(such as 'x; rm -rf /'), not the command name: fails on a shell string (exec, execSync, or "
        "options.shell) and when the payload is not its own args element"
    ),
    PATH_CONTAINMENT: (
        "h.fs.reads.length = 0 then h.assert.inside(h.fs.reads, base, { payload }) for payload "
        "'../../etc/passwd' and '..%2f..%2fetc%2fpasswd', then once for a legitimate name; base is "
        "the served directory as the module resolves it. It passes only when a traversal payload "
        "records no read, so resolve with path.resolve(base, name) and answer 400 before any fs "
        "access unless the resolved path is base or starts with base + path.sep; path.basename fails"
    ),
    HARDCODED_CREDENTIAL: (
        "const m = h.load(path, { env: { NAME: 'value-from-env' } }); h.assert.envRead('NAME'); "
        "h.assert.notInSource(m, literal), and h.assert.equal(m.<identifier>, 'value-from-env') when "
        "the module exports it: the value must come from process.env.NAME, with NAME derived from "
        "the identifier the literal was bound to, and the literal must be gone from the file"
    ),
    CODE_INJECTION_EVAL: (
        "with FUNC the function at the finding: h.call(m.FUNC, ...) with a payload that would run "
        "code; h.assert.noCode(); then h.assert.equal(JSON.stringify(h.call(m.FUNC, ...'[1, 2]'...).value), "
        "'[1,2]'): the payload must never be compiled (eval, new Function, the vm compile calls, and "
        "a string setTimeout/setInterval are stubbed and recorded) while a JSON document still parses"
    ),
    PASSWORD_HASHING: (
        "with HASH and VERIFY the module's own functions: const a = h.call(m.HASH, pw).value, "
        "b = h.call(m.HASH, pw).value; h.assert(a !== b); h.assert.passwordHash(pw); "
        "h.assert(h.call(m.VERIFY, pw, a).value); h.assert(!h.call(m.VERIFY, 'wrong', a).value): "
        "createHash/createHmac are recorded, so the password must reach crypto.scryptSync or "
        "pbkdf2Sync with a random per-call salt and never a fast digest"
    ),
    COOKIE_FLAGS: (
        "const m = h.load(path) (and h.invoke the route for res.cookie); h.assert.cookieFlags(KIND[, name]) "
        "with KIND 'express-session', 'cookie-session' or 'res.cookie': every recorded cookie of that "
        "kind must carry httpOnly: true, secure: true and sameSite 'lax' or 'strict'"
    ),
}

# The Python harness assertions (contracts/test-harness-python-v1.md).
PYTHON_FAMILY_ASSERTIONS: dict[str, str] = {
    SQL_PARAMETERIZATION: (
        "q = h.db.queries[0]; h.assert_not_includes(q['sql'], payload); "
        "h.assert_includes(repr(q['params']), payload): the payload must reach the driver as a "
        "bound parameter (sqlite3 '?', psycopg '%s', SQLAlchemy text() ':name'), never in the SQL text"
    ),
    COMMAND_ARGUMENTS: (
        "h.assert_argv(h.subprocess.calls[0], payload) with payload the injected input you sent "
        "(such as 'x; rm -rf /'): fails on os.system, shell=True, or a single command string, and "
        "when the payload is not its own element of the args list"
    ),
    PATH_CONTAINMENT: (
        "h.fs.reads.clear() then h.assert_inside(h.fs.reads, base, payload=payload) for payload "
        "'../../etc/passwd' and '..%2f..%2fetc%2fpasswd', then once for a legitimate name; base is "
        "the served directory as the module resolves it. It passes only when a traversal payload "
        "records no open() at all, so resolve with os.path.realpath(os.path.join(base, name)) and "
        "abort(400) before any file access unless the result is base or starts with base + os.sep"
    ),
    HARDCODED_CREDENTIAL: (
        "m = h.load(path, env={'NAME': 'value-from-env'}); h.assert_equal(m.NAME, 'value-from-env'); "
        "h.assert_env_read('NAME'); h.assert_not_in_source(m, literal): the module must take the "
        "secret from os.environ and no longer carry the literal"
    ),
    CODE_INJECTION_EVAL: (
        "with FUNC the function at the finding: h.call(m.FUNC, \"__import__('os').system('id')\"); "
        "h.assert_no_commands(); h.assert_equal(h.call(m.FUNC, '[1, 2]').value, [1, 2]): the payload "
        "must never run (os.system and subprocess are stubbed and recorded) while a literal still parses"
    ),
    PASSWORD_HASHING: (
        "with HASH and VERIFY the module's own functions: a = h.call(m.HASH, pw).value; "
        "b = h.call(m.HASH, pw).value; h.assert_true(a != b); h.assert_password_hash(pw); "
        "h.assert_true(h.call(m.VERIFY, pw, a).value); h.assert_true(not h.call(m.VERIFY, 'wrong', a).value): "
        "hashlib digests are recorded, so the password must reach hashlib.scrypt or pbkdf2_hmac "
        "with an os.urandom salt and never md5, sha1 or sha256"
    ),
    COOKIE_FLAGS: (
        "for a setting: m = h.load(path); h.assert_equal(m.NAME, True) (or m.app.config['NAME']); for "
        "set_cookie: h.invoke the view, then h.assert_cookie_flags(name): secure=True, httponly=True "
        "and samesite 'Lax' or 'Strict' on every recorded cookie of that name"
    ),
}


def is_workflow_path(path: str | None) -> bool:
    """A GitHub Actions workflow: `.yml`/`.yaml` under a `.github/workflows/` path segment.

    Mirrors `is_workflow_path` in services/analysis-service/src/test_code_scope.py. The
    directory matters: a `.yml` anywhere else is a manifest, a compose file or another
    provider's CI config, and none of the workflow templates is meaningful there.
    """
    if not path:
        return False
    normalized = str(path).replace("\\", "/").lower()
    if PurePosixPath(normalized).suffix not in WORKFLOW_SUFFIXES:
        return False
    return normalized.startswith(WORKFLOW_DIRECTORY) or f"/{WORKFLOW_DIRECTORY}" in normalized


def language_of_path(path: str | None) -> str | None:
    """The toolchain a file belongs to, or None when nothing here can check it."""
    if not path:
        return None
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in JAVASCRIPT_SUFFIXES:
        return JAVASCRIPT
    if suffix in PYTHON_SUFFIXES:
        return PYTHON
    if is_workflow_path(path):
        return WORKFLOW
    return None


def family_verification(family: str | None) -> str | None:
    """How a repair of this family is shown to be a repair, or None for an unknown family."""
    return FAMILY_VERIFICATION.get(family or "")


def declares_static_assertion(family: str | None) -> bool:
    """Whether this family's repairs are asserted statically by declaration.

    One of the two routes to the `static_assertion` level, and the declared one: this is for a
    family whose repair no regression test could demonstrate even in principle, which today is
    `workflow_hardening`. `FAMILY_VERIFICATION` above is the declaration; the other route is a
    family that *can* be executed, for a finding whose execution was refused for a reason the
    evidence records. A family must never be declared here when a proof can drive its repair,
    because that would trade an executed proof for a weaker one.
    """
    return family_verification(family) == STATIC_ASSERTION


def family_assertion(family: str | None, language: str | None) -> str | None:
    """The harness assertion a regression test for this family must make.

    None for the workflow family, and that is the contract rather than an omission: the family
    verifies by static assertion, so there is no harness, no test and nothing to assert. A
    caller that reaches for an assertion here is about to build a proof for something a proof
    cannot describe.
    """
    if family == WORKFLOW_HARDENING:
        return None
    table = PYTHON_FAMILY_ASSERTIONS if language == PYTHON else FAMILY_ASSERTIONS
    return table.get(family or "")


def family_supported(family: str | None, language: str | None) -> bool:
    return family is not None and language is not None and family in LANGUAGE_FAMILIES.get(language, frozenset())


def rule_family(finding: Any) -> str | None:
    text = " ".join(
        str(value or "")
        for value in (
            finding.rule_id,
            finding.cwe_id,
            finding.category,
            finding.title,
            finding.message,
            # The finding model allows extra fields and the analysis service sends this one; it
            # is the only field that names the vulnerability without ambiguity.
            getattr(finding, "internal_type", "") or "",
        )
    ).lower()
    # The workflow family is resolved first, and from the rule rather than the CWE, because its
    # CWEs are already taken. The shell-injection rule declares CWE-78, which the next block
    # reads as `command_arguments`, and that family would hand a workflow to a template that
    # rewrites a `child_process` call into an argument list. The internal type is unambiguous
    # where the CWE is not.
    if "workflow_script_injection" in text or "unpinned_action_reference" in text or ".gha-" in text:
        return WORKFLOW_HARDENING
    # A weak password hash is named by its CWE (916) or its internal type. CWE-327 alone is not
    # enough: tier 1's `crypto.weak.hash` declares it for every MD5 or SHA-1 call, and the
    # analysis service renames the finding `weak_password_hash` only when the digested value is a
    # credential. A digest of anything else (a cache key, an ETag) is not a password and has no
    # verifier to rewrite, so it stays outside the family.
    if "cwe-916" in text or "weak_password_hash" in text or "auth.weak_password_hash" in text:
        return PASSWORD_HASHING
    # CWE-1275 (SameSite=None) shares the internal type but not the repair: None is how a cookie
    # is made to travel cross-site on purpose, and lowering it to Lax would break that embed or
    # login flow rather than fix it. Only the missing-flag findings are this family.
    if "cwe-1275" not in text and (
        "cwe-614" in text or "cwe-1004" in text or "insecure_cookie_flags" in text or "session.insecure_cookie" in text
    ):
        return COOKIE_FLAGS
    if "cwe-89" in text or "sql injection" in text or "sql.injection" in text:
        return SQL_PARAMETERIZATION
    if "cwe-78" in text or "command injection" in text or "command.injection" in text:
        return COMMAND_ARGUMENTS
    if "cwe-22" in text or "path traversal" in text or "path containment" in text or "path.traversal" in text:
        return PATH_CONTAINMENT
    if "cwe-798" in text or "hardcoded credential" in text or "hardcoded.credential" in text or (
        "hardcoded" in text and any(term in text for term in ("secret", "password", "api key", "api_key", "token"))
    ):
        return HARDCODED_CREDENTIAL
    if "cwe-95" in text or "code injection" in text or "code.injection" in text or "eval" in text.split() or ".eval" in text:
        return CODE_INJECTION_EVAL
    return None
