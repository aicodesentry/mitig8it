import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Posting policy values. A rule whose precision nobody has measured still posts: the
# quarantine is for rules measured and found wrong, not for rules nobody has looked at.
PRECISION_MEASURED = "measured"
PRECISION_UNMEASURED = "unmeasured"
POSTING_POST = "post"
POSTING_QUARANTINE = "quarantine"


@dataclass
class SecurityRule:
    rule_id: str
    title: str
    category: str
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    severity: str
    confidence: float
    exploitability: str
    pattern: re.Pattern
    description: str
    remediation: str
    # Most rules recognize the shape of executable code, so they have no true positive in a
    # changelog or a README: that text never runs. A rule that looks for committed data
    # rather than code, such as a credential literal, sets this and keeps scanning prose.
    scans_prose: bool = False

    # ── Posting policy ───────────────────────────────────────────────────
    # `precision` records whether this rule's false-positive rate has been measured on a
    # real corpus. `posting` decides whether a match reaches a reviewer: a quarantined
    # rule still runs and is still counted, so the replay and the metrics can keep
    # measuring it, but nothing it produces is posted to GitHub, counted in the check
    # summary, or handed to remediation. `precision_evidence` names the measurement.
    precision: str = PRECISION_UNMEASURED
    posting: str = POSTING_POST
    precision_evidence: str = ""

    # ── Matching ─────────────────────────────────────────────────────────
    # A negative condition belongs here, not in a lookahead. A lookahead placed after a
    # greedy `.*` can always be satisfied by letting the `.*` run to the end of the line,
    # so it excludes nothing (see `find_ineffective_lookaheads` below). `exclusion` is a
    # second pass over the same line: a match is dropped when this pattern also matches.
    exclusion: Optional[re.Pattern] = None
    # False blanks the body of every string literal before matching, for rules whose
    # signal is code shape rather than committed text.
    reads_string_literals: bool = True


# ---------------------------------------------------------------------------
# CWE Top 25 (2024) + high-value supplementary rules
# Grouped by OWASP category for readability
# ---------------------------------------------------------------------------

SECURITY_RULES: List[SecurityRule] = [

    # ── A01:2021 — Broken Access Control ─────────────────────────────────

    SecurityRule(
        rule_id="auth.bypass.missing_check",
        title="Potential access-control bypass",
        category="broken access control",
        cwe_id="CWE-862",
        owasp_category="A01:2021",
        severity="high",
        confidence=0.62,
        exploitability="medium",
        # The exclusion is a lookahead anchored at the start of the line, so it rejects
        # the line when an auth token appears anywhere on it. A lookahead placed after
        # a greedy `.*` (the previous shape) can always be satisfied at the end of the
        # line, so it excluded nothing and the rule fired on guarded routes.
        pattern=re.compile(
            r"^(?!.*(?:auth|jwt|permission|middleware|protect|guard|session|login_required|depends\())"
            r".*(app\.(get|post|put|delete)\(|@app\.(get|post|put|delete)|router\.(get|post|put|delete))"
            r".*(admin|internal|user|private|settings|config)",
            re.IGNORECASE,
        ),
        description="Sensitive endpoint appears to lack explicit auth/authorization checks.",
        remediation="Enforce auth and authorization middleware on all sensitive routes.",
    ),
    SecurityRule(
        rule_id="path.traversal.user_path",
        title="Potential path traversal from user-controlled path",
        category="path traversal",
        cwe_id="CWE-22",
        owasp_category="A01:2021",
        severity="high",
        confidence=0.83,
        exploitability="medium",
        pattern=re.compile(
            r"(\bopen\(|\bsend_file\(|\bFile\(|\breadFile\(|\breadFileSync\(|\bcreateReadStream\()"
            r".*(\.\./|req\.|input\(|\+|f\"|\{)",
            re.IGNORECASE,
        ),
        description="File path access appears to use unsanitized user input.",
        remediation="Normalize and allowlist paths; reject traversal sequences and absolute paths.",
    ),
    SecurityRule(
        rule_id="authz.missing_function_level",
        title="Missing authorization on sensitive function",
        category="broken access control",
        cwe_id="CWE-306",
        owasp_category="A01:2021",
        severity="high",
        confidence=0.58,
        exploitability="high",
        pattern=re.compile(
            r"(def\s+delete_|def\s+update_|def\s+create_|\.destroy\(|\.remove\()",
            re.IGNORECASE,
        ),
        exclusion=re.compile(
            r"(@login_required|@auth|@permission|isAuthenticated|authorize)",
            re.IGNORECASE,
        ),
        description="Destructive operation may lack proper authorization checks.",
        remediation="Add authorization decorators or middleware to all state-changing operations.",
        precision=PRECISION_MEASURED,
        posting=POSTING_QUARANTINE,
        precision_evidence=(
            "Sept 2026 replay: 19 findings, 13 at `high`, every sampled one a stream, socket "
            "or connection-pool teardown (`result.destroy()`, `session.destroy()`, "
            "`void this.sequelize.pool.destroy(connection)`). Moving the dead lookahead out of "
            "the regex does not help: none of those lines carries an auth token either."
        ),
    ),
    SecurityRule(
        rule_id="cors.overly_permissive",
        title="Overly permissive CORS configuration",
        category="security misconfiguration",
        cwe_id="CWE-942",
        owasp_category="A01:2021",
        severity="medium",
        confidence=0.82,
        exploitability="medium",
        pattern=re.compile(
            r"(Access-Control-Allow-Origin|allow_origins|cors\()\s*[:=({\[]\s*['\"\[]?\s*['\"]?\*['\"]?",
            re.IGNORECASE,
        ),
        description="CORS allows all origins, enabling cross-site request attacks.",
        remediation="Restrict CORS to specific trusted origins instead of wildcard *.",
    ),
    SecurityRule(
        rule_id="csrf.missing_protection",
        title="Missing CSRF protection on state-changing endpoint",
        category="cross-site request forgery",
        cwe_id="CWE-352",
        owasp_category="A01:2021",
        severity="medium",
        confidence=0.55,
        exploitability="medium",
        pattern=re.compile(
            r"@(csrf_exempt|no_csrf|xsrf_exempt)",
            re.IGNORECASE,
        ),
        description="CSRF protection explicitly disabled on an endpoint.",
        remediation="Enable CSRF tokens on all state-changing endpoints.",
    ),

    # ── A02:2021 — Cryptographic Failures ────────────────────────────────

    SecurityRule(
        rule_id="crypto.weak.hash",
        title="Weak cryptographic hash used for security context",
        category="insecure cryptography",
        cwe_id="CWE-327",
        owasp_category="A02:2021",
        severity="medium",
        confidence=0.78,
        exploitability="medium",
        pattern=re.compile(r"\b(md5|sha1)\s*\(", re.IGNORECASE),
        description="Weak hash algorithm may be insufficient for security-sensitive operations.",
        remediation="Use modern algorithms (SHA-256+, Argon2, bcrypt, or libsodium primitives).",
    ),
    SecurityRule(
        rule_id="crypto.insufficient_entropy",
        title="Insufficient randomness for security-sensitive value",
        category="insecure cryptography",
        cwe_id="CWE-330",
        owasp_category="A02:2021",
        severity="medium",
        confidence=0.76,
        exploitability="medium",
        pattern=re.compile(
            r"(Math\.random\(\)|random\.random\(\)|rand\(\)|srand\()",
            re.IGNORECASE,
        ),
        description="Non-cryptographic random source used for security-sensitive value.",
        remediation="Use crypto.randomBytes, secrets module, or /dev/urandom for security tokens.",
    ),
    SecurityRule(
        rule_id="crypto.hardcoded_iv",
        title="Hardcoded initialization vector or nonce",
        category="insecure cryptography",
        cwe_id="CWE-329",
        owasp_category="A02:2021",
        severity="medium",
        confidence=0.72,
        exploitability="medium",
        pattern=re.compile(
            r"(iv|nonce|IV)\s*[:=]\s*['\"][A-Fa-f0-9]{16,}['\"]",
            re.IGNORECASE,
        ),
        description="Hardcoded IV/nonce defeats the purpose of encryption randomization.",
        remediation="Generate a fresh random IV/nonce for each encryption operation.",
    ),

    # ── A03:2021 — Injection ─────────────────────────────────────────────

    SecurityRule(
        rule_id="sql.injection.raw_query",
        title="Potential SQL Injection via string concatenation",
        category="SQL injection",
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        severity="high",
        confidence=0.86,
        exploitability="high",
        pattern=re.compile(
            r"(f['\"].*(?:SELECT|INSERT|UPDATE|DELETE)\s+|(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:\+\s*[a-zA-Z_]|\.format\(|%s|%\s*\())",
            re.IGNORECASE,
        ),
        description="A SQL query appears to be dynamically assembled from variables.",
        remediation="Use parameterized queries or prepared statements.",
    ),
    SecurityRule(
        rule_id="cmd.injection.shell_true",
        title="Potential command injection in shell execution",
        category="command injection",
        cwe_id="CWE-78",
        owasp_category="A03:2021",
        severity="critical",
        confidence=0.9,
        exploitability="high",
        pattern=re.compile(
            r"(subprocess\.\w+|os\.system|os\.popen|child_process\.\w+)\s*\(.*"
            r"(shell\s*=\s*True|\+|f\"|`\$|req\.|input\()",
            re.IGNORECASE,
        ),
        description="Shell command execution includes dynamic input or shell=True.",
        remediation="Avoid shell=True and pass commands as argument lists with strict allowlists.",
    ),
    SecurityRule(
        rule_id="code.injection.eval",
        title="Code injection via eval or dynamic execution",
        category="code injection",
        cwe_id="CWE-95",
        owasp_category="A03:2021",
        severity="critical",
        confidence=0.92,
        exploitability="high",
        # A shell invocation is command injection (CWE-78), not code injection, and it
        # already has its own rule. `child_process.exec`/`execFile` therefore must not
        # match here: a duplicate CWE-95 finding on the same line carries a fix hint
        # ("use JSON.parse") that does not apply to running a command.
        pattern=re.compile(
            r"(?:"
            # eval in any language: Python's builtin and JavaScript's global alike.
            r"\beval\s*\("
            # JavaScript constructs that compile a string into executable code.
            r"|\bnew\s+Function\s*\("
            r"|\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction|Script)\s*\("
            r"|\b(?:setTimeout|setInterval)\s*\(\s*[\"'`]"
            # Python's `exec` builtin. `execFile`/`execSync` never reach this branch
            # because the call paren must follow `exec` directly; a member call such as
            # `child_process.exec(` is rejected by the lookbehind; and a destructured
            # `exec(` is rejected when it is shaped like a shell call, that is when its
            # command is a template literal or a callback follows it.
            r"|(?<![.\w$])exec\s*\((?!\s*[`])(?![^;]*,\s*(?:\(|function\b|async\b))"
            r")",
            re.IGNORECASE,
        ),
        description="Dynamic code execution can run attacker-controlled payloads.",
        remediation="Replace eval/exec with safe alternatives (JSON.parse, AST literal_eval, schema validation).",
    ),
    SecurityRule(
        rule_id="xss.unsafe_html_render",
        title="Potential XSS through unsafe HTML rendering",
        category="XSS",
        cwe_id="CWE-79",
        owasp_category="A03:2021",
        severity="high",
        confidence=0.84,
        exploitability="medium",
        pattern=re.compile(
            r"(dangerouslySetInnerHTML|innerHTML\s*=|v-html|document\.write\(|\$\(.*\)\.html\()",
            re.IGNORECASE,
        ),
        description="Raw HTML rendering without sanitization can enable script injection.",
        remediation="Avoid raw HTML rendering or sanitize untrusted content before rendering.",
    ),
    SecurityRule(
        rule_id="nosql.injection",
        title="Potential NoSQL injection",
        category="NoSQL injection",
        cwe_id="CWE-943",
        owasp_category="A03:2021",
        severity="high",
        confidence=0.75,
        exploitability="high",
        pattern=re.compile(
            r"(\.find\(|\.findOne\(|\.aggregate\(|\.updateOne\().*"
            r"(req\.(body|query|params)|\$where|\$regex|\$ne|\$gt|\$lt)",
            re.IGNORECASE,
        ),
        description="Database query includes unsanitized user input that may allow NoSQL operator injection.",
        remediation="Validate and sanitize input; reject MongoDB operators from user-supplied data.",
    ),
    SecurityRule(
        rule_id="ldap.injection",
        title="Potential LDAP injection",
        category="LDAP injection",
        cwe_id="CWE-90",
        owasp_category="A03:2021",
        severity="high",
        confidence=0.74,
        exploitability="high",
        pattern=re.compile(
            r"(ldap_search|ldap\.search|search_s\(|search_ext_s\().*(\+|f\"|format\(|%s)",
            re.IGNORECASE,
        ),
        description="LDAP query constructed with unsanitized input.",
        remediation="Use parameterized LDAP queries and escape special LDAP characters.",
    ),
    SecurityRule(
        rule_id="template.injection",
        title="Potential server-side template injection",
        category="template injection",
        cwe_id="CWE-1336",
        owasp_category="A03:2021",
        severity="critical",
        confidence=0.78,
        exploitability="high",
        pattern=re.compile(
            r"(render_template_string|Template\(|Jinja2|Environment\(\)).*"
            r"(req\.|input\(|\+|f\"|format\()",
            re.IGNORECASE,
        ),
        description="Template rendered from user-controlled input enables server-side code execution.",
        remediation="Never pass user input directly to template engines; use pre-compiled templates.",
    ),

    # ── A04:2021 — Insecure Design ───────────────────────────────────────

    SecurityRule(
        rule_id="rate_limit.missing",
        title="Missing rate limiting on sensitive endpoint",
        category="insecure design",
        cwe_id="CWE-770",
        owasp_category="A04:2021",
        severity="medium",
        confidence=0.52,
        exploitability="medium",
        pattern=re.compile(
            r"(\/login|\/register|\/reset|\/forgot|\/verify|\/otp|\/auth)",
            re.IGNORECASE,
        ),
        exclusion=re.compile(
            r"(rate.?limit|throttle|limiter|slowDown)",
            re.IGNORECASE,
        ),
        description="Authentication endpoint appears to lack rate limiting.",
        remediation="Add rate limiting middleware to authentication and sensitive endpoints.",
        precision=PRECISION_MEASURED,
        posting=POSTING_QUARANTINE,
        precision_evidence=(
            "Sept 2026 replay: 2 findings, both wrong, and the rule's whole output over 165 "
            "pull requests was `location: '/login'` in a got redirect test, "
            "` *    res.location('../login');` in an express JSDoc example, and the string "
            "`@octokit/auth-token` in a vendored licences file. The rule has no notion of a "
            "route declaration; it matches the substring `/auth` anywhere on a line."
        ),
    ),

    # ── A05:2021 — Security Misconfiguration ─────────────────────────────

    SecurityRule(
        rule_id="config.debug_enabled",
        title="Debug mode enabled in application config",
        category="security misconfiguration",
        cwe_id="CWE-489",
        owasp_category="A05:2021",
        severity="medium",
        confidence=0.75,
        exploitability="low",
        pattern=re.compile(r"(DEBUG|debug)\s*[:=]\s*(True|true|1|\"true\")", re.IGNORECASE),
        description="Debug mode exposes stack traces, internal state, and may disable security controls.",
        remediation="Ensure DEBUG is disabled in production via environment variables.",
    ),
    SecurityRule(
        rule_id="upload.unsafefile",
        title="Unsafe file upload handling",
        category="unsafe file upload",
        cwe_id="CWE-434",
        owasp_category="A05:2021",
        severity="high",
        confidence=0.71,
        exploitability="medium",
        pattern=re.compile(
            r"(multer|upload\(|save\(|write_file|saveFile).*(filename|path|originalname|file\.).*(req\.|input|user)",
            re.IGNORECASE,
        ),
        description="Upload flow appears to trust user-controlled file metadata or path.",
        remediation="Validate MIME/type, enforce extension allowlists, randomize storage names.",
    ),
    SecurityRule(
        rule_id="config.tls_disabled",
        title="TLS/SSL verification disabled",
        category="security misconfiguration",
        cwe_id="CWE-295",
        owasp_category="A05:2021",
        severity="high",
        confidence=0.88,
        exploitability="medium",
        pattern=re.compile(
            r"(verify\s*=\s*False|rejectUnauthorized\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
            r"|InsecureRequestWarning|CERT_NONE|ssl\._create_unverified_context)",
            re.IGNORECASE,
        ),
        description="TLS certificate verification is disabled, enabling man-in-the-middle attacks.",
        remediation="Always verify TLS certificates. Use proper CA bundles for internal services.",
    ),
    SecurityRule(
        rule_id="config.verbose_errors",
        title="Verbose error details exposed to client",
        category="information exposure",
        cwe_id="CWE-209",
        owasp_category="A05:2021",
        severity="medium",
        confidence=0.65,
        exploitability="low",
        pattern=re.compile(
            r"(res\.(json|send|write)|return\s+(jsonify|Response|HttpResponse))\s*\(.*"
            r"(stack|stackTrace|traceback|err\.message|error\.message|str\(e\))",
            re.IGNORECASE,
        ),
        description="Error stack trace or internal error message may be sent to the client.",
        remediation="Return generic error messages to clients; log details server-side only.",
    ),

    # ── A06:2021 — Vulnerable and Outdated Components ────────────────────
    # (handled by DEPENDENCY_RISK_PATTERNS below)

    # ── A07:2021 — Identification and Authentication Failures ────────────

    SecurityRule(
        rule_id="secret.hardcoded.credential",
        title="Hardcoded secret or credential",
        category="hardcoded secrets",
        cwe_id="CWE-798",
        owasp_category="A07:2021",
        severity="critical",
        confidence=0.94,
        exploitability="high",
        pattern=re.compile(
            r"(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|password|passwd|"
            r"private[_-]?key|client[_-]?secret|database[_-]?url|connection[_-]?string)"
            r"\s*[:=]\s*['\"][A-Za-z0-9_\-/+=\.:@;]{12,}['\"]",
            re.IGNORECASE,
        ),
        description="Credential-like literal appears committed in source.",
        remediation="Move secrets to secure secret management and rotate leaked values.",
        # A secret pasted into a README or a changelog is still a leaked secret.
        scans_prose=True,
    ),
    SecurityRule(
        rule_id="auth.weak_password_hash",
        title="Password stored with weak or no hashing",
        category="authentication failure",
        cwe_id="CWE-916",
        owasp_category="A07:2021",
        severity="critical",
        confidence=0.8,
        exploitability="high",
        pattern=re.compile(
            r"(password|passwd|password_hash|pass_hash)\s*=\s*\w*\(?\s*\b(md5|sha1|sha256|base64)\s*\(",
            re.IGNORECASE,
        ),
        description="Password hashed with a fast/unsalted algorithm unsuitable for credential storage.",
        remediation="Use bcrypt, Argon2, or scrypt with proper salt and work factor.",
    ),
    SecurityRule(
        rule_id="session.insecure_cookie",
        title="Session cookie missing security flags",
        category="session management",
        cwe_id="CWE-614",
        owasp_category="A07:2021",
        severity="medium",
        confidence=0.77,
        exploitability="medium",
        pattern=re.compile(
            r"(set.?cookie|session|cookie)\s*[({].*"
            r"(httpOnly\s*[:=]\s*false|secure\s*[:=]\s*false|sameSite\s*[:=]\s*['\"]?none)",
            re.IGNORECASE,
        ),
        description="Session cookie missing httpOnly, secure, or sameSite flag.",
        remediation="Set httpOnly: true, secure: true, sameSite: 'strict' on session cookies.",
    ),

    # ── A08:2021 — Software and Data Integrity Failures ──────────────────

    SecurityRule(
        rule_id="deserialize.untrusted_data",
        title="Insecure deserialization of untrusted data",
        category="insecure deserialization",
        cwe_id="CWE-502",
        owasp_category="A08:2021",
        severity="critical",
        confidence=0.88,
        exploitability="high",
        pattern=re.compile(
            r"(pickle\.loads|yaml\.load\(|marshal\.loads|unserialize\(|"
            r"ObjectInputStream|readObject\(|JsonConvert\.Deserialize|"
            r"BinaryFormatter|JavaScriptSerializer|shelve\.open|dill\.loads|joblib\.load\()",
            re.IGNORECASE,
        ),
        description="Deserialization primitive can execute attacker-controlled payloads.",
        remediation="Use safe loaders (e.g. yaml.safe_load) and strict schema validation on untrusted input.",
    ),

    # ── A09:2021 — Security Logging and Monitoring Failures ──────────────

    SecurityRule(
        rule_id="logging.sensitive_data",
        title="Sensitive data written to logs",
        category="information exposure",
        cwe_id="CWE-532",
        owasp_category="A09:2021",
        severity="medium",
        confidence=0.68,
        exploitability="low",
        pattern=re.compile(
            r"(console\.log|logger?\.(info|debug|warn)|print\(|logging\.(info|debug))"
            r".*\b(password|secret|token|apiKey|api_key|authorization|credit.?card|ssn|bearer)\b",
            re.IGNORECASE,
        ),
        description="Sensitive data (credentials, tokens, PII) may be written to application logs.",
        remediation="Redact sensitive fields before logging. Never log secrets or PII.",
    ),

    # ── A10:2021 — Server-Side Request Forgery ───────────────────────────

    SecurityRule(
        rule_id="ssrf.untrusted_url_fetch",
        title="Potential SSRF via untrusted URL fetch",
        category="SSRF",
        cwe_id="CWE-918",
        owasp_category="A10:2021",
        severity="high",
        confidence=0.8,
        exploitability="medium",
        pattern=re.compile(
            r"(requests\.(get|post|put|delete|head)|axios\.(get|post|put|delete)|"
            r"fetch\(|urllib\.request|http\.get\(|http\.request\()"
            r".*(req\.|params|input|url|query|args)",
            re.IGNORECASE,
        ),
        description="Outbound HTTP request appears to use user-controlled URL data.",
        remediation="Use strict URL allowlists and block private/internal address ranges.",
    ),

    # ── Additional CWE Top 25 ────────────────────────────────────────────

    SecurityRule(
        rule_id="memory.buffer_overflow",
        title="Potential buffer overflow via unsafe function",
        category="memory safety",
        cwe_id="CWE-120",
        owasp_category="A06:2021",
        severity="critical",
        confidence=0.85,
        exploitability="high",
        pattern=re.compile(
            r"\b(strcpy|strcat|sprintf|gets|scanf|vsprintf|strncpy)\s*\(",
            re.IGNORECASE,
        ),
        description="Unsafe C/C++ function with no bounds checking can cause buffer overflow.",
        remediation="Use bounded alternatives: strncpy_s, snprintf, fgets, or std::string.",
    ),
    SecurityRule(
        rule_id="memory.format_string",
        title="Potential format string vulnerability",
        category="memory safety",
        cwe_id="CWE-134",
        owasp_category="A03:2021",
        severity="critical",
        confidence=0.82,
        exploitability="high",
        pattern=re.compile(
            r"(printf|fprintf|sprintf|syslog)\s*\(\s*[a-zA-Z_]",
            re.IGNORECASE,
        ),
        description="Format function called with a variable as format string, enabling arbitrary memory read/write.",
        remediation="Always use a literal format string: printf(\"%s\", var) instead of printf(var).",
    ),
    SecurityRule(
        rule_id="race.toctou",
        title="Potential TOCTOU race condition",
        category="race condition",
        cwe_id="CWE-367",
        owasp_category="A04:2021",
        severity="medium",
        confidence=0.6,
        exploitability="medium",
        pattern=re.compile(
            r"(os\.path\.exists|os\.access|Path\.exists|fs\.existsSync|fs\.accessSync)"
            r".*\n.*(open\(|fs\.read|fs\.write|unlink|rmdir|rename)",
            re.MULTILINE,
        ),
        description="File existence check followed by file operation creates a race window.",
        remediation="Use atomic operations (open with O_CREAT|O_EXCL) instead of check-then-act.",
    ),
    SecurityRule(
        rule_id="xxe.xml_parsing",
        title="XML parsing vulnerable to XXE",
        category="XXE",
        cwe_id="CWE-611",
        owasp_category="A05:2021",
        severity="high",
        confidence=0.82,
        exploitability="high",
        pattern=re.compile(
            r"(xml\.etree\.ElementTree\.parse|xml\.dom\.minidom\.parse|"
            r"lxml\.etree\.parse|SAXParser|XMLReader|DocumentBuilder|"
            r"xml2js\.parseString|DOMParser|XMLHttpRequest.*responseXML)",
            re.IGNORECASE,
        ),
        description="XML parser may process external entities, enabling file read or SSRF.",
        remediation="Disable external entity processing: use defusedxml (Python), disable DTDs (Java/JS).",
    ),
    SecurityRule(
        rule_id="redirect.open",
        title="Potential open redirect",
        category="open redirect",
        cwe_id="CWE-601",
        owasp_category="A01:2021",
        severity="medium",
        confidence=0.72,
        exploitability="medium",
        pattern=re.compile(
            r"(redirect\(|res\.redirect\(|location\.href\s*=|window\.location\s*=)"
            r".*(req\.|params|query|input|args|url|next|return_to|redirect_uri)",
            re.IGNORECASE,
        ),
        description="Redirect destination controlled by user input enables phishing.",
        remediation="Validate redirect URLs against an allowlist of trusted domains.",
    ),
    SecurityRule(
        rule_id="integer.overflow",
        title="Potential integer overflow or wraparound",
        category="integer overflow",
        cwe_id="CWE-190",
        owasp_category="A06:2021",
        severity="medium",
        confidence=0.55,
        exploitability="medium",
        # Every alternative carries a leading word boundary. Without it `int\(` matched
        # `models.UniqueConstraint(` and `function fingerprint(snapshot: Snapshot)`.
        pattern=re.compile(
            r"(\bparseInt\b|\bNumber\(|\bint\(|\bInteger\.parseInt\b|\batoi\(|\bstrtol\()",
            re.IGNORECASE,
        ),
        exclusion=re.compile(
            r"(isNaN|isFinite|Number\.isSafe|\btry\b|\bcatch\b)",
            re.IGNORECASE,
        ),
        description="Integer parsing without overflow/bounds checking.",
        remediation="Validate parsed integer is within expected range before use.",
        precision=PRECISION_MEASURED,
        posting=POSTING_QUARANTINE,
        precision_evidence=(
            "Sept 2026 replay: 14 findings. The word boundary and the relocated exclusion "
            "clear both sampled lines (`models.UniqueConstraint(`, "
            "`function fingerprint(snapshot: Snapshot): string {`), but what remains is still "
            "`the line contains parseInt`, with no measurement on the other 12 findings and "
            "no true positive anywhere in the corpus. Re-enable when a measured sample says "
            "the bare parse is worth a review comment."
        ),
    ),
    SecurityRule(
        rule_id="null.pointer.deref",
        title="Potential null pointer dereference",
        category="null pointer",
        cwe_id="CWE-476",
        owasp_category="A06:2021",
        severity="medium",
        confidence=0.5,
        exploitability="low",
        pattern=re.compile(
            r"\.\w+\s*\(.*\)\s*\.\w+\s*",
            re.IGNORECASE,
        ),
        exclusion=re.compile(
            r"(\?\.|\?\[|&&|\|\||![=]=\s*null|![=]=\s*undefined|===\s*null|===\s*undefined)",
            re.IGNORECASE,
        ),
        description="Method chain without null check may crash on null return value.",
        remediation="Add null/undefined checks or use optional chaining (?.) before accessing properties.",
        precision=PRECISION_MEASURED,
        posting=POSTING_QUARANTINE,
        precision_evidence=(
            "Sept 2026 replay: 85 of 134 findings (63%), and all 19 sampled by hand were wrong. "
            "The pattern is a method-chain detector, not a null check: it fired on "
            "`connection.removeAllListeners('error').on('error', ...)`, on the Jest idiom "
            "`await expect(next.start()).rejects.toThrow()` (27 findings on its own), and on the "
            "Rust `chunking_context.unused_references().await?`, where its remediation text "
            "recommends optional chaining that the language does not have. Relocating the "
            "exclusion fixes only the guarded case; the semantics are wrong."
        ),
    ),
    SecurityRule(
        rule_id="concurrency.shared_state",
        title="Concurrent access to shared mutable state",
        category="race condition",
        cwe_id="CWE-362",
        owasp_category="A04:2021",
        severity="medium",
        confidence=0.5,
        exploitability="medium",
        pattern=re.compile(
            r"(global\s+\w+|class\s+\w+:.*\n\s+\w+\s*=\s*\[\]|"
            r"static\s+(mut\s+)?[A-Z_]+\s*[:=]|"
            r"threading\.Thread|multiprocessing\.Process)",
            re.IGNORECASE | re.MULTILINE,
        ),
        exclusion=re.compile(
            r"(lock|mutex|synchronized|atomic|Lock\(|RLock\()",
            re.IGNORECASE,
        ),
        # `global` in a sentence is prose, and a sentence inside a string literal is not
        # code. Blanking string bodies removes one of the two shapes the replay caught.
        reads_string_literals=False,
        description="Shared mutable state accessed concurrently without synchronization.",
        remediation="Use locks, mutexes, or thread-safe data structures for shared state.",
        precision=PRECISION_MEASURED,
        posting=POSTING_QUARANTINE,
        precision_evidence=(
            "Sept 2026 replay: 6 findings. `global\\s+\\w+` matches English, so the rule fired "
            "on the comment `// If agent.http2 is unset, use the global agent for connection "
            "pooling.` and on the changelog line `Fix a global leak when multiple subnets are "
            "trusted`. Comment stripping removes the first shape; the prose-file shape needs "
            "the rule to know what a declaration is."
        ),
    ),

    # ── LLM-specific ─────────────────────────────────────────────────────

    SecurityRule(
        rule_id="llm.prompt.injection",
        title="Unsafe prompt composition with untrusted input",
        category="prompt injection",
        cwe_id="CWE-20",
        owasp_category="LLM01",
        severity="medium",
        confidence=0.67,
        exploitability="medium",
        pattern=re.compile(
            r"(prompt|system_message|messages)\s*[\[=+].*"
            r"(req\.|user_input|input\(|request\.(body|query)|args\[)",
            re.IGNORECASE,
        ),
        description="Prompt is composed with untrusted text without policy/guardrail separation.",
        remediation="Isolate system instructions, sanitize/label user content, and add output controls.",
    ),
]


# ---------------------------------------------------------------------------
# Dependency risk patterns (version-specific known vulnerabilities)
# ---------------------------------------------------------------------------

DEPENDENCY_RISK_PATTERNS = [
    # JavaScript
    (re.compile(r"lodash.*4\.17\.(?:1\d|20|[0-9])(?!\d)", re.IGNORECASE),
     "lodash < 4.17.21 has prototype pollution (CVE-2021-23337)", "high"),
    (re.compile(r"express['\"]?\s*[:@<=>~^]*\s*['\"]?4\.[0-9]\.", re.IGNORECASE),
     "express < 4.17.3 has open redirect vulnerability", "medium"),
    (re.compile(r"jsonwebtoken.*['\"]?\^?[0-8]\.\d", re.IGNORECASE),
     "jsonwebtoken < 9.0.0 has insecure defaults (CVE-2022-23529)", "high"),
    (re.compile(r"axios['\"]?\s*[:@<=>~^]*\s*['\"]?0\.", re.IGNORECASE),
     "axios 0.x has SSRF and prototype pollution vulnerabilities", "medium"),

    # Python
    (re.compile(r"pyyaml\s*[<=>~^]*\s*5\.[0-3](\.\d)?$", re.IGNORECASE | re.MULTILINE),
     "PyYAML < 5.4 allows arbitrary code execution via yaml.load()", "critical"),
    (re.compile(r"django\s*[<=>~^]*\s*[23]\.\d\.\d(?!\d)", re.IGNORECASE),
     "Older Django versions may have known security vulnerabilities", "medium"),
    (re.compile(r"flask\s*[<=>~^]*\s*[01]\.", re.IGNORECASE),
     "Flask < 2.0 has known security issues", "medium"),
    (re.compile(r"requests\s*[<=>~^]*\s*2\.2[0-7]\.", re.IGNORECASE),
     "requests < 2.28.0 has proxy credential leak (CVE-2023-32681)", "medium"),

    # Java
    (re.compile(r"log4j.*2\.1[0-4]\.", re.IGNORECASE),
     "log4j 2.10-2.14 vulnerable to Log4Shell (CVE-2021-44228)", "critical"),
    (re.compile(r"spring-boot.*2\.[0-6]\.", re.IGNORECASE),
     "Spring Boot < 2.7 may have known vulnerabilities including Spring4Shell", "high"),
    (re.compile(r"commons-collections.*3\.[0-2]\.", re.IGNORECASE),
     "Apache Commons Collections 3.x allows deserialization RCE", "critical"),
]


# ---------------------------------------------------------------------------
# Static check: negative lookaheads that exclude nothing
# ---------------------------------------------------------------------------


def _skip_group_body(source: str, start: int) -> int:
    """Index just past the group that opens at `start`."""
    depth = 0
    index = start
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index = _skip_character_class(source, index)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(source)


def _skip_character_class(source: str, start: int) -> int:
    index = start + 1
    if index < len(source) and source[index] == "^":
        index += 1
    if index < len(source) and source[index] == "]":
        index += 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
            continue
        if source[index] == "]":
            return index + 1
        index += 1
    return len(source)


def _read_quantifier(source: str, index: int) -> Tuple[int, bool, bool]:
    """Returns (next index, token is required, quantifier is greedy and unbounded)."""
    if index >= len(source):
        return index, True, False

    char = source[index]
    if char in "*+?":
        end = index + 1
        lazy = end < len(source) and source[end] in "?+"
        if lazy:
            end += 1
        required = char == "+"
        unbounded_greedy = char in "*+" and not lazy
        return end, required, unbounded_greedy

    if char == "{":
        close = source.find("}", index)
        if close == -1:
            return index, True, False
        body = source[index + 1:close]
        end = close + 1
        lazy = end < len(source) and source[end] in "?+"
        if lazy:
            end += 1
        low = body.split(",")[0].strip() or "0"
        required = low.isdigit() and int(low) > 0
        unbounded_greedy = body.rstrip().endswith(",") and not lazy
        return end, required, unbounded_greedy

    return index, True, False


def find_ineffective_lookaheads(rules=None) -> List[Tuple[str, str]]:
    """Rules whose negative lookahead cannot exclude anything.

    The shape is `<unbounded greedy quantifier><optional tokens>(?!alternatives)`. The
    engine can always satisfy the lookahead by letting the quantifier consume to the end
    of the line, where the lookahead then looks at nothing, so the rule silently degrades
    to its leading alternation. `auth.bypass.missing_check` was re-anchored for exactly
    this reason; this check is here so no sibling rule can pick the shape back up.

    The scan is a heuristic over the pattern source, not a regex engine. It walks tokens
    left to right and flags a negative lookahead when an unbounded greedy quantifier
    precedes it with no required token in between. A required token anchors the lookahead
    (that is why `lodash.*4\\.17\\.(?:1\\d|20|[0-9])(?!\\d)` is not flagged), and an
    alternation bar resets the scan because the branches are independent.

    Returns `(rule_id, lookahead source)` pairs.
    """
    findings: List[Tuple[str, str]] = []
    for rule_id, pattern in tier1_patterns() if rules is None else (
        (rule.rule_id, rule.pattern) for rule in rules
    ):
        for lookahead in _ineffective_lookaheads_in(pattern.pattern):
            findings.append((rule_id, lookahead))
    return findings


def tier1_patterns() -> List[Tuple[str, "re.Pattern"]]:
    """Every regex tier 1 runs: the security rules and the dependency risk patterns."""
    patterns: List[Tuple[str, re.Pattern]] = [(rule.rule_id, rule.pattern) for rule in SECURITY_RULES]
    patterns.extend(
        (f"dependency.risk.version[{index}]", pattern)
        for index, (pattern, _message, _severity) in enumerate(DEPENDENCY_RISK_PATTERNS)
    )
    for rule in SECURITY_RULES:
        if rule.exclusion is not None:
            patterns.append((f"{rule.rule_id}.exclusion", rule.exclusion))
    return patterns


def _ineffective_lookaheads_in(source: str) -> List[str]:
    hits: List[str] = []
    greedy_pending = False
    required_since_greedy = False
    index = 0

    while index < len(source):
        char = source[index]

        if char == "\\":
            token_end = index + 2
        elif char == "[":
            token_end = _skip_character_class(source, index)
        elif char == "(":
            if source.startswith("(?!", index) or source.startswith("(?<!", index):
                if greedy_pending and not required_since_greedy:
                    hits.append(source[index:_skip_group_body(source, index)])
                index = _skip_group_body(source, index)
                continue
            if source.startswith("(?=", index) or source.startswith("(?<=", index):
                index = _skip_group_body(source, index)
                continue
            # A capturing or non-capturing group: descend into it so a greedy quantifier
            # inside the group is seen, then apply the group's own quantifier.
            body_end = _skip_group_body(source, index)
            hits.extend(_ineffective_lookaheads_in(source[index + 1:body_end - 1]))
            token_end = body_end
        elif char == "|":
            greedy_pending = False
            required_since_greedy = False
            index += 1
            continue
        elif char in "^$":
            # An anchor pins the position, so nothing before it can be given back.
            greedy_pending = False
            required_since_greedy = False
            index += 1
            continue
        elif char == ")":
            index += 1
            continue
        else:
            token_end = index + 1

        after_quantifier, required, unbounded_greedy = _read_quantifier(source, token_end)
        if unbounded_greedy:
            greedy_pending = True
            required_since_greedy = False
        elif required and greedy_pending:
            required_since_greedy = True
        index = after_quantifier

    return hits


def likely_llm_repo(path: str, content: str) -> bool:
    indicators = ["openai", "langchain", "anthropic", "prompt", "llm", "completion", "chat.completions"]
    low = f"{path}\n{content}".lower()
    return any(token in low for token in indicators)
