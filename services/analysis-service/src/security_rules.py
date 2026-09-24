import re
from dataclasses import dataclass
from typing import List, Optional


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
            r"(def\s+delete_|def\s+update_|def\s+create_|\.destroy\(|\.remove\()"
            r".*(?!@login_required|@auth|@permission|isAuthenticated|authorize)",
            re.IGNORECASE,
        ),
        description="Destructive operation may lack proper authorization checks.",
        remediation="Add authorization decorators or middleware to all state-changing operations.",
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
            r"(\/login|\/register|\/reset|\/forgot|\/verify|\/otp|\/auth)"
            r".*(?!rate.?limit|throttle|limiter|slowDown)",
            re.IGNORECASE,
        ),
        description="Authentication endpoint appears to lack rate limiting.",
        remediation="Add rate limiting middleware to authentication and sensitive endpoints.",
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
        pattern=re.compile(
            r"(parseInt|Number\(|int\(|Integer\.parseInt|atoi\(|strtol\()"
            r".*(?!isNaN|isFinite|Number\.isSafe|try|catch)",
            re.IGNORECASE,
        ),
        description="Integer parsing without overflow/bounds checking.",
        remediation="Validate parsed integer is within expected range before use.",
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
            r"\.\w+\s*\(.*\)\s*\.\w+\s*(?!\?\.|\?\[|&&|\|\||!=\s*null|!==\s*null)",
            re.IGNORECASE,
        ),
        description="Method chain without null check may crash on null return value.",
        remediation="Add null/undefined checks or use optional chaining (?.) before accessing properties.",
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
            r"threading\.Thread|multiprocessing\.Process)"
            r".*(?!lock|mutex|synchronized|atomic|Lock\(|RLock\()",
            re.IGNORECASE | re.MULTILINE,
        ),
        description="Shared mutable state accessed concurrently without synchronization.",
        remediation="Use locks, mutexes, or thread-safe data structures for shared state.",
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


def likely_llm_repo(path: str, content: str) -> bool:
    indicators = ["openai", "langchain", "anthropic", "prompt", "llm", "completion", "chat.completions"]
    low = f"{path}\n{content}".lower()
    return any(token in low for token in indicators)
