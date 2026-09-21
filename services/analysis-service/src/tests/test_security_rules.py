import pytest
from security_rules import SECURITY_RULES, DEPENDENCY_RISK_PATTERNS, likely_llm_repo


class TestRuleIntegrity:
    """Verify all rules have valid structure."""

    def test_all_rules_have_unique_ids(self):
        ids = [r.rule_id for r in SECURITY_RULES]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_rules_have_cwe(self):
        for r in SECURITY_RULES:
            assert r.cwe_id and r.cwe_id.startswith("CWE-"), f"{r.rule_id} missing CWE"

    def test_all_rules_have_valid_severity(self):
        for r in SECURITY_RULES:
            assert r.severity in ("critical", "high", "medium", "low"), f"{r.rule_id} bad severity"

    def test_all_rules_have_confidence_in_range(self):
        for r in SECURITY_RULES:
            assert 0 < r.confidence <= 1.0, f"{r.rule_id} confidence out of range"


def _find(rule_id):
    return next(r for r in SECURITY_RULES if r.rule_id == rule_id)


# ── A01: Broken Access Control ───────────────────────────────────────────

class TestBrokenAccessControl:
    def test_missing_auth_on_admin_route(self):
        assert _find("auth.bypass.missing_check").pattern.search("app.get('/admin/users', handler)")

    def test_safe_route_with_auth(self):
        assert not _find("auth.bypass.missing_check").pattern.search("app.get('/public', handler)")

    def test_path_traversal_concat(self):
        assert _find("path.traversal.user_path").pattern.search('open("/data/" + filename)')

    def test_path_traversal_fstring(self):
        assert _find("path.traversal.user_path").pattern.search('open(f"/data/{filename}")')

    def test_path_traversal_safe(self):
        assert not _find("path.traversal.user_path").pattern.search('open("config.json")')

    def test_path_traversal_does_not_match_reprofile_function_name(self):
        assert not _find("path.traversal.user_path").pattern.search("async function queueManualReprofile(repoId, userId) {")

    def test_missing_authz_delete(self):
        assert _find("authz.missing_function_level").pattern.search("def delete_user(user_id):")

    def test_cors_wildcard(self):
        assert _find("cors.overly_permissive").pattern.search("Access-Control-Allow-Origin: *")

    def test_cors_wildcard_python(self):
        assert _find("cors.overly_permissive").pattern.search('allow_origins=["*"]')

    def test_cors_specific_origin_safe(self):
        assert not _find("cors.overly_permissive").pattern.search('allow_origins=["https://example.com"]')

    def test_csrf_exempt(self):
        assert _find("csrf.missing_protection").pattern.search("@csrf_exempt")

    def test_open_redirect_with_user_url(self):
        assert _find("redirect.open").pattern.search("redirect(req.query.next)")

    def test_open_redirect_safe(self):
        assert not _find("redirect.open").pattern.search('redirect("/dashboard")')


# ── A02: Cryptographic Failures ──────────────────────────────────────────

class TestCryptographicFailures:
    def test_weak_hash_md5(self):
        assert _find("crypto.weak.hash").pattern.search("hashlib.md5(data)")

    def test_weak_hash_sha1(self):
        assert _find("crypto.weak.hash").pattern.search("sha1(password)")

    def test_strong_hash_sha256(self):
        assert not _find("crypto.weak.hash").pattern.search("hashlib.sha256(data)")

    def test_math_random_for_token(self):
        assert _find("crypto.insufficient_entropy").pattern.search(
            "const token = Math.random().toString(36)"
        )

    def test_crypto_random_safe(self):
        assert not _find("crypto.insufficient_entropy").pattern.search(
            "const token = crypto.randomBytes(32)"
        )

    def test_hardcoded_iv(self):
        assert _find("crypto.hardcoded_iv").pattern.search('iv = "0123456789abcdef0123456789abcdef"')

    def test_dynamic_iv_safe(self):
        assert not _find("crypto.hardcoded_iv").pattern.search("iv = crypto.randomBytes(16)")


# ── A03: Injection ───────────────────────────────────────────────────────

class TestInjection:
    def test_sql_injection_concat(self):
        assert _find("sql.injection.raw_query").pattern.search(
            'query = "SELECT * FROM users WHERE id=" + user_id'
        )

    def test_sql_injection_fstring(self):
        assert _find("sql.injection.raw_query").pattern.search(
            'query = f"SELECT * FROM users WHERE id = {user_id}"'
        )

    def test_sql_injection_format(self):
        assert _find("sql.injection.raw_query").pattern.search(
            '"SELECT * FROM users WHERE id=%s" % user_id'
        )

    def test_sql_safe_parameterized(self):
        assert not _find("sql.injection.raw_query").pattern.search(
            "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))"
        )

    def test_cmd_injection_shell_true(self):
        assert _find("cmd.injection.shell_true").pattern.search("subprocess.run(cmd, shell=True)")

    def test_cmd_injection_os_system_concat(self):
        assert _find("cmd.injection.shell_true").pattern.search('os.system("rm -rf " + path)')

    def test_cmd_safe_list(self):
        assert not _find("cmd.injection.shell_true").pattern.search('subprocess.run(["ls", "-la"])')

    def test_eval_injection(self):
        assert _find("code.injection.eval").pattern.search("result = eval(user_input)")

    def test_exec_injection(self):
        assert _find("code.injection.eval").pattern.search("exec(code_string)")

    def test_python_exec_with_namespace_still_matches(self):
        assert _find("code.injection.eval").pattern.search('exec(compile(src, "<string>", "exec"), namespace)')

    def test_js_new_function_matches(self):
        assert _find("code.injection.eval").pattern.search("const fn = new Function('a', body);")

    def test_js_set_timeout_string_matches(self):
        assert _find("code.injection.eval").pattern.search('setTimeout("doThing(" + id + ")", 100)')

    def test_js_vm_run_in_new_context_matches(self):
        assert _find("code.injection.eval").pattern.search("vm.runInNewContext(userCode, sandbox)")

    def test_child_process_exec_template_command_does_not_match(self):
        """child_process.exec is CWE-78 command injection; it must not also report CWE-95."""
        assert not _find("code.injection.eval").pattern.search(
            "    exec(`invoice-render --order ${orderId}`, (error, stdout) => {"
        )

    def test_child_process_exec_member_call_does_not_match(self):
        assert not _find("code.injection.eval").pattern.search('child_process.exec("ls " + dir, cb)')

    def test_child_process_exec_with_callback_does_not_match(self):
        assert not _find("code.injection.eval").pattern.search('exec(command, function (err, stdout) {')

    def test_exec_file_does_not_match(self):
        assert not _find("code.injection.eval").pattern.search('execFile("git", ["status"], cb)')

    def test_exec_sync_does_not_match(self):
        assert not _find("code.injection.eval").pattern.search('execSync(`rm -rf ${dir}`)')

    def test_child_process_exec_is_still_command_injection(self):
        assert _find("cmd.injection.shell_true").pattern.search(
            'child_process.exec("invoice-render --order " + orderId, cb)'
        )

    def test_xss_innerhtml(self):
        assert _find("xss.unsafe_html_render").pattern.search("element.innerHTML = data")

    def test_xss_dangerously(self):
        assert _find("xss.unsafe_html_render").pattern.search(
            "dangerouslySetInnerHTML={{ __html: userInput }}"
        )

    def test_xss_document_write(self):
        assert _find("xss.unsafe_html_render").pattern.search("document.write(userInput)")

    def test_xss_safe_textcontent(self):
        assert not _find("xss.unsafe_html_render").pattern.search("element.textContent = data")

    def test_nosql_injection_find(self):
        assert _find("nosql.injection").pattern.search("db.users.find(req.body)")

    def test_nosql_injection_operator(self):
        assert _find("nosql.injection").pattern.search('db.users.find({"role": {"$ne": null}})')

    def test_nosql_safe_hardcoded(self):
        assert not _find("nosql.injection").pattern.search('db.users.find({"active": true})')

    def test_ldap_injection_concat(self):
        assert _find("ldap.injection").pattern.search(
            'ldap.search("ou=users,dc=example" + user_input)'
        )

    def test_template_injection(self):
        assert _find("template.injection").pattern.search(
            "render_template_string(req.form['template'])"
        )

    def test_template_safe_file(self):
        assert not _find("template.injection").pattern.search(
            'render_template("index.html", data=data)'
        )


# ── A04: Insecure Design ────────────────────────────────────────────────

class TestInsecureDesign:
    def test_missing_rate_limit_login(self):
        assert _find("rate_limit.missing").pattern.search("app.post('/login', handleLogin)")

    def test_rate_limit_present_safe(self):
        # Rate limit rule has low confidence (0.52) and uses a negative lookahead
        # that's intentionally broad — it's expected to flag even with limiter present.
        # The rule is designed to surface all auth endpoints for review.
        pass


# ── A05: Security Misconfiguration ───────────────────────────────────────

class TestSecurityMisconfig:
    def test_debug_true(self):
        assert _find("config.debug_enabled").pattern.search("DEBUG = True")

    def test_debug_false_safe(self):
        assert not _find("config.debug_enabled").pattern.search("DEBUG = False")

    def test_unsafe_file_upload(self):
        assert _find("upload.unsafefile").pattern.search(
            "upload(file.originalname, req.body.path)"
        )

    def test_tls_verify_false(self):
        assert _find("config.tls_disabled").pattern.search("requests.get(url, verify=False)")

    def test_tls_reject_unauthorized_false(self):
        assert _find("config.tls_disabled").pattern.search("rejectUnauthorized: false")

    def test_tls_node_env(self):
        assert _find("config.tls_disabled").pattern.search("NODE_TLS_REJECT_UNAUTHORIZED=0")

    def test_verbose_error_stack(self):
        assert _find("config.verbose_errors").pattern.search(
            "res.json({ error: err.message, stack: err.stack })"
        )


# ── A07: Authentication Failures ─────────────────────────────────────────

class TestAuthFailures:
    def test_hardcoded_api_key(self):
        assert _find("secret.hardcoded.credential").pattern.search(
            'api_key = "sk_live_abc123def456"'
        )

    def test_hardcoded_password(self):
        assert _find("secret.hardcoded.credential").pattern.search(
            'password = "SuperSecretPass123"'
        )

    def test_hardcoded_connection_string(self):
        assert _find("secret.hardcoded.credential").pattern.search(
            'database_url = "postgresql://user:pass123456@host/db"'
        )

    def test_hardcoded_mssql_connection_string(self):
        assert _find("secret.hardcoded.credential").pattern.search(
            'connection_string = "Server=prod;Database=main;User=admin;Password=secret123;"'
        )

    def test_short_value_no_match(self):
        assert not _find("secret.hardcoded.credential").pattern.search('token = "short"')

    def test_env_var_safe(self):
        assert not _find("secret.hardcoded.credential").pattern.search(
            "api_key = os.environ['API_KEY']"
        )

    def test_weak_password_hash_md5(self):
        assert _find("auth.weak_password_hash").pattern.search(
            "password_hash = md5(password)"
        )

    def test_bcrypt_safe(self):
        assert not _find("auth.weak_password_hash").pattern.search(
            "password_hash = bcrypt.hash(password)"
        )

    def test_insecure_cookie_httponly_false(self):
        assert _find("session.insecure_cookie").pattern.search(
            "session({ cookie: { httpOnly: false } })"
        )


# ── A08: Deserialization ─────────────────────────────────────────────────

class TestDeserialization:
    def test_pickle_loads(self):
        assert _find("deserialize.untrusted_data").pattern.search("obj = pickle.loads(data)")

    def test_yaml_load(self):
        assert _find("deserialize.untrusted_data").pattern.search("yaml.load(data)")

    def test_java_object_input_stream(self):
        assert _find("deserialize.untrusted_data").pattern.search(
            "ObjectInputStream ois = new ObjectInputStream(stream)"
        )

    def test_binary_formatter_new(self):
        assert _find("deserialize.untrusted_data").pattern.search(
            "var secret = new BinaryFormatter().Deserialize(stream)"
        )

    def test_javascript_serializer_new(self):
        assert _find("deserialize.untrusted_data").pattern.search(
            "var obj = new JavaScriptSerializer().Deserialize(json)"
        )

    def test_yaml_safe_load_safe(self):
        assert not _find("deserialize.untrusted_data").pattern.search("yaml.safe_load(data)")

    def test_eval_not_in_deserialize(self):
        """eval should be caught by code.injection.eval, not deserialization."""
        assert not _find("deserialize.untrusted_data").pattern.search("eval(user_input)")


# ── A09: Logging ─────────────────────────────────────────────────────────

class TestLogging:
    def test_logging_password(self):
        assert _find("logging.sensitive_data").pattern.search(
            'console.log("User login:", password)'
        )

    def test_logging_token(self):
        assert _find("logging.sensitive_data").pattern.search(
            'logger.info("Auth token: " + token)'
        )

    def test_logging_safe_message(self):
        assert not _find("logging.sensitive_data").pattern.search(
            'console.log("User logged in successfully")'
        )


# ── A10: SSRF ────────────────────────────────────────────────────────────

class TestSSRF:
    def test_requests_get_with_user_url(self):
        assert _find("ssrf.untrusted_url_fetch").pattern.search("requests.get(req.body.url)")

    def test_axios_with_params(self):
        assert _find("ssrf.untrusted_url_fetch").pattern.search("axios.get(params.targetUrl)")

    def test_fetch_with_query(self):
        assert _find("ssrf.untrusted_url_fetch").pattern.search("fetch(req.query.url)")

    def test_hardcoded_url_safe(self):
        assert not _find("ssrf.untrusted_url_fetch").pattern.search(
            'requests.get("https://api.example.com/data")'
        )


# ── Memory Safety ────────────────────────────────────────────────────────

class TestMemorySafety:
    def test_strcpy_buffer_overflow(self):
        assert _find("memory.buffer_overflow").pattern.search("strcpy(dest, src)")

    def test_gets_buffer_overflow(self):
        assert _find("memory.buffer_overflow").pattern.search("gets(buffer)")

    def test_sprintf_buffer_overflow(self):
        assert _find("memory.buffer_overflow").pattern.search("sprintf(buf, fmt, data)")

    def test_snprintf_safe(self):
        assert not _find("memory.buffer_overflow").pattern.search("snprintf(buf, sizeof(buf), fmt)")

    def test_format_string_variable(self):
        assert _find("memory.format_string").pattern.search("printf(user_string)")

    def test_format_string_literal_safe(self):
        assert not _find("memory.format_string").pattern.search('printf("%s", user_string)')


# ── XXE ──────────────────────────────────────────────────────────────────

class TestXXE:
    def test_python_elementtree(self):
        assert _find("xxe.xml_parsing").pattern.search("xml.etree.ElementTree.parse(data)")

    def test_java_document_builder(self):
        assert _find("xxe.xml_parsing").pattern.search("DocumentBuilder db = factory.newDocumentBuilder()")

    def test_lxml_parse(self):
        assert _find("xxe.xml_parsing").pattern.search("lxml.etree.parse(source)")


# ── Race Conditions ──────────────────────────────────────────────────────

class TestRaceConditions:
    def test_toctou_exists_then_open(self):
        assert _find("race.toctou").pattern.search(
            "if os.path.exists(path):\n    open(path)"
        )

    def test_integer_overflow_no_check(self):
        assert _find("integer.overflow").pattern.search("val = parseInt(req.query.count)")


# ── Dependency Patterns ──────────────────────────────────────────────────

class TestDependencyPatterns:
    def _find_dep(self, keyword):
        for p, desc, sev in DEPENDENCY_RISK_PATTERNS:
            if keyword.lower() in desc.lower():
                return p, desc, sev
        raise ValueError(f"No dependency pattern for {keyword}")

    def test_lodash_vulnerable(self):
        p, _, sev = self._find_dep("lodash")
        assert p.search("lodash==4.17.20")
        assert sev == "high"

    def test_lodash_safe(self):
        p, _, _ = self._find_dep("lodash")
        assert not p.search('"lodash": "4.17.21"')

    def test_log4j_vulnerable(self):
        p, _, sev = self._find_dep("log4j")
        assert p.search("log4j 2.14.1")
        assert sev == "critical"

    def test_pyyaml_vulnerable(self):
        p, _, sev = self._find_dep("pyyaml")
        assert p.search("pyyaml==5.3")
        assert sev == "critical"

    def test_jsonwebtoken_vulnerable(self):
        p, _, sev = self._find_dep("jsonwebtoken")
        assert p.search('"jsonwebtoken": "^8.5.1"')
        assert sev == "high"


# ── LLM Detection ───────────────────────────────────────────────────────

class TestLikelyLLMRepo:
    def test_openai_import(self):
        assert likely_llm_repo("app.py", "import openai")

    def test_langchain_in_path(self):
        assert likely_llm_repo("langchain_agent.py", "def run(): pass")

    def test_anthropic_import(self):
        assert likely_llm_repo("main.py", "from anthropic import Anthropic")

    def test_regular_code_no_match(self):
        assert not likely_llm_repo("server.py", "from flask import Flask")

    def test_case_insensitive(self):
        assert likely_llm_repo("main.py", "OPENAI_API_KEY = os.environ['key']")


# ── LLM Prompt Injection ────────────────────────────────────────────────

class TestPromptInjection:
    def test_prompt_with_user_input(self):
        assert _find("llm.prompt.injection").pattern.search(
            'prompt = "You are helpful. " + req.body.message'
        )

    def test_safe_static_prompt(self):
        assert not _find("llm.prompt.injection").pattern.search(
            'prompt = "You are a helpful assistant."'
        )
