# Vulnerable corpus score

Run on 2026-10-25 at `26d956747fa9597be52ae4388c3a4210443a80a9` with the 23 pinned
repositories in `benchmarks/vulnerable-corpus/corpus.json`:

```bash
make recall-ratchet
.venv/analysis/bin/python scripts/replay/score.py scripts/replay/.cache/recall-results/*.json \
  --labels benchmarks/vulnerable-corpus/labels.json \
  --adjudications benchmarks/vulnerable-corpus/adjudications.json \
  --out docs/validation/vulnerable-corpus-2026-10-25.md
```

171 labels, 2513 findings.

## Headline

| | Findings | Labelled true | Hand true | Hand false | Precision |
| --- | ---: | ---: | ---: | ---: | ---: |
| What posts today | 470 | 114 | 38 | 26 | 0.85 |
| Quarantined rules | 2043 | 23 | 12 | 60 | 0.37 |
| Everything | 2513 | 137 | 50 | 86 | 0.68 |

Recall: 105/171 labelled vulnerabilities produced a finding of the expected class on the labelled lines (0.61). A further 12 had the expected class reported elsewhere in the same file, and 7 were reported on the labelled lines under a different class.

## Manual review of XSS and command-injection labels

The 32 cross-site-scripting and 11 command-injection labels were reread against their pinned
source evidence, and every scanner overlap was compared with the labelled line. This review is
an adjudication of those labels and overlaps; it does not turn the hundreds of unrelated unread
findings into precision evidence.

**Cross-site scripting.** The 26 line hits are genuine unsafe rendering or disabled-escaping
shapes. They are carried by the current rules
`opengrep.cwe-79.js-angular-bypass-security-trust`,
`opengrep.cwe-79.tpl-ejs-unescaped-output`,
`opengrep.cwe-79.tpl-unescaping-filter`,
`opengrep.cwe-79.js-html-string-interpolated`,
`opengrep.cwe-79.tpl-inline-script-inner-html`,
`opengrep.cwe-79.py-html-percent-format`,
`opengrep.cwe-79.js-template-autoescape-disabled`, and `xss.unsafe_html_render`.
The surviving gaps are specific rather than an unsupported file family: NodeGoat's downstream
Swig `{{...}}` sinks depend on the separately detected global `autoescape: false`; dvpwa passes
`autoescape=False` through a multiline `setup_jinja` call the current rule does not model;
Juice Shop constructs a `<script>` body with string concatenation rather than interpolation; and
DSVW's JSONP callback uses nested percent formatting. The DSVW file has another XSS finding, but
not on the callback line.

**Command injection.** All six line hits are genuine shell-command construction and are carried
by `opengrep.cwe-78.child-process-exec`, `cmd.injection.shell_true`,
`opengrep.cwe-78.py-subprocess-shell-interpolated`, and
`opengrep.cwe-78.js-exec-interpolated`. The surviving misses are the three electerm sites, which
build a command in one statement and pass the variable to `run`/`runWinCmd` in the next, and the
multiline pygoat `Popen(command, shell=True)` site. The systeminformation label is detected only
elsewhere in its file. Reaching these without matching every `exec($VAR)` still requires a
bounded one-hop data-flow rule.

## Precision

### By rule

| Rule | Findings | Labelled true | Hand true | Hand false | Unread | Precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `null.pointer.deref` | 846 | 0 | 1 | 31 | 814 | 0.03 |
| `opengrep.cwe-79.js-html-string-interpolated` | 678 | 7 | 1 | 9 | 661 | 0.47 |
| `integer.overflow` | 156 | 0 | 0 | 2 | 154 | 0.00 |
| `authz.missing_function_level` | 128 | 0 | 0 | 6 | 122 | 0.00 |
| `rate_limit.missing` | 90 | 0 | 0 | 5 | 85 | 0.00 |
| `path.traversal.user_path` | 86 | 2 | 1 | 4 | 79 | 0.43 |
| `opengrep.cwe-1357.gha-third-party-action-unpinned` | 32 | 0 | 6 | 0 | 26 | 1.00 |
| `ssrf.untrusted_url_fetch` | 30 | 2 | 1 | 0 | 27 | 1.00 |
| `code.injection.eval` | 29 | 11 | 0 | 0 | 18 | 1.00 |
| `opengrep.cwe-352.py-csrf-exempt` | 25 | 1 | 1 | 0 | 23 | 1.00 |
| `concurrency.shared_state` | 24 | 0 | 0 | 0 | 24 | n/a |
| `crypto.insufficient_entropy` | 22 | 3 | 0 | 0 | 19 | 1.00 |
| `secret.entropy.credential_assignment` | 19 | 1 | 4 | 14 | 0 | 0.26 |
| `opengrep.cwe-78.js-exec-interpolated` | 18 | 2 | 0 | 0 | 16 | 1.00 |
| `deserialize.untrusted_data` | 17 | 8 | 1 | 0 | 8 | 1.00 |
| `nosql.injection` | 16 | 3 | 0 | 0 | 13 | 1.00 |
| `xss.unsafe_html_render` | 16 | 1 | 0 | 1 | 14 | 0.50 |
| `logging.sensitive_data` | 15 | 0 | 1 | 0 | 14 | 1.00 |
| `opengrep.cwe-79.tpl-inline-script-inner-html` | 15 | 1 | 4 | 0 | 10 | 1.00 |
| `opengrep.cwe-79.js-angular-bypass-security-trust` | 14 | 7 | 5 | 0 | 2 | 1.00 |
| `opengrep.cwe-79.py-html-percent-format` | 14 | 5 | 6 | 1 | 2 | 0.92 |
| `secret.hardcoded.credential` | 13 | 1 | 0 | 0 | 12 | 1.00 |
| `opengrep.cwe-79.tpl-unescaping-filter` | 12 | 2 | 5 | 3 | 2 | 0.70 |
| `secret.format.known_key` | 11 | 1 | 2 | 8 | 0 | 0.27 |
| `redirect.open` | 10 | 3 | 0 | 0 | 7 | 1.00 |
| `sql.injection.raw_query` | 10 | 4 | 0 | 0 | 6 | 1.00 |
| `auth.bypass.missing_check` | 8 | 0 | 0 | 1 | 7 | 0.00 |
| `opengrep.cwe-502.yaml-unsafe-load` | 8 | 7 | 0 | 0 | 1 | 1.00 |
| `opengrep.cwe-89.py-execute-concat-direct` | 8 | 8 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-798.js-credential-config-key` | 7 | 3 | 0 | 0 | 4 | 1.00 |
| `opengrep.cwe-943.js-mongo-where-operator` | 7 | 2 | 0 | 0 | 5 | 1.00 |
| `cmd.injection.shell_true` | 6 | 2 | 0 | 0 | 4 | 1.00 |
| `config.debug_enabled` | 6 | 2 | 0 | 0 | 4 | 1.00 |
| `crypto.weak.hash` | 6 | 1 | 1 | 0 | 4 | 1.00 |
| `opengrep.cwe-798.hardcoded-secret-js` | 6 | 1 | 0 | 1 | 4 | 0.50 |
| `xxe.xml_parsing` | 6 | 1 | 0 | 0 | 5 | 1.00 |
| `csrf.missing_protection` | 5 | 1 | 0 | 0 | 4 | 1.00 |
| `opengrep.cwe-502.pickle-loads` | 5 | 2 | 0 | 0 | 3 | 1.00 |
| `opengrep.cwe-614.insecure-cookie` | 5 | 1 | 0 | 0 | 4 | 1.00 |
| `opengrep.cwe-95.js-new-function-dynamic` | 5 | 1 | 0 | 0 | 4 | 1.00 |
| `opengrep.cwe-22.js-sendfile-request-path` | 4 | 4 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-327.weak-hash-password` | 4 | 3 | 0 | 0 | 1 | 1.00 |
| `opengrep.cwe-79.tpl-ejs-unescaped-output` | 4 | 4 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-89.sql-template-literal` | 4 | 1 | 0 | 0 | 3 | 1.00 |
| `opengrep.cwe-22.js-render-request-object-locals` | 3 | 1 | 2 | 0 | 0 | 1.00 |
| `opengrep.cwe-22.path-traversal-open` | 3 | 0 | 0 | 0 | 3 | n/a |
| `opengrep.cwe-798.py-credential-keyword-argument` | 3 | 0 | 1 | 0 | 2 | 1.00 |
| `auth.weak_password_hash` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `llm.prompt.injection` | 2 | 0 | 0 | 0 | 2 | n/a |
| `opengrep.cwe-22.js-archive-entry-write` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-22.path-traversal-fs` | 2 | 1 | 0 | 0 | 1 | 1.00 |
| `opengrep.cwe-22.py-path-join-request-value` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-22.py-pathlib-join-interpolated` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-489.py-debug-constant-true` | 2 | 1 | 0 | 0 | 1 | 1.00 |
| `opengrep.cwe-494.gha-remote-script-piped-to-shell` | 2 | 0 | 2 | 0 | 0 | 1.00 |
| `opengrep.cwe-502.py-pickle-load-file` | 2 | 0 | 1 | 0 | 1 | 1.00 |
| `opengrep.cwe-601.js-redirect-request-value` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-78.child-process-exec` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-798.js-session-secret-literal` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-798.py-framework-secret-key-literal` | 2 | 1 | 0 | 0 | 1 | 1.00 |
| `template.injection` | 2 | 0 | 0 | 0 | 2 | n/a |
| `config.tls_disabled` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-22.js-path-resolve-request-value` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-22.py-open-request-path` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-295.js-agent-reject-unauthorized-false` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-295.tls-disabled` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-338.py-random-module-secret` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-347.py-jwt-verification-disabled` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-489.py-flask-run-host-all-interfaces` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-502.js-node-serialize-unserialize` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-601.py-redirect-request-value` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-611.py-lxml-resolve-entities` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-614.js-session-cookie-insecure` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-78.command-injection-input` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-78.py-subprocess-shell-interpolated` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-79.js-template-autoescape-disabled` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-79.py-jinja-autoescape-off` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-79.tpl-mustache-triple-brace` | 1 | 0 | 1 | 0 | 0 | 1.00 |
| `opengrep.cwe-79.tpl-pug-unescaped-interpolation` | 1 | 0 | 1 | 0 | 0 | 1.00 |
| `opengrep.cwe-79.tpl-vue-v-html` | 1 | 0 | 1 | 0 | 0 | 1.00 |
| `opengrep.cwe-798.hardcoded-secret-assignment` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-798.js-credential-constant` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-89.js-query-string-concat` | 1 | 0 | 0 | 0 | 1 | n/a |
| `opengrep.cwe-918.py-urlopen-request-url` | 1 | 0 | 1 | 0 | 0 | 1.00 |
| `opengrep.cwe-918.ssrf-axios` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `opengrep.cwe-95.eval-injection` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `session.insecure_cookie` | 1 | 1 | 0 | 0 | 0 | 1.00 |

### By class

| Class | Findings | Labelled true | Hand true | Hand false | Unread | Precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `null_pointer_deref` | 845 | 0 | 1 | 31 | 813 | 0.03 |
| `cross_site_scripting` | 758 | 28 | 24 | 14 | 692 | 0.79 |
| `integer_overflow` | 156 | 0 | 0 | 2 | 154 | 0.00 |
| `authz_missing_function_level` | 128 | 0 | 0 | 6 | 122 | 0.00 |
| `path_traversal` | 106 | 15 | 3 | 4 | 84 | 0.82 |
| `rate_limit_missing` | 89 | 0 | 0 | 4 | 85 | 0.00 |
| `hardcoded_secret` | 65 | 10 | 7 | 23 | 25 | 0.42 |
| `command_injection` | 38 | 7 | 0 | 1 | 30 | 0.88 |
| `unsafe_deserialization` | 33 | 18 | 2 | 0 | 13 | 1.00 |
| `server_side_request_forgery` | 32 | 3 | 2 | 0 | 27 | 1.00 |
| `unpinned_action_reference` | 32 | 0 | 6 | 0 | 26 | 1.00 |
| `csrf_protection_disabled` | 30 | 2 | 1 | 0 | 27 | 1.00 |
| `dynamic_code_execution` | 27 | 13 | 0 | 0 | 14 | 1.00 |
| `concurrency_shared_state` | 24 | 0 | 0 | 0 | 24 | n/a |
| `insecure_randomness` | 23 | 4 | 0 | 0 | 19 | 1.00 |
| `nosql_injection` | 23 | 5 | 0 | 0 | 18 | 1.00 |
| `sql_injection` | 23 | 13 | 0 | 0 | 10 | 1.00 |
| `logging_sensitive_data` | 15 | 0 | 1 | 0 | 14 | 1.00 |
| `open_redirect` | 13 | 5 | 0 | 0 | 8 | 1.00 |
| `debug_mode_enabled` | 9 | 3 | 0 | 0 | 6 | 1.00 |
| `auth_bypass_missing_check` | 8 | 0 | 0 | 1 | 7 | 0.00 |
| `weak_password_hash` | 8 | 6 | 0 | 0 | 2 | 1.00 |
| `insecure_cookie_flags` | 7 | 3 | 0 | 0 | 4 | 1.00 |
| `xml_external_entity` | 7 | 2 | 0 | 0 | 5 | 1.00 |
| `weak_cipher_algorithm` | 4 | 0 | 1 | 0 | 3 | 1.00 |
| `tls_validation_disabled` | 3 | 0 | 0 | 0 | 3 | n/a |
| `llm_prompt_injection` | 2 | 0 | 0 | 0 | 2 | n/a |
| `remote_script_execution` | 2 | 0 | 2 | 0 | 0 | 1.00 |
| `server_side_template_injection` | 2 | 0 | 0 | 0 | 2 | n/a |
| `jwt_signature_not_verified` | 1 | 0 | 0 | 0 | 1 | n/a |

### By language

| Language | Findings | Labelled true | Hand true | Hand false | Unread | Precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `TypeScript` | 1469 | 41 | 9 | 55 | 1364 | 0.48 |
| `JavaScript` | 601 | 30 | 5 | 17 | 549 | 0.67 |
| `Python` | 363 | 59 | 16 | 11 | 277 | 0.87 |
| `other` | 45 | 0 | 8 | 0 | 37 | 1.00 |
| `Template` | 35 | 7 | 12 | 3 | 13 | 0.86 |

## Recall

### By expected class

| Group | Labels | Hit | In file | Located only | Missed | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `command_injection` | 11 | 6 | 1 | 0 | 4 | 0.55 |
| `cross_site_scripting` | 32 | 26 | 1 | 0 | 5 | 0.81 |
| `csrf_protection_disabled` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `debug_mode_enabled` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `dynamic_code_execution` | 10 | 9 | 1 | 0 | 0 | 0.90 |
| `error_detail_exposure` | 6 | 0 | 0 | 0 | 6 | 0.00 |
| `hardcoded_secret` | 18 | 7 | 4 | 0 | 7 | 0.39 |
| `insecure_cookie_flags` | 7 | 2 | 0 | 1 | 4 | 0.29 |
| `insecure_randomness` | 5 | 4 | 0 | 0 | 1 | 0.80 |
| `jwt_algorithm_none` | 1 | 0 | 0 | 1 | 0 | 0.00 |
| `jwt_signature_not_verified` | 1 | 0 | 0 | 0 | 1 | 0.00 |
| `nosql_injection` | 5 | 3 | 0 | 0 | 2 | 0.60 |
| `open_redirect` | 6 | 3 | 0 | 0 | 3 | 0.50 |
| `path_traversal` | 14 | 13 | 1 | 0 | 0 | 0.93 |
| `permissive_cors_policy` | 1 | 0 | 0 | 0 | 1 | 0.00 |
| `prototype_pollution` | 1 | 0 | 0 | 0 | 1 | 0.00 |
| `security_header_disabled` | 2 | 0 | 0 | 0 | 2 | 0.00 |
| `server_side_request_forgery` | 3 | 2 | 0 | 0 | 1 | 0.67 |
| `server_side_template_injection` | 4 | 1 | 1 | 1 | 1 | 0.25 |
| `sql_injection` | 14 | 11 | 2 | 0 | 1 | 0.79 |
| `unsafe_deserialization` | 11 | 11 | 0 | 0 | 0 | 1.00 |
| `weak_cipher_algorithm` | 1 | 0 | 1 | 0 | 0 | 0.00 |
| `weak_password_hash` | 11 | 3 | 0 | 4 | 4 | 0.27 |
| `xml_external_entity` | 4 | 1 | 0 | 0 | 3 | 0.25 |

### By CWE

| Group | Labels | Hit | In file | Located only | Missed | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `CWE-1004` | 5 | 0 | 0 | 1 | 4 | 0.00 |
| `CWE-1321` | 1 | 0 | 0 | 0 | 1 | 0.00 |
| `CWE-1336` | 4 | 1 | 1 | 1 | 1 | 0.25 |
| `CWE-209` | 6 | 0 | 0 | 0 | 6 | 0.00 |
| `CWE-22` | 14 | 13 | 1 | 0 | 0 | 0.93 |
| `CWE-256` | 1 | 0 | 0 | 0 | 1 | 0.00 |
| `CWE-321` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `CWE-327` | 2 | 0 | 1 | 1 | 0 | 0.00 |
| `CWE-328` | 2 | 0 | 0 | 2 | 0 | 0.00 |
| `CWE-330` | 3 | 2 | 0 | 0 | 1 | 0.67 |
| `CWE-338` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `CWE-347` | 2 | 0 | 0 | 1 | 1 | 0.00 |
| `CWE-352` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `CWE-489` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `CWE-502` | 12 | 12 | 0 | 0 | 0 | 1.00 |
| `CWE-601` | 6 | 3 | 0 | 0 | 3 | 0.50 |
| `CWE-611` | 4 | 1 | 0 | 0 | 3 | 0.25 |
| `CWE-614` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `CWE-693` | 2 | 0 | 0 | 0 | 2 | 0.00 |
| `CWE-78` | 11 | 6 | 1 | 0 | 4 | 0.55 |
| `CWE-79` | 32 | 26 | 1 | 0 | 5 | 0.81 |
| `CWE-798` | 17 | 6 | 4 | 0 | 7 | 0.35 |
| `CWE-89` | 14 | 11 | 2 | 0 | 1 | 0.79 |
| `CWE-916` | 7 | 3 | 0 | 1 | 3 | 0.43 |
| `CWE-918` | 3 | 2 | 0 | 0 | 1 | 0.67 |
| `CWE-94` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `CWE-942` | 1 | 0 | 0 | 0 | 1 | 0.00 |
| `CWE-943` | 5 | 3 | 0 | 0 | 2 | 0.60 |
| `CWE-95` | 6 | 5 | 1 | 0 | 0 | 0.83 |
| `CWE-98` | 1 | 1 | 0 | 0 | 0 | 1.00 |

### By repository

| Group | Labels | Hit | In file | Located only | Missed | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `Morgan-Phoenix/EnroCrypt` | 1 | 0 | 1 | 0 | 0 | 0.00 |
| `OWASP/NodeGoat` | 16 | 5 | 1 | 0 | 10 | 0.31 |
| `Stranger6667/pyanyapi` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `adeyosemanputra/pygoat` | 25 | 17 | 4 | 0 | 4 | 0.68 |
| `anxolerd/dvpwa` | 8 | 2 | 1 | 0 | 5 | 0.25 |
| `appsecco/dvna` | 14 | 10 | 0 | 2 | 2 | 0.71 |
| `benbusby/whoogle-search` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `commenthol/safer-eval` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `commenthol/serialize-to-js` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `dicebear/dicebear` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `electerm/electerm` | 3 | 0 | 0 | 0 | 3 | 0.00 |
| `google/slo-generator` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `illagrenan/django-make-app` | 1 | 1 | 0 | 0 | 0 | 1.00 |
| `juice-shop/juice-shop` | 43 | 26 | 1 | 3 | 13 | 0.60 |
| `kepano/defuddle` | 4 | 4 | 0 | 0 | 0 | 1.00 |
| `masci/banks` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `scitokens/scitokens` | 5 | 5 | 0 | 0 | 0 | 1.00 |
| `sebhildebrandt/systeminformation` | 1 | 0 | 1 | 0 | 0 | 0.00 |
| `snyk-labs/nodejs-goof` | 16 | 9 | 1 | 1 | 5 | 0.56 |
| `stamparm/DSVW` | 18 | 10 | 2 | 1 | 5 | 0.56 |
| `tadashi-aikawa/owlmixin` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `webcomics/dosage` | 2 | 2 | 0 | 0 | 0 | 1.00 |
| `zamotany/logkitty` | 2 | 2 | 0 | 0 | 0 | 1.00 |

### Labels with no finding of the expected class on the labelled lines

| Label | Repository | Path | Lines | Expected | Reported instead | In file |
| --- | --- | --- | ---: | --- | --- | --- |
| `cve-electerm-cmdi-cp` | electerm/electerm | `src/app/lib/fs.js` | 137-140 | command_injection | nothing | no |
| `cve-electerm-cmdi-mv` | electerm/electerm | `src/app/lib/fs.js` | 126-129 | command_injection | nothing | no |
| `cve-electerm-cmdi-rmrf` | electerm/electerm | `src/app/lib/fs.js` | 115-118 | command_injection | nothing | no |
| `cve-enrocrypt-md5` | Morgan-Phoenix/EnroCrypt | `enrocrypt/hashing.py` | 70-70 | weak_cipher_algorithm, weak_password_hash | nothing | yes |
| `cve-systeminformation-cmdi-networkinterfaces` | sebhildebrandt/systeminformation | `lib/network.js` | 551-552 | command_injection | nothing | yes |
| `dsvw-error-detail-traceback` | stamparm/DSVW | `dsvw.py` | 67-67 | error_detail_exposure | nothing | no |
| `dsvw-hardcoded-user-passwords` | stamparm/DSVW | `dsvw.py` | 9-9 | hardcoded_secret | nothing | no |
| `dsvw-insecure-random-sessionid` | stamparm/DSVW | `dsvw.py` | 62-62 | insecure_randomness | nothing | no |
| `dsvw-open-redirect` | stamparm/DSVW | `dsvw.py` | 70-70 | open_redirect | nothing | no |
| `dsvw-path-param-file-and-fetch` | stamparm/DSVW | `dsvw.py` | 29-29 | path_traversal, server_side_request_forgery | command_injection | yes |
| `dsvw-ssti-tmpl-format` | stamparm/DSVW | `dsvw.py` | 55-55 | server_side_template_injection | cross_site_scripting | no |
| `dsvw-xss-jsonp-callback` | stamparm/DSVW | `dsvw.py` | 59-59 | cross_site_scripting | sql_injection | yes |
| `dsvw-xss-protection-header-off` | stamparm/DSVW | `dsvw.py` | 73-73 | security_header_disabled | nothing | no |
| `dvna-a2-md5-reset-token-get` | appsecco/dvna | `core/authHandler.js` | 49-49 | weak_password_hash, insecure_randomness | weak_cipher_algorithm | no |
| `dvna-a2-md5-reset-token-post` | appsecco/dvna | `core/authHandler.js` | 78-78 | weak_password_hash, insecure_randomness | null_pointer_deref | no |
| `dvna-a4-xxe-bulkproducts` | appsecco/dvna | `core/appHandler.js` | 235-235 | xml_external_entity | nothing | no |
| `dvna-a6-error-detail-exposure-modifyproduct` | appsecco/dvna | `core/appHandler.js` | 128-129 | error_detail_exposure | nothing | no |
| `dvpwa-error-detail-exposure` | anxolerd/dvpwa | `sqli/templates/errors/50x.jinja2` | 6-6 | error_detail_exposure | nothing | no |
| `dvpwa-hardcoded-db-password` | anxolerd/dvpwa | `config/dev.yaml` | 1-3 | hardcoded_secret | nothing | no |
| `dvpwa-jinja2-autoescape-off` | anxolerd/dvpwa | `sqli/app.py` | 33-35 | cross_site_scripting | nothing | no |
| `dvpwa-md5-password-fixtures` | anxolerd/dvpwa | `migrations/001-fixtures.sql` | 10-13 | weak_password_hash | nothing | no |
| `dvpwa-session-cookie-httponly-off` | anxolerd/dvpwa | `sqli/middlewares.py` | 20-20 | insecure_cookie_flags | nothing | no |
| `dvpwa-sqli-student-create` | anxolerd/dvpwa | `sqli/dao/student.py` | 42-43 | sql_injection | nothing | yes |
| `goof-dustjs-template-injection-about-new` | snyk-labs/nodejs-goof | `views/about_new.dust` | 4-4 | server_side_template_injection, dynamic_code_execution | nothing | no |
| `goof-errorhandler-stack-exposure` | snyk-labs/nodejs-goof | `app.js` | 79-81 | error_detail_exposure, debug_mode_enabled | nothing | no |
| `goof-hardcoded-api-token` | snyk-labs/nodejs-goof | `app.js` | 83-83 | hardcoded_secret | logging_sensitive_data | yes |
| `goof-hardcoded-mysql-credentials` | snyk-labs/nodejs-goof | `typeorm-db.js` | 11-12 | hardcoded_secret | nothing | no |
| `goof-open-redirect-login` | snyk-labs/nodejs-goof | `routes/index.js` | 73-74 | open_redirect | nothing | no |
| `goof-prototype-pollution-chat-merge` | snyk-labs/nodejs-goof | `routes/index.js` | 360-360 | prototype_pollution | nothing | no |
| `goof-session-cookie-missing-httponly` | snyk-labs/nodejs-goof | `app.js` | 42-46 | insecure_cookie_flags | hardcoded_secret | no |
| `juice-csp-unsafe-eval-userprofile` | juice-shop/juice-shop | `routes/userProfile.ts` | 91-91 | security_header_disabled | nothing | no |
| `juice-hardcoded-hashids-salt` | juice-shop/juice-shop | `routes/restoreProgress.ts` | 18-18 | hardcoded_secret | nothing | no |
| `juice-hardcoded-hmac-key` | juice-shop/juice-shop | `lib/insecurity.ts` | 42-42 | hardcoded_secret | nothing | yes |
| `juice-hardcoded-wallet-mnemonic` | juice-shop/juice-shop | `routes/checkKeys.ts` | 10-10 | hardcoded_secret | nothing | no |
| `juice-insecure-cookie-token-insecurity` | juice-shop/juice-shop | `lib/insecurity.ts` | 192-192 | insecure_cookie_flags | nothing | no |
| `juice-insecure-cookie-token-profile` | juice-shop/juice-shop | `routes/updateUserProfile.ts` | 42-42 | insecure_cookie_flags | nothing | no |
| `juice-jwt-decode-without-verify` | juice-shop/juice-shop | `lib/insecurity.ts` | 56-56 | jwt_signature_not_verified | nothing | no |
| `juice-jwt-no-algorithm-pinning` | juice-shop/juice-shop | `lib/insecurity.ts` | 52-52 | jwt_algorithm_none | insecure_randomness | no |
| `juice-md5-hash-helper` | juice-shop/juice-shop | `lib/insecurity.ts` | 41-41 | weak_password_hash | null_pointer_deref | no |
| `juice-md5-user-password-setter` | juice-shop/juice-shop | `models/user.ts` | 73-73 | weak_password_hash | nothing | no |
| `juice-nosqli-updatereviews` | juice-shop/juice-shop | `routes/updateProductReviews.ts` | 17-20 | nosql_injection | nothing | no |
| `juice-openredirect-allowlist-includes` | juice-shop/juice-shop | `lib/insecurity.ts` | 136-136 | open_redirect | nothing | no |
| `juice-permissive-cors` | juice-shop/juice-shop | `server.ts` | 182-183 | permissive_cors_policy | nothing | no |
| `juice-sha1-ctf-flag-hmac` | juice-shop/juice-shop | `lib/utils.ts` | 80-80 | weak_password_hash | null_pointer_deref | no |
| `juice-sqli-login` | juice-shop/juice-shop | `routes/login.ts` | 34-34 | sql_injection | nothing | no |
| `juice-xss-video-subtitles` | juice-shop/juice-shop | `routes/videoHandler.ts` | 71-71 | cross_site_scripting | nothing | no |
| `juice-xxe-parser-options` | juice-shop/juice-shop | `lib/xml.ts` | 35-35 | xml_external_entity | nothing | no |
| `nodegoat-a1-nosql-allocations-threshold` | OWASP/NodeGoat | `app/data/allocations-dao.js` | 77-79 | nosql_injection | nothing | no |
| `nodegoat-a2-hardcoded-admin-password-seed` | OWASP/NodeGoat | `artifacts/db-reset.js` | 18-18 | hardcoded_secret | nothing | no |
| `nodegoat-a2-plaintext-password-storage` | OWASP/NodeGoat | `app/data/user-dao.js` | 20-25 | weak_password_hash | nothing | no |
| `nodegoat-a3-session-cookie-flags` | OWASP/NodeGoat | `server.js` | 78-82 | insecure_cookie_flags | nothing | no |
| `nodegoat-a3-xss-memos-marked` | OWASP/NodeGoat | `app/views/memos.html` | 31-31 | cross_site_scripting | nothing | no |
| `nodegoat-a3-xss-profile-website-url-context` | OWASP/NodeGoat | `app/views/profile.html` | 78-78 | cross_site_scripting | nothing | no |
| `nodegoat-a3-xss-stored-name-layout-menu` | OWASP/NodeGoat | `app/views/layout.html` | 75-75 | cross_site_scripting | nothing | no |
| `nodegoat-a5-error-stack-render` | OWASP/NodeGoat | `app/routes/error.js` | 10-12 | error_detail_exposure | nothing | no |
| `nodegoat-a5-error-template-output` | OWASP/NodeGoat | `app/views/error-template.html` | 11-11 | error_detail_exposure, cross_site_scripting | nothing | no |
| `nodegoat-a6-hardcoded-crypto-key` | OWASP/NodeGoat | `config/env/all.js` | 9-9 | hardcoded_secret | nothing | yes |
| `nodegoat-ssrf-research` | OWASP/NodeGoat | `app/routes/research.js` | 15-16 | server_side_request_forgery | nothing | no |
| `pygoat-command-injection-cmd-lab` | adeyosemanputra/pygoat | `introduction/views.py` | 430-432 | command_injection | nothing | no |
| `pygoat-customhash-crypto-failure-lab2` | adeyosemanputra/pygoat | `introduction/utility.py` | 58-59 | weak_password_hash | nothing | no |
| `pygoat-hardcoded-jwt-secret-mitre` | adeyosemanputra/pygoat | `introduction/mitre.py` | 169-169 | hardcoded_secret | nothing | no |
| `pygoat-imagemath-eval-a9-lab2` | adeyosemanputra/pygoat | `introduction/views.py` | 588-588 | dynamic_code_execution | nothing | yes |
| `pygoat-jwt-cookie-key` | adeyosemanputra/pygoat | `pygoat/settings.py` | 171-171 | hardcoded_secret | nothing | yes |
| `pygoat-sqli-2021-injection-lab` | adeyosemanputra/pygoat | `introduction/views.py` | 864-864 | sql_injection | hardcoded_secret | yes |
| `pygoat-ssti-blog-render` | adeyosemanputra/pygoat | `introduction/views.py` | 1006-1006 | server_side_template_injection, path_traversal | nothing | yes |
| `pygoat-xxe-external-entities` | adeyosemanputra/pygoat | `introduction/views.py` | 258-260 | xml_external_entity | nothing | no |
