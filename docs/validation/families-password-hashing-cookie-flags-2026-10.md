# Two repair families: password hashing and cookie flags

Written 2026-10-17, on `feat/families-weak-hash-cookie-flags`.

## Why

`weak_password_hash` and `insecure_cookie_flags` were found and never repaired. Their recall on
the September corpus is 0.27 and 0.29
([vulnerable-corpus-2026-09.md](vulnerable-corpus-2026-09.md), "Recall"), and when one was found
the engine skipped it as `unsupported_rule_family`: the reviewer got a comment and no fix. Both
repairs are mechanical, so both are now families, proven by execution in both toolchains, with
the same template-first path and generated proof every other executed family has. Detection did
not change; this branch does nothing about the recall numbers.

## What the families do

`password_hashing` takes a module's own password-hashing function whose body returns a fast
digest (MD5, SHA-1, SHA-256 and the rest of the SHA-2 family, hex or base64) of its one
parameter. The repair derives a salted scrypt key instead, stored as
`scrypt$<16-byte salt hex>$<32-byte key hex>`, from the standard library only: Node
`crypto.scryptSync` with `crypto.randomBytes`, Python `hashlib.scrypt` with `os.urandom`. Because
a salted hash differs on every call, `hash(attempt) === stored` can never be true again, so the
repair also adds a verifier (`verifyPasswordHash`, `verify_password_hash`, constant-time through
`crypto.timingSafeEqual` and `hmac.compare_digest`) and rewrites every comparison of the hash in
the module into a call to it.

`cookie_flags` takes the options a cookie is already set with and sets HttpOnly, Secure and
SameSite, keeping every other key as written: the `cookie` object of an express-session call,
the options of a cookie-session call, the third argument of `res.cookie`, and a Flask
`set_cookie` call. A Django setting (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`,
`CSRF_COOKIE_SECURE`) or the same key in a Flask `app.config` assigned False is turned to True.

SameSite is set to Lax, not Strict. Strict withholds the cookie on every top-level navigation
that starts on another site, so a user who follows a link from an email or a search result
arrives signed out. Lax still withholds the cookie from cross-site POSTs, frames and subresource
requests, which is what a CSRF attack needs, and it is what current browsers already apply to a
cookie that names no SameSite, so it does not change how a working application behaves. An
existing `sameSite: 'strict'` is kept.

## Named refusals

Every shape the site model does not recognize is refused with a code, never guessed at. Two
codes per family are properties of the code rather than of what the template recognizes, so
they are gates: the finding is skipped before any agent runs, and no model gets to try.

| Code | Family | Gate | Why |
| --- | --- | --- | --- |
| `password_hash_used_for_lookup` | password | yes | The digest is a key in a query (`WHERE password_hash = $2`). A salted hash never matches a lookup, so the fix is a query and schema change. |
| `password_hash_called_from_other_module` | password | yes | Another module imports and calls the function, and would compare a salted hash with a fresh one. |
| `cookie_samesite_none_is_deliberate` | cookie | yes | SameSite=None is how a cookie is made cross-site on purpose; choosing Lax would break the embed or sign-in it serves. |
| `password_hash_not_returned_by_function` | password | no | The digest is inline in a view or a larger function, not the return value of a one-statement hashing function. |
| `password_hash_in_method` | password | no | The function is a class method, which a proof cannot construct a receiver for. |
| `password_hash_function_not_single_parameter`, `password_hash_input_not_the_parameter` | password | no | The function takes a pepper or salt already, or digests something other than its parameter. |
| `password_digest_encoding_not_text` | password | no | `.digest()` returns bytes; the repair returns a string. |
| `password_verifier_not_found`, `password_comparison_not_rewritable` | password | no | No comparison in the module, or one whose operator or precedence the rewrite cannot keep. |
| `cookie_options_not_recognized`, `cookie_options_spread`, `cookie_flag_value_not_literal` | cookie | no | Options built elsewhere, a spread that could override the repair, or a flag computed at runtime. |
| `cookie_flags_passed_positionally` | cookie | no | `set_cookie` given its flags by position. |

Proof-only refusals: `password_hash_function_not_exported`, `password_verifier_not_callable`,
`cookie_route_not_found` (a `set_cookie` or `res.cookie` outside a route), and
`cookie_options_not_at_module_scope` (session middleware configured inside a function the import
never calls).

## What the proof asserts

Both harnesses gained a recorder for each family. The Node `crypto` module and the Python
`hashlib` module are the real ones with every digest and key derivation recorded, along with
what it was fed. The express-session and cookie-session packages are faked (so a module that
requires them now loads in the sandbox), `res.cookie` and Flask `set_cookie` record their
options, and the Flask fake's `app.config` answers `from_object` and its siblings.

A password proof hashes one password twice and requires the two values to differ, requires
that the password never reached a fast digest and did reach scrypt or PBKDF2
(`h.assert.passwordHash`, `h.assert_password_hash`), and requires the module's own verifier to
accept the password against the first hash and reject a wrong one. The second clause is what
stops `md5(salt + password)`, which differs per call; the third is what stops a repair that
salts the hash and breaks every login. Both are tested as failing repairs.

A cookie proof loads the module (session middleware), invokes the route (`res.cookie`, Flask
`set_cookie`), and requires every recorded cookie of that kind and name to carry
`httpOnly`/`secure` true and `sameSite` Lax or Strict (`h.assert.cookieFlags`,
`h.assert_cookie_flags`). A Django setting is read back off the loaded settings module, a Flask
key off `app.config`. A repair that sets only `secure` is tested as failing.

The Node harness is about 31 KiB of its 32 KiB budget and the Python harness about 39 of 40, so
the next recorder in either needs a budget change.

## Measured

Run on 2026-10-17, macOS on Apple silicon, Python 3.11.6, Node 24.1.0.

| Measurement | Result |
| --- | --- |
| New supported fixtures | 16: four per family per toolchain |
| New negative fixtures | 2: `js-password-lookup`, `js-cookie-samesite-none` |
| Template output equal to the reviewed repair | 16 of 16 |
| Generated proof fails on the original, passes on the reviewed repair, in the real harness | 16 of 16 |
| Trusted fixture test, original against reviewed repair (`tests/verify.*`) | 16 of 16 |
| Negatives skipped by the gate with the expected code | 2 of 2 |
| `make bench-remediation-reference` | 81 of 81 fixtures pass |
| `evaluate.py --adapter engine-local` | 81 of 81 pass: 67 verified (62 executed, 5 asserted), 14 abstained; precision, coverage and abstention 1.00 |
| Model calls made by the 16 new supported fixtures under engine-local | 0 |

The template path carried every new fixture: under the engine-local adapter each one was
verified with zero provider tokens, so the scripted provider was never consulted.

## Not measured

- **Reach on real code.** Nothing here was run against the 23-repository corpus. Reading the
  labelled lines in `benchmarks/vulnerable-corpus/labels.json` (read, not run) suggests the
  templates reach few of them: pygoat's `password = md5(password.encode()).hexdigest()` is inline
  in a view (`password_hash_not_returned_by_function`), dvpwa's `check_password` is a method
  (`password_hash_in_method`), and juice-shop's `hash` helper is imported by other modules and
  looked up in SQL. On cookies, dvna's `cookie: { secure: false }` is the recognized shape but its
  `server.js` requires packages the sandbox does not carry, and pygoat's `set_cookie(...,
  samesite=None, secure=False)` is rewritten but sits in a Django view, so its proof is refused
  as `cookie_route_not_found` and it can reach at most the static assertion. The September
  "Family reach on real vulnerabilities" run is what would turn this reading into a number:

  ```sh
  PY=~/.pyenv/versions/3.11.6/bin/python
  $PY scripts/replay/replay.py --snapshot --include-quarantined \
      --repo appsecco/dvna --ref <ref from labels.json> --out results/dvna.json
  # repeat for each repository in benchmarks/vulnerable-corpus/labels.json, then drive every
  # finding in a supported family through RepairEngine with the local sandbox driver and a
  # provider that refuses every call, as vulnerable-corpus-2026-09.md describes
  ```

- **Stored digests.** The password repair changes the stored format. Hashes stored before it no
  longer verify, and the stored value grows to 104 characters, which may not fit an existing
  column. The candidate's description says both; no fixture can observe either, because each
  starts from an empty store. A rehash-on-login migration would keep existing accounts working
  but needs the old digest in the code, which is the finding, and a write path the template
  cannot see.

- **Secure on plain HTTP.** A cookie marked Secure is not sent over HTTP, so a development
  server without TLS stops keeping its session after the repair. The description says so. No
  fixture runs a server.

- **A live model.** The model path for these families (a finding the template refuses for a
  reason that is not a gate) was not run: there is no model key locally. The agent's task
  message names the family's harness assertion, as for every family, but the Python system
  prompt's per-family paragraph was not extended for the two families, to stay inside the
  context budget the agent tests pin.

- **Precision of the producing rules.** Unchanged and not re-measured; the rules gained a
  `family` metadata key and nothing else.

## Gating

Both families are in the repair service's default `allowed_rule_families` and in the API
service's default policy, so a deployment with no explicit list repairs them. A deployment that
pins `REMEDIATION_ALLOWED_RULE_FAMILIES_JSON` (production does) leaves them off until the list
names them, and the capability report lists them under `rule_families_excluded_by_policy`.

## Reproduce

```sh
make test-remediation      # includes tests/test_password_hashing_family.py and tests/test_cookie_flags_family.py
make test-harness
make bench-remediation-reference
.venv/remediation/bin/python benchmarks/remediation/evaluate.py --suite seed --adapter engine-local \
    --output benchmarks/results/remediation-engine-local.json
cd services/analysis-service/src && ../../../.venv/analysis/bin/python -m pytest tests/test_tier2_rule_metadata.py tests/test_taxonomy.py
```
