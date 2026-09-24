from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union


TAXONOMY_VERSIONS = {
    "cwe": "4.18",
    "attack": "17.0",
    "capec": "3.9",
    "owasp": "2021",
}


# The vocabulary a rule may name itself with. `internal_type` is what the product groups,
# deduplicates and reports on, so a rule that passes its own check id as the type makes a
# category of one that nothing else can join. A tier 2 rule must declare one of these;
# `tests/test_tier2_rule_metadata.py` enforces it.
#
# Adding a value here is a product decision, not a rule detail: it says the finding is a
# kind of thing worth telling a reviewer apart from its neighbours.
CANONICAL_INTERNAL_TYPES = frozenset({
    # Injection
    "sql_injection",
    "nosql_injection",
    "ldap_injection",
    "command_injection",
    "dynamic_code_execution",
    "server_side_template_injection",
    "cross_site_scripting",
    "xml_external_entity",
    # Data handling
    "unsafe_deserialization",
    "path_traversal",
    "server_side_request_forgery",
    "open_redirect",
    "prototype_pollution",
    # Secrets and cryptography
    "hardcoded_secret",
    "weak_password_hash",
    "weak_cipher_algorithm",
    "static_initialization_vector",
    "insecure_randomness",
    # Authentication and session
    "jwt_algorithm_none",
    "jwt_signature_not_verified",
    "jwt_expiration_ignored",
    "insecure_cookie_flags",
    "csrf_protection_disabled",
    # Transport and configuration
    "tls_validation_disabled",
    "weak_tls_protocol",
    "permissive_cors_policy",
    "security_header_disabled",
    "debug_mode_enabled",
    "error_detail_exposure",
})


RULE_TAXONOMY_OVERRIDES: Dict[str, Dict[str, Union[List[str], str]]] = {
    "secret.hardcoded.credential": {
        "internal_type": "hardcoded_secret",
        "attack": ["T1552"],
        "capec": ["CAPEC-37"],
    },
    "auth.weak_password_hash": {
        "internal_type": "weak_password_hash",
        "attack": ["T1110"],
    },
    "sql.injection.raw_query": {
        "internal_type": "sql_injection",
        "attack": ["T1190"],
        "capec": ["CAPEC-66"],
    },
    "cmd.injection.shell_true": {
        "internal_type": "command_injection",
        "attack": ["T1059"],
        "capec": ["CAPEC-88"],
    },
    "code.injection.eval": {
        "internal_type": "dynamic_code_execution",
        "attack": ["T1059"],
    },
    "xss.unsafe_html_render": {
        "internal_type": "cross_site_scripting",
        "capec": ["CAPEC-63"],
    },
    "nosql.injection": {
        "internal_type": "nosql_injection",
        "attack": ["T1190"],
        "capec": ["CAPEC-676"],
    },
    "ldap.injection": {
        "internal_type": "ldap_injection",
        "attack": ["T1190"],
        "capec": ["CAPEC-136"],
    },
    "template.injection": {
        "internal_type": "server_side_template_injection",
        "attack": ["T1190"],
        "capec": ["CAPEC-242"],
    },
    "deserialize.untrusted_data": {
        "internal_type": "unsafe_deserialization",
        "attack": ["T1190"],
        "capec": ["CAPEC-586"],
    },
    "config.tls_disabled": {
        "internal_type": "tls_validation_disabled",
        "attack": ["T1557"],
        "capec": ["CAPEC-94"],
    },
    "ssrf.untrusted_url_fetch": {
        "internal_type": "server_side_request_forgery",
        "attack": ["T1190"],
        "capec": ["CAPEC-664"],
    },
    "path.traversal.user_path": {
        "internal_type": "path_traversal",
        "attack": ["T1006"],
        "capec": ["CAPEC-126"],
    },
}


CWE_ATTACK_MAP: Dict[str, List[str]] = {
    "CWE-22": ["T1006"],
    "CWE-78": ["T1059"],
    "CWE-79": [],
    "CWE-89": ["T1190"],
    "CWE-90": ["T1190"],
    "CWE-94": ["T1059"],
    "CWE-95": ["T1059"],
    "CWE-209": [],
    "CWE-295": ["T1557"],
    "CWE-326": ["T1557"],
    "CWE-327": ["T1600"],
    "CWE-329": ["T1600"],
    "CWE-338": ["T1110"],
    "CWE-347": ["T1134"],
    "CWE-352": ["T1189"],
    "CWE-434": ["T1190"],
    "CWE-502": ["T1190"],
    "CWE-532": [],
    "CWE-601": ["T1189"],
    "CWE-611": ["T1190"],
    "CWE-613": ["T1134"],
    "CWE-614": ["T1539"],
    "CWE-770": [],
    "CWE-798": ["T1552"],
    "CWE-862": ["T1190"],
    "CWE-916": ["T1110"],
    "CWE-918": ["T1190"],
    "CWE-942": ["T1190"],
    "CWE-943": ["T1190"],
    "CWE-1275": ["T1539"],
    "CWE-1321": ["T1190"],
    "CWE-1336": ["T1190"],
}


CWE_CAPEC_MAP: Dict[str, List[str]] = {
    "CWE-22": ["CAPEC-126"],
    "CWE-78": ["CAPEC-88"],
    "CWE-79": ["CAPEC-63"],
    "CWE-89": ["CAPEC-66"],
    "CWE-90": ["CAPEC-136"],
    "CWE-95": [],
    "CWE-295": ["CAPEC-94"],
    "CWE-326": ["CAPEC-620"],
    "CWE-327": ["CAPEC-97"],
    "CWE-329": ["CAPEC-97"],
    "CWE-338": ["CAPEC-59"],
    "CWE-347": ["CAPEC-463"],
    "CWE-352": ["CAPEC-62"],
    "CWE-434": ["CAPEC-650"],
    "CWE-502": ["CAPEC-586"],
    "CWE-601": ["CAPEC-178"],
    "CWE-611": ["CAPEC-221"],
    "CWE-613": ["CAPEC-60"],
    "CWE-614": ["CAPEC-102"],
    "CWE-798": ["CAPEC-37"],
    "CWE-916": ["CAPEC-55"],
    "CWE-918": ["CAPEC-664"],
    "CWE-942": ["CAPEC-664"],
    "CWE-943": ["CAPEC-676"],
    "CWE-1321": ["CAPEC-77"],
    "CWE-1336": ["CAPEC-242"],
}


def _as_list(value: Optional[object]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        values = value
    else:
        values = [value]

    normalized: List[str] = []
    for item in values:
        if item is None:
            continue
        if isinstance(item, dict):
            for nested in item.values():
                normalized.extend(_as_list(nested))
            continue
        text = str(item).strip()
        if not text:
            continue
        normalized.append(text)
    return list(dict.fromkeys(normalized))


def _first(items: Iterable[str]) -> Optional[str]:
    for item in items:
        return item
    return None


def canonicalize_internal_type(
    *,
    rule_id: Optional[str],
    category: Optional[str],
    explicit: Optional[str],
    cwe_id: Optional[object] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    file_path: Optional[str] = None,
    code_snippet: Optional[str] = None,
) -> str:
    text = " ".join(
        part for part in [
            rule_id or "",
            category or "",
            explicit or "",
            title or "",
            description or "",
            code_snippet or "",
        ] if part
    ).lower()
    ext = Path(file_path or "").suffix.lower()
    cwe_ids = set(_as_list(cwe_id))

    # A rule that names a canonical type has already answered this question, and it knows
    # more than the token sniffing below does. `jwt.decode(token, verify=False)` contains
    # `verify=false`, which the TLS heuristic would otherwise read as a disabled
    # certificate check; the rule that matched it says `jwt_signature_not_verified` and is
    # right. The heuristics stay for rules that declare nothing, or declare their check id.
    if explicit in CANONICAL_INTERNAL_TYPES:
        return str(explicit)

    if any(token in text for token in ('sslcontext.getinstance("ssl")', "tlsv1", "sslv3", "weak tls", "weak ssl")):
        return "weak_tls_protocol"
    if ext in {".js", ".ts", ".jsx", ".tsx", ".php"} and "exec(" in text:
        return "command_injection"
    if any(token in text for token in ("process.start", "runtime.getruntime().exec", "child_process.exec", "system(", "shell_exec(", "passthru(", "exec.command", "os.system")):
        return "command_injection"
    if any(token in text for token in ("eval(", "assert(", "new function", "render_template_string")):
        return "dynamic_code_execution"
    if any(token in text for token in ("insecureskipverify", "verify=false", "rejectunauthorized", "servercertificatevalidationcallback", "trust-all", "trust_all")):
        return "tls_validation_disabled"
    if explicit and explicit not in {"exec", "eval", "security", "security_issue"}:
        return explicit

    if "CWE-798" in cwe_ids:
        return "hardcoded_secret"
    if "CWE-502" in cwe_ids:
        return "unsafe_deserialization"
    if "CWE-89" in cwe_ids:
        return "sql_injection"
    if "CWE-78" in cwe_ids:
        return "command_injection"
    if "CWE-95" in cwe_ids:
        return "dynamic_code_execution"
    if "CWE-295" in cwe_ids:
        if 'sslcontext.getinstance("ssl")' in text:
            return "weak_tls_protocol"
        return "tls_validation_disabled"
    if "CWE-79" in cwe_ids:
        return "cross_site_scripting"
    if "CWE-22" in cwe_ids:
        return "path_traversal"
    if "CWE-918" in cwe_ids:
        return "server_side_request_forgery"
    if "CWE-943" in cwe_ids:
        return "nosql_injection"
    if "CWE-90" in cwe_ids:
        return "ldap_injection"
    if "CWE-601" in cwe_ids:
        return "open_redirect"
    if "CWE-611" in cwe_ids:
        return "xml_external_entity"
    if "CWE-916" in cwe_ids:
        return "weak_password_hash"
    if "CWE-327" in cwe_ids:
        return "weak_cipher_algorithm"
    if "CWE-329" in cwe_ids:
        return "static_initialization_vector"
    if "CWE-330" in cwe_ids or "CWE-338" in cwe_ids:
        return "insecure_randomness"
    if "CWE-326" in cwe_ids:
        return "weak_tls_protocol"
    if "CWE-347" in cwe_ids:
        return "jwt_signature_not_verified"
    if "CWE-613" in cwe_ids:
        return "jwt_expiration_ignored"
    if "CWE-614" in cwe_ids or "CWE-1275" in cwe_ids:
        return "insecure_cookie_flags"
    if "CWE-352" in cwe_ids:
        return "csrf_protection_disabled"
    if "CWE-942" in cwe_ids:
        return "permissive_cors_policy"
    if "CWE-1321" in cwe_ids:
        return "prototype_pollution"
    if "CWE-1336" in cwe_ids:
        return "server_side_template_injection"
    if "CWE-489" in cwe_ids:
        return "debug_mode_enabled"
    if "CWE-209" in cwe_ids:
        return "error_detail_exposure"

    override = RULE_TAXONOMY_OVERRIDES.get(rule_id or "", {})
    if override.get("internal_type"):
        return str(override["internal_type"])
    if rule_id:
        return rule_id.replace(".", "_").replace("-", "_")
    if category:
        return str(category).strip().lower().replace("/", " ").replace("-", " ").replace(" ", "_")
    return "security_issue"


def build_taxonomy_metadata(
    *,
    rule_id: Optional[str],
    category: Optional[str] = None,
    cwe_id: Optional[object] = None,
    owasp_category: Optional[object] = None,
    internal_type: Optional[str] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    file_path: Optional[str] = None,
    code_snippet: Optional[str] = None,
    attack_techniques: Optional[object] = None,
    capec_ids: Optional[object] = None,
) -> Dict[str, object]:
    override = RULE_TAXONOMY_OVERRIDES.get(rule_id or "", {})

    cwe_ids = _as_list(cwe_id)
    owasp_refs = _as_list(owasp_category)
    attack_ids = _as_list(attack_techniques) or _as_list(override.get("attack"))
    capec = _as_list(capec_ids) or _as_list(override.get("capec"))

    if not attack_ids:
        for cwe in cwe_ids:
            attack_ids.extend(CWE_ATTACK_MAP.get(cwe, []))

    if not capec:
        for cwe in cwe_ids:
            capec.extend(CWE_CAPEC_MAP.get(cwe, []))

    mappings = {
        "cwe": list(dict.fromkeys(cwe_ids)),
        "owasp": list(dict.fromkeys(owasp_refs)),
        "attack": list(dict.fromkeys(attack_ids)),
        "capec": list(dict.fromkeys(capec)),
    }

    return {
        "internal_type": canonicalize_internal_type(
            rule_id=rule_id,
            category=category,
            explicit=internal_type,
            cwe_id=mappings["cwe"],
            title=title,
            description=description,
            file_path=file_path,
            code_snippet=code_snippet,
        ),
        "primary_cwe_id": _first(mappings["cwe"]),
        "primary_owasp_category": _first(mappings["owasp"]),
        "taxonomy_mappings": mappings,
        "taxonomy_versions": dict(TAXONOMY_VERSIONS),
    }
