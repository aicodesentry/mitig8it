from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union


TAXONOMY_VERSIONS = {
    "cwe": "4.18",
    "attack": "17.0",
    "capec": "3.9",
    "owasp": "2021",
}


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


# The canonical internal type each CWE resolves to. This is the tier-independent
# derivation: tier 1 rules reach it through RULE_TAXONOMY_OVERRIDES and tier 2 opengrep
# rules through the CWE in their YAML metadata, so both tiers land on the same type for
# the same vulnerability and the finding clusterer can merge them.
#
# Insertion order is the resolution order when a finding carries several CWEs, so the
# first entry that matches wins and the result is deterministic.
CWE_INTERNAL_TYPE_MAP: Dict[str, str] = {
    "CWE-798": "hardcoded_secret",
    "CWE-502": "unsafe_deserialization",
    "CWE-89": "sql_injection",
    "CWE-78": "command_injection",
    "CWE-94": "dynamic_code_execution",
    "CWE-95": "dynamic_code_execution",
    "CWE-295": "tls_validation_disabled",
    "CWE-79": "cross_site_scripting",
    "CWE-22": "path_traversal",
    "CWE-918": "server_side_request_forgery",
    "CWE-943": "nosql_injection",
    "CWE-90": "ldap_injection",
    "CWE-601": "open_redirect",
    "CWE-327": "weak_cryptography",
    "CWE-434": "unrestricted_file_upload",
    "CWE-489": "debug_feature_enabled",
    "CWE-611": "xml_external_entity",
    "CWE-614": "insecure_cookie",
    "CWE-916": "weak_password_hash",
    "CWE-942": "permissive_cors",
    "CWE-1104": "dependency_version_risk",
    "CWE-1336": "server_side_template_injection",
}


# Every internal type the product reasons about, from the tier 1 rule overrides and the
# CWE map plus the types only the text heuristics produce. A value outside this set is a
# detector's own rule id rather than a type, and is derived rather than trusted.
#
# "security_issue" stays out on purpose: it is the last-resort return value, not a claim
# about the vulnerability, so a detector that offers it is still asked to derive a type.
CANONICAL_INTERNAL_TYPES = frozenset(
    {
        str(override["internal_type"])
        for override in RULE_TAXONOMY_OVERRIDES.values()
        if override.get("internal_type")
    }
    | set(CWE_INTERNAL_TYPE_MAP.values())
    | {"weak_tls_protocol"}
)


def is_canonical_internal_type(value: Optional[str]) -> bool:
    """True only for a canonical internal type, never for a raw detector rule id.

    A rule id such as `cwe-89.sql-template-literal` carries a dot or a `cwe-` prefix and
    is not in the canonical set, so it is rejected here and the caller falls through to
    the CWE and rule-id derivation.
    """
    if not value:
        return False
    text = str(value).strip().lower()
    if not text or "." in text or text.startswith("cwe-"):
        return False
    return text in CANONICAL_INTERNAL_TYPES


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
    "CWE-434": ["T1190"],
    "CWE-502": ["T1190"],
    "CWE-532": [],
    "CWE-611": ["T1190"],
    "CWE-770": [],
    "CWE-798": ["T1552"],
    "CWE-862": ["T1190"],
    "CWE-918": ["T1190"],
}


CWE_CAPEC_MAP: Dict[str, List[str]] = {
    "CWE-22": ["CAPEC-126"],
    "CWE-78": ["CAPEC-88"],
    "CWE-79": ["CAPEC-63"],
    "CWE-89": ["CAPEC-66"],
    "CWE-90": ["CAPEC-136"],
    "CWE-95": [],
    "CWE-295": ["CAPEC-94"],
    "CWE-434": ["CAPEC-650"],
    "CWE-502": ["CAPEC-586"],
    "CWE-611": ["CAPEC-221"],
    "CWE-798": ["CAPEC-37"],
    "CWE-918": ["CAPEC-664"],
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
    cwe_ids = {str(value).strip().upper() for value in _as_list(cwe_id)}

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
    # Only a canonical type is trusted as given. A detector that passes its own rule id
    # (opengrep offers `cwe-89.sql-template-literal`) is derived from its CWE instead, so
    # both tiers name the same vulnerability the same way.
    if is_canonical_internal_type(explicit):
        return str(explicit).strip().lower()

    if "CWE-295" in cwe_ids and 'sslcontext.getinstance("ssl")' in text:
        return "weak_tls_protocol"
    for cwe, internal_type in CWE_INTERNAL_TYPE_MAP.items():
        if cwe in cwe_ids:
            return internal_type

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
