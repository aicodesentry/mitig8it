import yaml

from opengrep_runner import RULES_DIR
from taxonomy import (
    CWE_INTERNAL_TYPE_MAP,
    build_taxonomy_metadata,
    canonicalize_internal_type,
    is_canonical_internal_type,
)


class TestTaxonomyMappings:
    def test_builds_override_backed_metadata(self):
        taxonomy = build_taxonomy_metadata(
            rule_id="sql.injection.raw_query",
            category="SQL injection",
            cwe_id="CWE-89",
            owasp_category="A03:2021",
        )

        assert taxonomy["internal_type"] == "sql_injection"
        assert taxonomy["primary_cwe_id"] == "CWE-89"
        assert taxonomy["taxonomy_mappings"]["attack"] == ["T1190"]
        assert taxonomy["taxonomy_mappings"]["capec"] == ["CAPEC-66"]

    def test_preserves_explicit_attack_and_capec(self):
        taxonomy = build_taxonomy_metadata(
            rule_id="opengrep.custom.rule",
            category="security",
            cwe_id=["CWE-502"],
            owasp_category=["A08:2021"],
            internal_type="custom_deserialization",
            attack_techniques=["T1190"],
            capec_ids=["CAPEC-586"],
        )

        # A detector's own name for the type is not canonical, so the CWE decides it.
        assert taxonomy["internal_type"] == "unsafe_deserialization"
        assert taxonomy["taxonomy_mappings"]["cwe"] == ["CWE-502"]
        assert taxonomy["taxonomy_mappings"]["owasp"] == ["A08:2021"]
        assert taxonomy["taxonomy_mappings"]["attack"] == ["T1190"]
        assert taxonomy["taxonomy_mappings"]["capec"] == ["CAPEC-586"]

    def test_uses_safe_defaults_for_unknown_rule(self):
        taxonomy = build_taxonomy_metadata(
            rule_id="unknown.rule",
            category="security misconfiguration",
        )

        assert taxonomy["internal_type"] == "unknown_rule"
        assert taxonomy["taxonomy_mappings"] == {
            "cwe": [],
            "owasp": [],
            "attack": [],
            "capec": [],
        }

    def test_exec_in_javascript_maps_to_command_injection(self):
        taxonomy = build_taxonomy_metadata(
            rule_id="code.injection.eval",
            category="code injection",
            cwe_id="CWE-95",
            file_path="test_vuln.js",
            code_snippet="exec(req.query.cmd);",
        )

        assert taxonomy["internal_type"] == "command_injection"

    def test_ssl_context_protocol_maps_to_weak_tls_protocol(self):
        taxonomy = build_taxonomy_metadata(
            rule_id="opengrep.cwe-295.tls-trust-all",
            category="security",
            cwe_id="CWE-295",
            file_path="TestVuln.java",
            code_snippet='SSLContext ctx = SSLContext.getInstance("SSL");',
        )

        assert taxonomy["internal_type"] == "weak_tls_protocol"


class TestCanonicalInternalTypes:
    """A raw detector rule id is never a type.

    OpenGrep rules are named after the CWE they cover (`cwe-89.sql-template-literal`).
    Taking that name as the internal type gave tier 2 a different type from tier 1 for
    the same flaw, and the finding clusterer, which merges only within one type, kept
    both findings and published two suggestions on one line.
    """

    def test_opengrep_check_id_is_derived_from_the_cwe_not_taken_as_given(self):
        assert canonicalize_internal_type(
            rule_id="opengrep.cwe-89.sql-template-literal",
            category="SQL injection",
            explicit="cwe-89.sql-template-literal",
            cwe_id=["CWE-89"],
        ) == "sql_injection"

    def test_a_canonical_explicit_type_is_still_honoured(self):
        assert canonicalize_internal_type(
            rule_id="dependency.risk.version",
            category="dependency/package risk",
            explicit="dependency_version_risk",
            cwe_id=["CWE-1104"],
        ) == "dependency_version_risk"

    def test_is_canonical_internal_type_rejects_rule_ids_and_empty_values(self):
        assert is_canonical_internal_type("sql_injection")
        assert is_canonical_internal_type("  SQL_Injection  ")
        assert not is_canonical_internal_type("cwe-89.sql-template-literal")
        assert not is_canonical_internal_type("cwe-89")
        assert not is_canonical_internal_type("opengrep.custom.rule")
        assert not is_canonical_internal_type("security_issue")
        assert not is_canonical_internal_type("")
        assert not is_canonical_internal_type(None)

    def test_no_opengrep_rule_can_produce_a_raw_check_id_as_its_type(self):
        for path in sorted(RULES_DIR.glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for rule in document.get("rules", []):
                metadata = rule.get("metadata") or {}
                check_id = str(rule.get("id") or "")
                internal_type = build_taxonomy_metadata(
                    rule_id=f"opengrep.{check_id}",
                    category=metadata.get("category", "security"),
                    cwe_id=metadata.get("cwe"),
                    owasp_category=metadata.get("owasp"),
                    internal_type=metadata.get("internal_type"),
                    title=str(rule.get("message") or check_id),
                    description=str(rule.get("message") or ""),
                )["internal_type"]
                assert internal_type != check_id, f"{path.name}: {check_id}"
                assert is_canonical_internal_type(internal_type), f"{path.name}: {check_id} -> {internal_type}"

    def test_every_cwe_the_rule_files_use_maps_to_a_canonical_type(self):
        used = set()
        for path in sorted(RULES_DIR.glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for rule in document.get("rules", []):
                cwe = (rule.get("metadata") or {}).get("cwe")
                for value in cwe if isinstance(cwe, list) else [cwe]:
                    if value:
                        used.add(str(value).strip().upper())

        assert used, "the opengrep rule files declare no CWE at all"
        missing = sorted(cwe for cwe in used if cwe not in CWE_INTERNAL_TYPE_MAP)
        assert not missing, f"CWEs with no canonical internal type: {missing}"
        for cwe in sorted(used):
            assert is_canonical_internal_type(CWE_INTERNAL_TYPE_MAP[cwe]), cwe
