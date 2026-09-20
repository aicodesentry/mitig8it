const crypto = require('crypto');

const TRACE_STEP_KINDS = new Set(['source', 'assignment', 'call', 'sanitizer', 'sink']);

function calculateFingerprint(finding) {
  const data = [
    finding.rule_id,
    finding.file_path,
    String(finding.line_start || 0),
    (finding.code_snippet || '').trim(),
  ].join('|');
  return crypto.createHash('sha256').update(data).digest('hex');
}

function normalizeStringList(value) {
  if (value === undefined || value === null) return [];

  const values = Array.isArray(value) ? value : [value];
  const normalized = [];
  for (const item of values) {
    if (item === undefined || item === null) continue;
    if (typeof item === 'object' && !Array.isArray(item)) {
      for (const nested of Object.values(item)) {
        normalized.push(...normalizeStringList(nested));
      }
      continue;
    }
    const text = String(item).trim();
    if (!text) continue;
    if (!normalized.includes(text)) normalized.push(text);
  }
  return normalized;
}

function normalizeTaxonomyMappings(raw) {
  const input = raw.taxonomy_mappings || {};
  const cwe = normalizeStringList(input.cwe?.length ? input.cwe : raw.cwe_id);
  const owasp = normalizeStringList(input.owasp?.length ? input.owasp : raw.owasp_category);
  const attack = normalizeStringList(input.attack);
  const capec = normalizeStringList(input.capec);

  return { cwe, owasp, attack, capec };
}

function normalizeEvidenceDetails(raw) {
  const input = raw.evidence_details && typeof raw.evidence_details === 'object'
    ? raw.evidence_details
    : {};
  const analysisScope = raw.analysis_scope || input.analysis_scope || 'pattern';
  const sanitizers = normalizeStringList(
    raw.sanitizers_seen !== undefined ? raw.sanitizers_seen : input.sanitizer_exprs
  );
  const traceSteps = Array.isArray(input.trace_steps)
    ? input.trace_steps
      .filter((step) => step && typeof step === 'object')
      .map((step) => {
        const kind = String(step.kind || '').trim().toLowerCase();
        const expr = String(step.expr || '').trim();
        if (!TRACE_STEP_KINDS.has(kind) || !expr) return null;
        const normalized = {
          kind,
          label: String(step.label || kind).trim(),
          expr,
          file: step.file ? String(step.file).trim() : (raw.file_path || null),
          line: Number.isInteger(step.line) ? step.line : null,
        };
        if (step.status) normalized.status = String(step.status).trim();
        return normalized;
      })
      .filter(Boolean)
    : [];

  return {
    analysis_scope: analysisScope,
    is_taint_based: Boolean(
      raw.is_taint_based !== undefined
        ? raw.is_taint_based
        : (input.is_taint_based || String(analysisScope).startsWith('taint'))
    ),
    source_type: raw.source || input.source_type || null,
    source_expr: input.source_expr || null,
    sink_type: raw.sink || input.sink_type || null,
    sink_expr: input.sink_expr || null,
    sanitizer_exprs: sanitizers,
    sanitizer_status: input.sanitizer_status || (sanitizers.length ? 'present' : 'none'),
    trace_steps: traceSteps,
    trace_summary: raw.trace_summary || input.trace_summary || null,
    reviewability: input.reviewability || 'changed-lines-only',
    fix_scope: input.fix_scope || 'line',
    fix_target_line: Number.isInteger(input.fix_target_line) ? input.fix_target_line : null,
    fix_target_expr: input.fix_target_expr || null,
    missing_control_type: input.missing_control_type || null,
    auto_fix_eligible: Boolean(input.auto_fix_eligible),
    // Scanner-supplied scope markers, such as test-code classification. Kept
    // only when the scanner sent some, so findings without them are unchanged.
    ...(input.extra && typeof input.extra === 'object' && Object.keys(input.extra).length > 0
      ? { extra: input.extra }
      : {}),
  };
}

function normalizeFinding(raw) {
  const taxonomyMappings = normalizeTaxonomyMappings(raw);
  const evidenceDetails = normalizeEvidenceDetails(raw);
  const taxonomyVersions = raw.taxonomy_versions && typeof raw.taxonomy_versions === 'object'
    ? {
        cwe: raw.taxonomy_versions.cwe || null,
        attack: raw.taxonomy_versions.attack || null,
        capec: raw.taxonomy_versions.capec || null,
        owasp: raw.taxonomy_versions.owasp || null,
      }
    : {
        cwe: null,
        attack: null,
        capec: null,
        owasp: null,
      };

  return {
    rule_id: raw.rule_id,
    internal_type: raw.internal_type || raw.rule_id || 'security_issue',
    title: raw.title,
    description: raw.description,
    category: raw.category,
    cwe_id: taxonomyMappings.cwe[0] || raw.cwe_id || null,
    owasp_category: taxonomyMappings.owasp[0] || raw.owasp_category || null,
    taxonomy_mappings: taxonomyMappings,
    taxonomy_versions: taxonomyVersions,
    severity: (raw.severity || 'low').toLowerCase(),
    confidence: Math.max(0, Math.min(1, Number(raw.confidence || 0))),
    exploitability: raw.exploitability || 'medium',
    file_path: raw.file_path,
    line_start: raw.line_start || 1,
    line_end: raw.line_end || raw.line_start || 1,
    analysis_scope: evidenceDetails.analysis_scope,
    source: evidenceDetails.source_type,
    sink: evidenceDetails.sink_type,
    sanitizers_seen: evidenceDetails.sanitizer_exprs,
    trace_summary: evidenceDetails.trace_summary || '',
    evidence_details: evidenceDetails,
    code_snippet: raw.code_snippet || '',
    evidence: raw.evidence || raw.description || '',
    exploit_scenario: raw.exploit_scenario || '',
    remediation: raw.remediation || '',
    remediation_patch: raw.remediation_patch || '',
    fingerprint: raw.fingerprint || calculateFingerprint(raw),
  };
}

module.exports = {
  calculateFingerprint,
  normalizeFinding,
  normalizeEvidenceDetails,
  normalizeTaxonomyMappings,
};
