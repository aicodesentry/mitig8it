const structPb = require('google-protobuf/google/protobuf/struct_pb');
const commonPb = require('../grpc/generated/common_pb');

function compact(value) {
  if (Array.isArray(value)) return value.map(compact);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, item]) => item !== undefined && item !== null && item !== '')
      .map(([key, item]) => [key, compact(item)])
  );
}

function changedFileToMessage(file = {}) {
  const message = new commonPb.ChangedFile();
  message.setPath(file.path || '');
  message.setPatch(file.patch || '');
  message.setContent(file.content || '');
  message.setAdditions(Number(file.additions || 0));
  message.setDeletions(Number(file.deletions || 0));
  message.setStatus(file.status || '');
  message.setRawUrl(file.raw_url || file.rawUrl || '');
  message.setReviewableLineSpansList((file.reviewable_line_spans || file.reviewableLineSpans || []).map((span) => {
    const item = new commonPb.ReviewableLineSpan();
    item.setStart(Number(span.start || 0));
    item.setEnd(Number(span.end || 0));
    return item;
  }));
  return message;
}

function changedFileToPlain(file) {
  return {
    path: file.getPath(),
    patch: file.getPatch(),
    content: file.getContent(),
    additions: file.getAdditions(),
    deletions: file.getDeletions(),
    status: file.getStatus(),
    raw_url: file.getRawUrl(),
    reviewable_line_spans: file.getReviewableLineSpansList().map((span) => ({
      start: span.getStart(),
      end: span.getEnd(),
    })),
  };
}

function taxonomyMappingsToMessage(value = {}) {
  const message = new commonPb.TaxonomyMappings();
  message.setCweList(value.cwe || []);
  message.setOwaspList(value.owasp || []);
  message.setAttackList(value.attack || []);
  message.setCapecList(value.capec || []);
  return message;
}

function taxonomyVersionsToMessage(value = {}) {
  const message = new commonPb.TaxonomyVersions();
  message.setCwe(value.cwe || '');
  message.setAttack(value.attack || '');
  message.setCapec(value.capec || '');
  message.setOwasp(value.owasp || '');
  return message;
}

function traceStepToMessage(step = {}) {
  const message = new commonPb.TraceStep();
  message.setKind(step.kind || '');
  message.setLabel(step.label || '');
  message.setExpr(step.expr || '');
  message.setFile(step.file || '');
  message.setLine(Number(step.line || 0));
  message.setStatus(step.status || '');
  return message;
}

function evidenceDetailsToMessage(value = {}) {
  const message = new commonPb.EvidenceDetails();
  message.setAnalysisScope(value.analysis_scope || value.analysisScope || '');
  message.setIsTaintBased(Boolean(value.is_taint_based || value.isTaintBased));
  message.setSourceType(value.source_type || value.sourceType || '');
  message.setSourceExpr(value.source_expr || value.sourceExpr || '');
  message.setSinkType(value.sink_type || value.sinkType || '');
  message.setSinkExpr(value.sink_expr || value.sinkExpr || '');
  message.setSanitizerExprsList(value.sanitizer_exprs || value.sanitizerExprsList || []);
  message.setSanitizerStatus(value.sanitizer_status || value.sanitizerStatus || '');
  message.setTraceStepsList((value.trace_steps || value.traceStepsList || []).map(traceStepToMessage));
  message.setTraceSummary(value.trace_summary || value.traceSummary || '');
  message.setReviewability(value.reviewability || '');
  message.setTraceQuality(value.trace_quality || value.traceQuality || '');
  message.setEvidenceStrength(value.evidence_strength || value.evidenceStrength || '');
  message.setConfidenceBasis(value.confidence_basis || value.confidenceBasis || '');
  message.setFixScope(value.fix_scope || value.fixScope || '');
  message.setFixTargetLine(Number(value.fix_target_line || value.fixTargetLine || 0));
  message.setFixTargetExpr(value.fix_target_expr || value.fixTargetExpr || '');
  message.setMissingControlType(value.missing_control_type || value.missingControlType || '');
  message.setAutoFixEligible(Boolean(value.auto_fix_eligible || value.autoFixEligible));
  if (value.extra && typeof value.extra === 'object') {
    message.setExtra(structPb.Struct.fromJavaScript(value.extra));
  }
  return message;
}

function findingToMessage(finding = {}) {
  const message = new commonPb.Finding();
  message.setRuleId(finding.rule_id || finding.ruleId || '');
  message.setInternalType(finding.internal_type || finding.internalType || '');
  message.setTitle(finding.title || '');
  message.setDescription(finding.description || '');
  message.setCategory(finding.category || '');
  message.setCweId(finding.cwe_id || finding.cweId || '');
  message.setOwaspCategory(finding.owasp_category || finding.owaspCategory || '');
  message.setTaxonomyMappings(taxonomyMappingsToMessage(finding.taxonomy_mappings || finding.taxonomyMappings || {}));
  message.setTaxonomyVersions(taxonomyVersionsToMessage(finding.taxonomy_versions || finding.taxonomyVersions || {}));
  message.setSeverity(finding.severity || '');
  message.setConfidence(Number(finding.confidence || 0));
  message.setExploitability(finding.exploitability || '');
  message.setFilePath(finding.file_path || finding.filePath || '');
  message.setLineStart(Number(finding.line_start || finding.lineStart || 0));
  message.setLineEnd(Number(finding.line_end || finding.lineEnd || 0));
  message.setCodeSnippet(finding.code_snippet || finding.codeSnippet || '');
  message.setAnalysisScope(finding.analysis_scope || finding.analysisScope || '');
  message.setSource(finding.source || '');
  message.setSink(finding.sink || '');
  message.setSanitizersSeenList(finding.sanitizers_seen || finding.sanitizersSeenList || []);
  message.setTraceSummary(finding.trace_summary || finding.traceSummary || '');
  message.setEvidenceDetails(evidenceDetailsToMessage(finding.evidence_details || finding.evidenceDetails || {}));
  message.setEvidence(finding.evidence || '');
  message.setExploitScenario(finding.exploit_scenario || finding.exploitScenario || '');
  message.setRemediation(finding.remediation || '');
  message.setRemediationPatch(finding.remediation_patch || finding.remediationPatch || '');
  message.setFingerprint(finding.fingerprint || '');
  return message;
}

function evidenceExtraToPlain(finding) {
  const details = typeof finding.getEvidenceDetails === 'function' ? finding.getEvidenceDetails() : null;
  const extra = details && typeof details.getExtra === 'function' ? details.getExtra() : null;
  if (!extra) return undefined;
  const plain = extra.toJavaScript();
  return plain && typeof plain === 'object' && Object.keys(plain).length > 0 ? plain : undefined;
}

function findingToPlain(finding) {
  const object = finding.toObject();
  const evidenceExtra = evidenceExtraToPlain(finding);
  return compact({
    rule_id: object.ruleId,
    internal_type: object.internalType,
    title: object.title,
    description: object.description,
    category: object.category,
    cwe_id: object.cweId,
    owasp_category: object.owaspCategory,
    taxonomy_mappings: object.taxonomyMappings ? {
      cwe: object.taxonomyMappings.cweList || [],
      owasp: object.taxonomyMappings.owaspList || [],
      attack: object.taxonomyMappings.attackList || [],
      capec: object.taxonomyMappings.capecList || [],
    } : undefined,
    taxonomy_versions: object.taxonomyVersions ? {
      cwe: object.taxonomyVersions.cwe,
      attack: object.taxonomyVersions.attack,
      capec: object.taxonomyVersions.capec,
      owasp: object.taxonomyVersions.owasp,
    } : undefined,
    severity: object.severity,
    confidence: object.confidence,
    exploitability: object.exploitability,
    file_path: object.filePath,
    line_start: object.lineStart,
    line_end: object.lineEnd,
    code_snippet: object.codeSnippet,
    analysis_scope: object.analysisScope,
    source: object.source,
    sink: object.sink,
    sanitizers_seen: object.sanitizersSeenList || [],
    trace_summary: object.traceSummary,
    evidence_details: object.evidenceDetails ? {
      analysis_scope: object.evidenceDetails.analysisScope,
      is_taint_based: object.evidenceDetails.isTaintBased,
      source_type: object.evidenceDetails.sourceType,
      source_expr: object.evidenceDetails.sourceExpr,
      sink_type: object.evidenceDetails.sinkType,
      sink_expr: object.evidenceDetails.sinkExpr,
      sanitizer_exprs: object.evidenceDetails.sanitizerExprsList || [],
      sanitizer_status: object.evidenceDetails.sanitizerStatus,
      trace_steps: (object.evidenceDetails.traceStepsList || []).map((step) => compact({
        kind: step.kind,
        label: step.label,
        expr: step.expr,
        file: step.file,
        line: step.line,
        status: step.status,
      })),
      trace_summary: object.evidenceDetails.traceSummary,
      reviewability: object.evidenceDetails.reviewability,
      trace_quality: object.evidenceDetails.traceQuality,
      evidence_strength: object.evidenceDetails.evidenceStrength,
      confidence_basis: object.evidenceDetails.confidenceBasis,
      fix_scope: object.evidenceDetails.fixScope,
      fix_target_line: object.evidenceDetails.fixTargetLine,
      fix_target_expr: object.evidenceDetails.fixTargetExpr,
      missing_control_type: object.evidenceDetails.missingControlType,
      auto_fix_eligible: object.evidenceDetails.autoFixEligible,
      extra: evidenceExtra,
    } : undefined,
    evidence: object.evidence,
    exploit_scenario: object.exploitScenario,
    remediation: object.remediation,
    remediation_patch: object.remediationPatch,
    fingerprint: object.fingerprint,
  });
}

module.exports = {
  changedFileToMessage,
  changedFileToPlain,
  findingToMessage,
  findingToPlain,
};
