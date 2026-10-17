const { isFixRejectedByCritic } = require('./findingUtils');

function normalizePatch(text) {
  if (!text) return '';

  let normalized = String(text).trim();
  if (!normalized) return '';

  const fencedMatch = normalized.match(/^```[a-zA-Z0-9_-]*\n([\s\S]*?)\n```$/);
  if (fencedMatch) {
    normalized = fencedMatch[1].trim();
  }

  return normalized.replace(/\r\n/g, '\n');
}

function extractReviewableLines(patch) {
  const reviewable = new Set();
  for (const span of extractReviewableLineSpans(patch)) {
    for (let line = span.start; line <= span.end; line += 1) {
      reviewable.add(line);
    }
  }

  return reviewable;
}

function extractReviewableLineSpans(patch) {
  const spans = [];
  if (!patch) return spans;

  let newLine = 0;
  let spanStart = null;
  let spanEnd = null;

  function flushSpan() {
    if (spanStart == null || spanEnd == null) return;
    spans.push({ start: spanStart, end: spanEnd });
    spanStart = null;
    spanEnd = null;
  }

  for (const rawLine of String(patch).split('\n')) {
    if (rawLine.startsWith('@@')) {
      flushSpan();
      const match = rawLine.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match) newLine = Number(match[1]);
      continue;
    }
    if (rawLine.startsWith('+++ ') || rawLine.startsWith('--- ')) {
      continue;
    }
    if (rawLine.startsWith('+')) {
      const lineNumber = newLine || 1;
      if (spanStart == null) {
        spanStart = lineNumber;
        spanEnd = lineNumber;
      } else if (lineNumber === spanEnd + 1) {
        spanEnd = lineNumber;
      } else {
        flushSpan();
        spanStart = lineNumber;
        spanEnd = lineNumber;
      }
      newLine += 1;
      continue;
    }
    flushSpan();
    if (!rawLine.startsWith('-')) {
      newLine += 1;
    }
  }

  flushSpan();
  return spans;
}

function extractAddedBlock(patch, lineStart, lineEnd) {
  if (!patch || !lineStart) return '';

  let newLine = 0;
  const collected = [];
  const maxLine = lineEnd || lineStart;

  for (const rawLine of String(patch).split('\n')) {
    if (rawLine.startsWith('@@')) {
      const match = rawLine.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match) newLine = Number(match[1]);
      continue;
    }
    if (rawLine.startsWith('+++ ') || rawLine.startsWith('--- ')) {
      continue;
    }
    if (rawLine.startsWith('+')) {
      if (newLine >= lineStart && newLine <= maxLine) {
        collected.push(rawLine.slice(1));
      }
      newLine += 1;
      continue;
    }
    if (!rawLine.startsWith('-')) {
      newLine += 1;
    }
  }

  return collected.join('\n').trim();
}

function snippetsOverlap(snippet, addedBlock) {
  const left = normalizePatch(snippet);
  const right = normalizePatch(addedBlock);
  if (!left || !right) return false;
  return left === right || left.includes(right) || right.includes(left);
}

function countMeaningfulLines(text) {
  return String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean).length;
}

function lineRange(start, end) {
  const first = Number(start) || 0;
  const last = Number(end) || first;
  if (first <= 0 || last < first) return [];

  const lines = [];
  for (let line = first; line <= last; line += 1) {
    lines.push(line);
  }
  return lines;
}

function includesBroadRewriteConstruct(text) {
  return String(text || '')
    .split('\n')
    .some((line) => /^(import\s+|from\s+\S+\s+import\s+|const\s+\S+\s*=\s*require\(|require\(|def\s+|class\s+|function\s+)/.test(line.trim()));
}

function looksLikeUnifiedDiff(text) {
  return String(text || '')
    .split('\n')
    .some((line) => /^(diff --git|index |@@|--- |\+\+\+ )/.test(line.trim()) || /^[+-][^=]/.test(line.trim()));
}

function looksLikeParameterizedQuery(text) {
  return /(\$\d+|%s|\?)/.test(text) || /\.query\([^,]+,\s*[[(]/.test(text);
}

function evidenceDetailsForFinding(finding) {
  if (!finding || typeof finding !== 'object') return {};
  const details = finding.evidence_details;
  return details && typeof details === 'object' ? details : {};
}

function normalizeFixScope(finding) {
  const scope = String(evidenceDetailsForFinding(finding).fix_scope || '').trim().toLowerCase();
  if (scope === 'line' || scope === 'block') return scope;
  return 'unknown';
}

function normalizeAutoFixEligible(finding) {
  const details = evidenceDetailsForFinding(finding);
  return Boolean(details.auto_fix_eligible);
}

function normalizeFixTargetLine(finding) {
  const details = evidenceDetailsForFinding(finding);
  const line = Number(details.fix_target_line || 0);
  return line > 0 ? line : null;
}

function normalizeFixTargetExpr(finding) {
  const details = evidenceDetailsForFinding(finding);
  const expr = String(details.fix_target_expr || '').trim();
  return expr || '';
}

function normalizeMissingControlType(finding) {
  const details = evidenceDetailsForFinding(finding);
  const control = String(details.missing_control_type || '').trim();
  return control || '';
}

function securityLibraries(repoProfile) {
  const deterministic = repoProfile?.deterministic || {};
  return Array.isArray(deterministic.security_libraries) ? deterministic.security_libraries : [];
}

function hasSecurityLibrary(repoProfile, libraryName) {
  return securityLibraries(repoProfile).some((entry) =>
    String(entry?.library || '').toLowerCase() === String(libraryName || '').toLowerCase()
  );
}

function hasValidationLibrary(repoProfile) {
  return securityLibraries(repoProfile).some((entry) =>
    String(entry?.purpose || '').toLowerCase() === 'input validation'
  );
}

function buildRepoAwareRemediation(finding, repoProfile) {
  const existing = String(finding?.remediation || '').trim();
  const missingControlType = normalizeMissingControlType(finding);
  const interpreted = repoProfile?.interpreted || {};
  const framework = String(repoProfile?.deterministic?.framework || '').trim();

  if (missingControlType === 'html_sanitization_or_safe_text_rendering') {
    if (hasSecurityLibrary(repoProfile, 'dompurify')) {
      return 'Use the repo\'s existing DOMPurify sanitization pattern before writing HTML, or prefer textContent if HTML is unnecessary.';
    }
    if (existing) return existing;
    return 'Sanitize untrusted HTML before rendering it, or switch to a safe text sink if HTML is not required.';
  }

  if (missingControlType === 'output_encoding') {
    if (hasSecurityLibrary(repoProfile, 'dompurify') || hasSecurityLibrary(repoProfile, 'xss-clean')) {
      return 'Prefer the repo\'s existing XSS prevention pattern or switch to a safe text sink such as textContent.';
    }
    if (existing) return existing;
    return 'Apply output encoding for this sink or use a safe text rendering API.';
  }

  if (missingControlType === 'base_dir_validation') {
    if (hasValidationLibrary(repoProfile) || interpreted.validation_approach) {
      return 'Use the repo\'s existing validation path to enforce base-directory containment before reading the file.';
    }
    if (framework) {
      return `Apply ${framework}-consistent path validation that resolves the file within a fixed base directory.`;
    }
  }

  if (missingControlType === 'relative_or_allowlisted_redirect_validation') {
    if (hasValidationLibrary(repoProfile)) {
      return 'Use the repo\'s existing validation helpers to restrict redirects to relative paths or an explicit allowlist.';
    }
    if (framework) {
      return `Apply ${framework}-consistent redirect validation so only relative or allowlisted targets are accepted.`;
    }
  }

  if (missingControlType === 'host_or_scheme_allowlist') {
    if (hasValidationLibrary(repoProfile)) {
      return 'Use the repo\'s existing validation layer to allowlist outbound hosts and schemes before making the request.';
    }
    if (framework) {
      return `Add ${framework}-consistent URL validation that restricts outbound requests to trusted hosts and schemes.`;
    }
  }

  if (interpreted.database_pattern === 'parameterized') {
    const category = String(finding?.category || '').toLowerCase();
    const cweId = String(finding?.cwe_id || '').toUpperCase();
    if (category.includes('sql') || cweId === 'CWE-89') {
      return 'Use the repo\'s existing parameterized query pattern instead of concatenating user input into SQL.';
    }
  }

  return existing || '';
}

function validateAgainstRepoProfile(finding, suggestionPatch, repoProfile) {
  if (!repoProfile || typeof repoProfile !== 'object') {
    return { ok: true, reasons: ['repo profile unavailable; using structural validation only'] };
  }

  const deterministic = repoProfile.deterministic || {};
  const interpreted = repoProfile.interpreted || {};
  const reasons = [];
  const category = String(finding?.category || '').toLowerCase();
  const cweId = String(finding?.cwe_id || '').toUpperCase();

  if (interpreted.database_pattern === 'parameterized') {
    const isSqlFinding = category.includes('sql') || cweId === 'CWE-89';
    if (isSqlFinding && !looksLikeParameterizedQuery(suggestionPatch)) {
      return {
        ok: false,
        reasons: ['suggestion does not match the repo parameterized query pattern'],
      };
    }
    if (looksLikeParameterizedQuery(suggestionPatch)) {
      reasons.push('suggestion aligns with parameterized query pattern from repo profile');
    }
  }

  if (deterministic.framework) {
    reasons.push(`repo framework detected as ${deterministic.framework}`);
  }

  return { ok: true, reasons };
}

function validateSuggestedFix({ finding, filePatch, tierLabel, repoProfile }) {
  const suggestionPatch = normalizePatch(finding?.remediation_patch);
  if (!suggestionPatch) {
    return { ok: false, reason: 'missing suggestion patch' };
  }

  if (tierLabel !== 'Tier 3') {
    return { ok: false, reason: 'suggestions are only rendered after Tier 3 triage' };
  }

  if (isFixRejectedByCritic(finding)) {
    return { ok: false, reason: 'patch critic found an input that still reaches the sink' };
  }

  if (!normalizeAutoFixEligible(finding)) {
    return { ok: false, reason: 'finding is not eligible for one-click auto-fix' };
  }

  if (suggestionPatch.includes('```')) {
    return { ok: false, reason: 'suggestion patch contains markdown fences' };
  }

  const suggestionLines = suggestionPatch.split('\n');
  if (suggestionLines.length > 8) {
    return { ok: false, reason: 'suggestion patch exceeds 8 lines' };
  }

  const snippet = normalizePatch(finding?.code_snippet);
  const snippetLines = countMeaningfulLines(snippet) || 1;
  if (suggestionLines.length > snippetLines + 3) {
    return { ok: false, reason: 'suggestion patch is too large relative to flagged snippet' };
  }

  if (snippet && normalizePatch(snippet) === suggestionPatch) {
    return { ok: false, reason: 'suggestion patch is identical to current code' };
  }

  if (includesBroadRewriteConstruct(suggestionPatch)) {
    return { ok: false, reason: 'suggestion patch introduces imports or broad code structure changes' };
  }

  if (looksLikeUnifiedDiff(suggestionPatch)) {
    return { ok: false, reason: 'suggestion patch must be raw replacement code, not a diff' };
  }

  const reviewableLines = extractReviewableLines(filePatch);
  const targetLines = lineRange(finding?.line_start || 1, finding?.line_end || finding?.line_start || 1);
  if (targetLines.length === 0 || targetLines.some((line) => !reviewableLines.has(line))) {
    return { ok: false, reason: 'finding line is not reviewable in the PR diff' };
  }

  const fixScope = normalizeFixScope(finding);
  if (fixScope === 'line' && suggestionLines.length > 1) {
    return { ok: false, reason: 'line-scoped auto-fixes must stay within a single replacement line' };
  }

  const fixTargetLine = normalizeFixTargetLine(finding);
  if (fixTargetLine != null) {
    if (!reviewableLines.has(fixTargetLine)) {
      return { ok: false, reason: 'fix target line is not reviewable in the PR diff' };
    }
    if (!targetLines.includes(fixTargetLine)) {
      return { ok: false, reason: 'fix target line falls outside the finding anchor range' };
    }
  }

  const fixTargetExpr = normalizeFixTargetExpr(finding);
  const addedBlock = extractAddedBlock(filePatch, finding?.line_start || 1, finding?.line_end || finding?.line_start || 1);
  if (fixTargetExpr && addedBlock && !normalizePatch(addedBlock).includes(fixTargetExpr)) {
    return { ok: false, reason: 'fix target expression does not match the reviewable code block' };
  }

  if (snippet && addedBlock && !snippetsOverlap(snippet, addedBlock) && !fixTargetExpr) {
    return { ok: false, reason: 'flagged snippet does not match the added lines in the PR diff' };
  }

  const repoValidation = validateAgainstRepoProfile(finding, suggestionPatch, repoProfile);
  if (!repoValidation.ok) {
    return { ok: false, reason: repoValidation.reasons?.[0] || 'repo profile rejected suggestion' };
  }

  const details = repoValidation.reasons ? [...repoValidation.reasons] : [];
  const missingControlType = normalizeMissingControlType(finding);
  if (missingControlType) {
    details.push(`missing control classified as ${missingControlType}`);
  }
  if (fixScope !== 'unknown') {
    details.push(`fix scope validated as ${fixScope}`);
  }

  return {
    ok: true,
    reason: 'validated for inline GitHub suggestion rendering',
    details,
  };
}

module.exports = {
  validateSuggestedFix,
  __private: {
    buildRepoAwareRemediation,
    extractAddedBlock,
    extractReviewableLines,
    extractReviewableLineSpans,
    includesBroadRewriteConstruct,
    lineRange,
    looksLikeUnifiedDiff,
    normalizePatch,
    snippetsOverlap,
  },
};
