const axios = require('axios');

jest.mock('axios');
jest.mock('../src/db/repositories', () => ({getProfile: jest.fn().mockResolvedValue({profile_status: 'ready', profile_data: {}}), queueUrgentProfiling: jest.fn()}));
jest.mock('../src/services/githubApp', () => ({
  getInstallationToken: jest.fn(),
}));
jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));
jest.mock('../src/utils/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
}));
jest.mock('../src/services/remediationAutoGenerate', () => ({
  enqueueForCompletedAnalysis: jest.fn(async () => ({ enqueued: false, reason: 'generate_disabled' })),
}));

const { pool } = require('../src/config/database');
const logger = require('../src/utils/logger');
const { getInstallationToken } = require('../src/services/githubApp');

beforeEach(() => {
  jest.clearAllMocks();
  process.env.GITHUB_SERVICE_URL = 'http://github-service:3002';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'test-secret';
  process.env.ANALYSIS_SERVICE_URL = 'http://analysis-service:8001';
  getInstallationToken.mockResolvedValue('installation-token');
});

describe('PR Analysis Orchestrator — pure functions', () => {
  test('githubServiceRequest retries transient network failures and then succeeds', async () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    axios.post
      .mockRejectedValueOnce(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }))
      .mockResolvedValueOnce({ data: { ok: true } });

    const result = await __private.githubServiceRequest('/internal/github/pulls/files', { hello: 'world' });

    expect(result).toEqual({ ok: true });
    expect(axios.post).toHaveBeenCalledTimes(2);
  });

  test('githubServiceRequest surfaces unreachable service errors clearly', async () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    axios.post.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));

    await expect(
      __private.githubServiceRequest('/internal/github/pulls/files', { hello: 'world' })
    ).rejects.toThrow(/GitHub service unreachable/);

    expect(axios.post).toHaveBeenCalledTimes(3);
  });

  test('buildReviewBody stays summary-only and does not duplicate finding details', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const body = __private.buildReviewBody([{
      severity: 'high',
      title: 'Potential SQL injection',
      evidence: 'Matched raw query',
      exploit_scenario: 'An attacker can alter the query and access unintended rows.',
      remediation: 'Use parameterized queries.',
      remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
      file_path: 'src/app.js',
      line_start: 12,
    }], 'run-uuid-1');

    expect(body).toContain('The finding is annotated inline on the affected line below.');
    expect(body).toContain('1 of 1 annotated inline');
    expect(body).not.toContain('### Findings');
    expect(body).not.toContain('Potential SQL injection');
    expect(body).not.toContain('**Fix:** Use parameterized queries.');
    expect(body).not.toContain('db.query("SELECT * FROM users WHERE id = ?", [userId]);');
  });

  // The summary says how many findings have an inline annotation and how many it lists
  // only, instead of claiming every finding is annotated below.
  test('buildReviewBody counts the findings annotated inline and the ones listed in the summary only', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');
    const finding = (title, line) => ({ severity: 'high', title, evidence: 'x', remediation: 'y', file_path: 'src/app.js', line_start: line, confidence: 0.8 });
    const findings = [finding('SQL injection', 12), finding('Path traversal', 35), finding('Unsafe eval', 40)];

    const mixed = __private.buildReviewBody(findings, 'run-uuid-1', { inlineCount: 1 });
    expect(mixed).toContain('1 finding is annotated inline on the affected lines below; 2 findings are listed here only (the line is outside the diff or the evidence is below the inline threshold), with details in the Mitig8it dashboard.');
    expect(mixed).toContain('1 of 3 annotated inline');
    expect(mixed).not.toContain('Detailed findings are annotated inline');

    const none = __private.buildReviewBody(findings, 'run-uuid-1', { inlineCount: 0 });
    expect(none).toContain('0 findings are annotated inline on the affected lines below; 3 findings are listed here only');

    const all = __private.buildReviewBody(findings, 'run-uuid-1', { inlineCount: 3 });
    expect(all).toContain('All 3 findings are annotated inline on the affected lines below.');
    expect(all).toContain('3 of 3 annotated inline');
  });

  test('buildReviewComment renders GitHub suggestion blocks for validated Tier 3 patches', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const body = __private.buildReviewComment({
      severity: 'high',
      title: 'Code injection via eval',
      evidence: 'Matched eval call',
      confidence: 0.92,
      code_snippet: 'eval(req.body.code);',
      line_start: 1,
      line_end: 1,
      remediation: 'Replace eval with JSON parsing.',
      remediation_patch: 'const payload = JSON.parse(req.body.code);',
      evidence_details: {
        auto_fix_eligible: true,
        fix_scope: 'line',
        fix_target_line: 1,
        fix_target_expr: 'eval(req.body.code);',
      },
    }, {
      tierLabel: 'Tier 3',
      filePatch: '@@ -1 +1 @@\n-eval(req.body.code);\n+eval(req.body.code);',
    });

    expect(body).toContain('```suggestion');
    expect(body).toContain('const payload = JSON.parse(req.body.code);');
    expect(body).not.toContain('**Suggested fix code:**');
    expect(body).not.toContain('**Candidate fix code:**');
  });

  test('buildReviewComment falls back to fix text before Tier 3 validation', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const body = __private.buildReviewComment({
      severity: 'high',
      title: 'Code injection via eval',
      evidence: 'Matched eval call',
      confidence: 0.92,
      code_snippet: 'eval(req.body.code);',
      remediation: 'Replace eval with JSON parsing.',
      remediation_patch: 'const payload = JSON.parse(req.body.code);',
    }, {
      tierLabel: 'Tier 1',
      filePatch: '@@ -1 +1 @@\n-eval(req.body.code);\n+eval(req.body.code);',
    });

    expect(body).not.toContain('```suggestion');
    expect(body).toContain('**Fix:** Replace eval with JSON parsing.');
    expect(body).not.toContain('**Candidate fix code:**');
    expect(body).toContain('const payload = JSON.parse(req.body.code);');
  });

  test('buildReviewComment uses repo-aware SQL remediation when auto-fix is not allowed', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const body = __private.buildReviewComment({
      severity: 'high',
      title: 'Potential SQL injection',
      evidence: 'Matched raw query',
      confidence: 0.9,
      cwe_id: 'CWE-89',
      category: 'SQL injection',
      code_snippet: 'db.query("SELECT * FROM users WHERE id = " + userId);',
      remediation: 'Use parameterized queries.',
      remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
      line_start: 1,
      line_end: 1,
      evidence_details: {
        auto_fix_eligible: false,
        fix_scope: 'line',
      },
    }, {
      tierLabel: 'Tier 3',
      filePatch: '@@ -0,0 +1 @@\n+db.query("SELECT * FROM users WHERE id = " + userId);',
      repoProfile: {
        interpreted: { database_pattern: 'parameterized' },
      },
    });

    expect(body).not.toContain('```suggestion');
    expect(body).toContain("**Fix:** Use the repo's existing parameterized query pattern instead of concatenating user input into SQL.");
  });

  test('buildReviewComment uses repo-aware XSS remediation when DOMPurify is present', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const body = __private.buildReviewComment({
      severity: 'high',
      title: 'Potential XSS through unsafe HTML rendering',
      evidence: 'Matched unsafe innerHTML sink',
      confidence: 0.9,
      cwe_id: 'CWE-79',
      category: 'cross-site scripting (xss)',
      code_snippet: 'element.innerHTML = req.query.name;',
      remediation: 'Encode or sanitize output before rendering.',
      remediation_patch: 'element.innerHTML = DOMPurify.sanitize(req.query.name);',
      line_start: 1,
      line_end: 1,
      evidence_details: {
        auto_fix_eligible: false,
        fix_scope: 'line',
        missing_control_type: 'html_sanitization_or_safe_text_rendering',
      },
    }, {
      tierLabel: 'Tier 3',
      filePatch: '@@ -0,0 +1 @@\n+element.innerHTML = req.query.name;',
      repoProfile: {
        deterministic: {
          security_libraries: [{ library: 'dompurify', purpose: 'HTML sanitization' }],
        },
      },
    });

    expect(body).not.toContain('```suggestion');
    expect(body).toContain("**Fix:** Use the repo's existing DOMPurify sanitization pattern before writing HTML, or prefer textContent if HTML is unnecessary.");
  });

  test('buildReviewComment falls back to fix text for oversized patches', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const body = __private.buildReviewComment({
      severity: 'high',
      title: 'Code injection via eval',
      evidence: 'Matched eval call',
      confidence: 0.92,
      code_snippet: 'eval(req.body.code);',
      remediation: 'Replace eval with safer parsing.',
      remediation_patch: [
        'function safeParse(input) {',
        '  const value = JSON.parse(input);',
        '  if (!value) throw new Error("missing");',
        '  return value;',
        '}',
        '',
        'const payload = safeParse(req.body.code);',
        'doSomething(payload);',
        'logUsage(payload);',
      ].join('\n'),
    }, {
      tierLabel: 'Tier 3',
      filePatch: '@@ -1 +1 @@\n-eval(req.body.code);\n+eval(req.body.code);',
    });

    expect(body).not.toContain('```suggestion');
    expect(body).toContain('**Fix:** Replace eval with safer parsing.');
    expect(body).not.toContain('**Candidate fix code:**');
  });

  test('shouldRenderSuggestion rejects patches shorter than the anchored line range', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const rendered = __private.shouldRenderSuggestion(
      { line_start: 10, line_end: 12, code_snippet: 'a\nb\nc' },
      'oneLineFix();'
    );

    expect(rendered).toBe(false);
  });

  test('shouldRenderSuggestion rejects patches that overshoot the anchor span', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const rendered = __private.shouldRenderSuggestion(
      { line_start: 5, line_end: 5, code_snippet: 'eval(x);' },
      ['function safe(i) {', '  return JSON.parse(i);', '}', 'const v = safe(x);', 'use(v);'].join('\n')
    );

    expect(rendered).toBe(false);
  });

  test('shouldRenderSuggestion rejects findings with no anchor line', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const rendered = __private.shouldRenderSuggestion(
      { code_snippet: 'eval(x);' },
      'safeParse(x);'
    );

    expect(rendered).toBe(false);
  });

  test('shouldRenderSuggestion accepts a matching multi-line anchor', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const rendered = __private.shouldRenderSuggestion(
      { line_start: 10, line_end: 12, code_snippet: 'a\nb\nc' },
      'lineOne;\nlineTwo;\nlineThree;'
    );

    expect(rendered).toBe(true);
  });

  test('validateSuggestedFix rejects patches that do not match the diff snippet', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.validateSuggestedFix({
      finding: {
        line_start: 2,
        line_end: 2,
        code_snippet: 'eval(req.body.code);',
        remediation_patch: 'const payload = JSON.parse(req.body.code);',
        evidence_details: {
          auto_fix_eligible: true,
          fix_scope: 'line',
          fix_target_line: 2,
          fix_target_expr: 'eval(req.body.code);',
        },
      },
      filePatch: '@@ -0,0 +1,2 @@\n+const alreadySafe = true;\n+handle(req.body.code);',
      tierLabel: 'Tier 3',
      repoProfile: null,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toContain('does not match');
  });

  test('validateSuggestedFix rejects unified diff output', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.validateSuggestedFix({
      finding: {
        line_start: 1,
        line_end: 1,
        code_snippet: 'eval(req.body.code);',
        remediation_patch: '@@ -1 +1 @@\n-eval(req.body.code);\n+const payload = JSON.parse(req.body.code);',
        evidence_details: {
          auto_fix_eligible: true,
          fix_scope: 'line',
          fix_target_line: 1,
          fix_target_expr: 'eval(req.body.code);',
        },
      },
      filePatch: '@@ -0,0 +1 @@\n+eval(req.body.code);',
      tierLabel: 'Tier 3',
      repoProfile: null,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toContain('not a diff');
  });

  test('validateSuggestedFix rejects repo-inconsistent SQL fixes', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.validateSuggestedFix({
      finding: {
        category: 'SQL injection',
        cwe_id: 'CWE-89',
        line_start: 1,
        line_end: 1,
        code_snippet: 'db.query("SELECT * FROM users WHERE id = " + userId);',
        remediation_patch: 'db.query("SELECT * FROM users WHERE id = " + String(userId));',
        evidence_details: {
          auto_fix_eligible: true,
          fix_scope: 'line',
          fix_target_line: 1,
          fix_target_expr: 'db.query("SELECT * FROM users WHERE id = " + userId);',
          missing_control_type: 'output_encoding',
        },
      },
      filePatch: '@@ -0,0 +1 @@\n+db.query("SELECT * FROM users WHERE id = " + userId);',
      tierLabel: 'Tier 3',
      repoProfile: {
        interpreted: { database_pattern: 'parameterized' },
      },
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toContain('parameterized query pattern');
  });

  test('buildReviewComment renders Tier 3 suggestion for repo-consistent SQL fix', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const body = __private.buildReviewComment({
      severity: 'high',
      title: 'Potential SQL injection',
      evidence: 'Matched raw query',
      confidence: 0.9,
      cwe_id: 'CWE-89',
      category: 'SQL injection',
      code_snippet: 'db.query("SELECT * FROM users WHERE id = " + userId);',
      remediation: 'Use parameterized queries.',
      remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
      line_start: 1,
      line_end: 1,
      evidence_details: {
        auto_fix_eligible: true,
        fix_scope: 'line',
        fix_target_line: 1,
        fix_target_expr: 'db.query("SELECT * FROM users WHERE id = " + userId);',
        missing_control_type: 'output_encoding',
      },
    }, {
      tierLabel: 'Tier 3',
      filePatch: '@@ -0,0 +1 @@\n+db.query("SELECT * FROM users WHERE id = " + userId);',
      repoProfile: {
        interpreted: { database_pattern: 'parameterized' },
      },
    });

    expect(body).toContain('```suggestion');
    expect(body).toContain('db.query("SELECT * FROM users WHERE id = ?", [userId]);');
    expect(body).not.toContain('**Suggested fix code:**');
  });

  test('validateSuggestedFix rejects auto-fix ineligible findings', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.validateSuggestedFix({
      finding: {
        line_start: 1,
        line_end: 1,
        code_snippet: 'eval(req.body.code);',
        remediation_patch: 'const payload = JSON.parse(req.body.code);',
        evidence_details: {
          auto_fix_eligible: false,
          fix_scope: 'line',
          fix_target_line: 1,
          fix_target_expr: 'eval(req.body.code);',
        },
      },
      filePatch: '@@ -0,0 +1 @@\n+eval(req.body.code);',
      tierLabel: 'Tier 3',
      repoProfile: null,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toContain('not eligible');
  });

  test('validateSuggestedFix rejects multi-line patches for line-scoped fixes', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.validateSuggestedFix({
      finding: {
        line_start: 1,
        line_end: 1,
        code_snippet: 'eval(req.body.code);',
        remediation_patch: 'const payload = JSON.parse(req.body.code);\nhandle(payload);',
        evidence_details: {
          auto_fix_eligible: true,
          fix_scope: 'line',
          fix_target_line: 1,
          fix_target_expr: 'eval(req.body.code);',
        },
      },
      filePatch: '@@ -0,0 +1 @@\n+eval(req.body.code);',
      tierLabel: 'Tier 3',
      repoProfile: null,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toContain('line-scoped');
  });

  test('validateSuggestedFix rejects target lines outside the finding anchor', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.validateSuggestedFix({
      finding: {
        line_start: 2,
        line_end: 2,
        code_snippet: 'eval(req.body.code);',
        remediation_patch: 'const payload = JSON.parse(req.body.code);',
        evidence_details: {
          auto_fix_eligible: true,
          fix_scope: 'line',
          fix_target_line: 1,
          fix_target_expr: 'eval(req.body.code);',
        },
      },
      filePatch: '@@ -0,0 +1,2 @@\n+const existing = true;\n+eval(req.body.code);',
      tierLabel: 'Tier 3',
      repoProfile: null,
    });

    expect(result.ok).toBe(false);
    expect(result.reason).toContain('outside the finding anchor range');
  });

  test('validateSuggestedFix accepts snippets with surrounding diff context when the target expression matches', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.validateSuggestedFix({
      finding: {
        line_start: 3,
        line_end: 3,
        code_snippet: [
          'const text = String(req.query.id);',
          'const userId = Number(text);',
          'db.query("SELECT * FROM users WHERE id = " + userId);',
        ].join('\n'),
        remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
        evidence_details: {
          auto_fix_eligible: true,
          fix_scope: 'line',
          fix_target_line: 3,
          fix_target_expr: 'db.query("SELECT * FROM users WHERE id = " + userId);',
          missing_control_type: 'parameterized_query',
        },
      },
      filePatch: [
        '@@ -0,0 +1,3 @@',
        '+const text = String(req.query.id);',
        '+const userId = Number(text);',
        '+db.query("SELECT * FROM users WHERE id = " + userId);',
      ].join('\n'),
      tierLabel: 'Tier 3',
      repoProfile: {
        interpreted: { database_pattern: 'parameterized' },
      },
    });

    expect(result.ok).toBe(true);
  });

  test('didTier3MeaningfullyChangeFindings detects remediation patch enrichment', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const changed = __private.didTier3MeaningfullyChangeFindings(
      [{
        fingerprint: 'fp-1',
        severity: 'high',
        confidence: 0.9,
        title: 'Potential SQL injection',
        evidence: 'Matched deterministic rule',
        remediation: 'Use parameterized queries.',
        remediation_patch: '',
        line_start: 1,
        line_end: 1,
      }],
      [{
        fingerprint: 'fp-1',
        severity: 'high',
        confidence: 0.9,
        title: 'Potential SQL injection',
        evidence: 'Matched deterministic rule',
        remediation: 'Use parameterized queries.',
        remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
        line_start: 1,
        line_end: 1,
      }]
    );

    expect(changed).toBe(true);
  });

  test('prioritizeReviewComments sorts suggestion comments first within a file', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const ordered = __private.prioritizeReviewComments([
      { path: 'a.js', line: 20, severity: 'critical', hasSuggestion: false, body: 'plain' },
      { path: 'a.js', line: 10, severity: 'high', hasSuggestion: true, body: 'suggestion' },
      { path: 'b.js', line: 5, severity: 'high', hasSuggestion: true, body: 'other-file' },
    ]);

    expect(ordered[0]).toMatchObject({ path: 'a.js', hasSuggestion: true });
    expect(ordered[1]).toMatchObject({ path: 'a.js', hasSuggestion: false });
    expect(ordered[2]).toMatchObject({ path: 'b.js' });
  });

  test('hasTier3RenderableSuggestions detects applyable suggestion blocks', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.hasTier3RenderableSuggestions(
      [{
        severity: 'high',
        title: 'Potential SQL injection',
        category: 'SQL injection',
        cwe_id: 'CWE-89',
        file_path: 'a.js',
        line_start: 1,
        line_end: 1,
        code_snippet: 'db.query("SELECT * FROM users WHERE id = " + userId);',
        remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
        evidence_details: {
          auto_fix_eligible: true,
          fix_scope: 'line',
          fix_target_line: 1,
          fix_target_expr: 'db.query("SELECT * FROM users WHERE id = " + userId);',
          missing_control_type: 'output_encoding',
        },
      }],
      [{ path: 'a.js', patch: '@@ -0,0 +1 @@\n+db.query("SELECT * FROM users WHERE id = " + userId);' }],
      { interpreted: { database_pattern: 'parameterized' } }
    );

    expect(result).toBe(true);
  });

  test('shouldPostInlineComment allows strong taint findings with trace evidence', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.shouldPostInlineComment({
      confidence: 0.81,
      analysis_scope: 'taint-intraprocedural',
      source: 'req.query.file',
      sink: 'fs.readFile',
      evidence_details: {
        reviewability: 'changed-lines-only',
        sanitizer_status: 'none',
        trace_steps: [
          { kind: 'source', expr: 'req.query.file' },
          { kind: 'sink', expr: 'fs.readFile(file)' },
        ],
      },
    });

    expect(result).toBe(true);
  });

  test('shouldPostInlineComment blocks validated taint findings from inline review', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.shouldPostInlineComment({
      confidence: 0.96,
      analysis_scope: 'taint-intraprocedural',
      source: 'req.query.redirect',
      sink: 'res.redirect',
      evidence_details: {
        reviewability: 'changed-lines-only',
        sanitizer_status: 'validated',
        trace_summary: 'Request-controlled redirect value passes through allowlisted redirect validator.',
      },
    });

    expect(result).toBe(false);
  });

  test('shouldPostInlineComment blocks taint findings with weak trace quality', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.shouldPostInlineComment({
      confidence: 0.94,
      analysis_scope: 'taint-intraprocedural',
      source: 'req.query.target',
      sink: 'axios.get',
      evidence_details: {
        reviewability: 'changed-lines-only',
        sanitizer_status: 'none',
        evidence_strength: 'medium',
        trace_quality: 'weak',
        confidence_basis: 'taint_weak_trace',
      },
    });

    expect(result).toBe(false);
  });

  test('shouldPostInlineComment keeps weak pattern matches out of inline review', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.shouldPostInlineComment({
      confidence: 0.82,
      analysis_scope: 'pattern',
      evidence_details: {
        reviewability: 'changed-lines-only',
      },
    });

    expect(result).toBe(false);
  });

  test('shouldPostInlineComment allows ast-pattern findings with medium evidence and inline basis', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.shouldPostInlineComment({
      confidence: 0.87,
      analysis_scope: 'ast-pattern',
      evidence_details: {
        reviewability: 'changed-lines-only',
        evidence_strength: 'medium',
        trace_quality: 'none',
        confidence_basis: 'ast_pattern_changed-lines-only',
      },
    });

    expect(result).toBe(true);
  });

  test('explainInlineCommentDecision returns detailed inline rejection reasons', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const result = __private.explainInlineCommentDecision({
      confidence: 0.91,
      analysis_scope: 'taint-intraprocedural',
      evidence_details: {
        reviewability: 'changed-lines-only',
        sanitizer_status: 'validated',
      },
    });

    expect(result).toEqual({
      eligible: false,
      reason: 'validated_sanitizer_present',
    });
  });

  test('buildSurfaceDecisions distinguishes inline, summary-only, and suppressed findings', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const decisions = __private.buildSurfaceDecisions({
      files: [
        { path: 'src/app.js', patch: '@@ -1,0 +1,2 @@\n+const input = req.query.file;\n+fs.readFile(input);' },
      ],
      findings: [
        {
          id: 'finding-inline',
          status: 'open',
          is_baseline: false,
          file_path: 'src/app.js',
          line_start: 2,
          confidence: 0.82,
          analysis_scope: 'taint-intraprocedural',
          source: 'req.query.file',
          sink: 'fs.readFile',
          evidence_details: {
            reviewability: 'changed-lines-only',
            sanitizer_status: 'none',
            trace_summary: 'User input reaches fs.readFile.',
          },
        },
        {
          id: 'finding-summary',
          status: 'open',
          is_baseline: false,
          file_path: 'src/app.js',
          line_start: 2,
          confidence: 0.8,
          analysis_scope: 'pattern',
          evidence_details: {
            reviewability: 'changed-lines-only',
          },
        },
        {
          id: 'finding-suppressed',
          status: 'dismissed',
          is_baseline: false,
          file_path: 'src/app.js',
          line_start: 2,
          confidence: 0.99,
          evidence_details: {
            reviewability: 'changed-lines-only',
          },
        },
      ],
    });

    expect(decisions).toEqual([
      {
        findingId: 'finding-inline',
        surfaceDecision: 'inline',
        surfaceReason: 'strong_taint_evidence',
      },
      {
        findingId: 'finding-summary',
        surfaceDecision: 'summary_only',
        surfaceReason: 'pattern_confidence_below_inline_threshold',
      },
      {
        findingId: 'finding-suppressed',
        surfaceDecision: 'suppressed',
        surfaceReason: 'status_dismissed',
      },
    ]);
  });

  test('buildTier2FilePayload attaches full content and reviewable spans', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    const payload = __private.buildTier2FilePayload(
      {
        path: 'src/app.js',
        patch: '@@ -10,0 +10,2 @@\n+const value = req.query.file;\n+fs.readFile(value);',
        additions: 2,
      },
      new Map([['src/app.js', 'const value = req.query.file;\nfs.readFile(value);\n']])
    );

    expect(payload.content).toContain('fs.readFile');
    expect(payload.reviewable_line_spans).toEqual([{ start: 10, end: 11 }]);
  });

  test('enrichFilesForTier2 fetches full content for supported files and preserves fallback payload', async () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');

    axios.post.mockImplementation((url) => {
      if (url.includes('/internal/github/files/content')) {
        return Promise.resolve({
          data: {
            files: [
              { path: 'src/app.js', content: 'const value = req.query.file;\nfs.readFile(value);\n' },
            ],
          },
        });
      }
      return Promise.resolve({ data: {} });
    });

    const files = await __private.enrichFilesForTier2({
      repositoryFullName: 'owner/repo',
      installationId: 12345,
      commitSha: 'abc123',
      files: [
        { path: 'src/app.js', patch: '@@ -1,0 +1,2 @@\n+const value = req.query.file;\n+fs.readFile(value);', additions: 2 },
        { path: 'README.md', patch: '@@ -1 +1 @@\n+docs', additions: 1 },
      ],
    });

    expect(axios.post).toHaveBeenCalledWith(
      expect.stringContaining('/internal/github/files/content'),
      expect.objectContaining({
        repository_full_name: 'owner/repo',
        installation_id: 12345,
        ref: 'abc123',
        paths: ['src/app.js'],
      }),
      expect.any(Object)
    );
    expect(files[0].content).toContain('fs.readFile');
    expect(files[0].reviewable_line_spans).toEqual([{ start: 1, end: 2 }]);
    expect(files[1].content).toBe('');
    expect(files[1].reviewable_line_spans).toEqual([{ start: 1, end: 1 }]);
  });
});

describe('PR Analysis Orchestrator — pipeline', () => {
  const BASE_PAYLOAD = {
    analysis_run_id: 'run-uuid-1',
    repository_id: 'repo-uuid-1',
    repository_full_name: 'owner/repo',
    installation_id: 12345,
    pull_request_id: 'pr-uuid-1',
    pull_request_number: 42,
    commit_sha: 'abc123def456',
    baseline_set: true,
  };

  const FINDING = {
    rule_id: 'code.injection.eval',
    internal_type: 'code_injection',
    title: 'Code injection via eval or dynamic execution',
    description: 'Dynamic code execution can run attacker-controlled payloads.',
    category: 'code injection',
    severity: 'critical',
    confidence: 0.92,
    exploitability: 'high',
    file_path: 'test_vuln.js',
    line_start: 2,
    line_end: 2,
    code_snippet: 'eval(req.body.code);',
    evidence: 'Matched deterministic rule `code.injection.eval` on `eval(`.',
    remediation: 'Replace eval/exec with safe alternatives.',
    remediation_patch: 'const payload = JSON.parse(req.body.code);',
    fingerprint: 'fp-1',
  };
  const PERSISTED_FINDING = {
    id: 'finding-1',
    status: 'open',
    is_baseline: false,
    ...FINDING,
  };

  function flushAsync() {
    return new Promise((resolve) => setTimeout(resolve, 300));
  }

  function mockAxiosRoute(url, response) {
    // Helper: returns a function that matches URL patterns
    return { url, response };
  }

  // Setup axios.post to route by URL pattern
  function setupAxiosMocks(routes) {
    axios.post.mockImplementation((url, data, opts) => {
      for (const route of routes) {
        if (url.includes(route.pattern)) {
          if (route.error) return Promise.reject(route.error);
          return Promise.resolve({ data: route.data });
        }
      }
      return Promise.resolve({ data: {} });
    });
  }

  test('marks run as failed when GitHub service is unreachable', async () => {
    axios.post.mockRejectedValue(new Error('ECONNREFUSED'));
    pool.query.mockResolvedValue({ rowCount: 1, rows: [] });

    const { triggerAnalysisJob } = require('../src/services/prAnalysisOrchestrator');
    triggerAnalysisJob(BASE_PAYLOAD);
    await flushAsync();

    expect(pool.query).toHaveBeenCalledWith(
      expect.stringContaining("status = 'failed'"),
      expect.arrayContaining(['run-uuid-1'])
    );
    expect(logger.error).toHaveBeenCalled();
  });

  test('individual required tier failure fails the run', async () => {
    // With progressive posting, a single tier failing is non-blocking
    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'app.py', patch: '+x=1', additions: 1 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'app.py', content: 'x=1\n' }] } },
      { pattern: '/tier1', error: new Error('Tier 1 timeout') },
      { pattern: '/tier2', error: new Error('Tier 2 timeout') },
      { pattern: '/tier3', data: { findings: [], filtered_count: 0 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    expect(pool.query).toHaveBeenCalledWith(
      expect.stringContaining("status = 'failed'"), expect.anything()
    );
    expect(axios.post.mock.calls.some(([url, body]) => url.includes('/check-runs') && body.conclusion === 'success')).toBe(false);
  });

  test('calls GitHub service with correct internal secret header', async () => {
    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [] } },
      { pattern: '/files/content', data: { files: [] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [], filtered_count: 0, tier: 3 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    expect(axios.post).toHaveBeenCalledWith(
      expect.stringContaining('/internal/github/pulls/files'),
      expect.any(Object),
      expect.objectContaining({
        headers: { 'x-internal-secret': 'test-secret' },
      })
    );
  });

  test('posts review as COMMENT when no critical/high findings', async () => {
    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [] } },
      { pattern: '/files/content', data: { files: [] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    // With no findings across any tier, no review is posted (only check-run)
    const checkCall = axios.post.mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes('check-runs')
    );
    expect(checkCall).toBeTruthy();
  });

  test('queues automatic remediation only after the run is completed, and a queue failure never fails the run', async () => {
    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [] } },
      { pattern: '/files/content', data: { files: [] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    let autoGenerate;
    let db;
    jest.isolateModules(() => {
      autoGenerate = require('../src/services/remediationAutoGenerate');
      db = require('../src/config/database');
      db.pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });
      autoGenerate.enqueueForCompletedAnalysis.mockRejectedValue(new Error('remediation database unavailable'));
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    expect(autoGenerate.enqueueForCompletedAnalysis).toHaveBeenCalledTimes(1);
    expect(autoGenerate.enqueueForCompletedAnalysis).toHaveBeenCalledWith({ pullRequestId: 'pr-uuid-1', analysisRunId: 'run-uuid-1' });
    const sql = db.pool.query.mock.calls.map(([text]) => String(text));
    const completedAt = sql.findIndex((text) => text.includes("SET status = 'completed'"));
    expect(completedAt).toBeGreaterThanOrEqual(0);
    // The enqueue happens after completion and its failure does not mark the run failed.
    expect(sql.slice(completedAt + 1).some((text) => text.includes("status = 'failed'"))).toBe(false);
    const order = autoGenerate.enqueueForCompletedAnalysis.mock.invocationCallOrder[0];
    const completion = db.pool.query.mock.invocationCallOrder[completedAt];
    expect(order).toBeGreaterThan(completion);
  });

  // A pull request over the adapter's 200-file cap is reviewed as far as the cap allows
  // rather than refused. The check run must say so: reporting a clean result on a pull
  // request the run only partly read would be the dishonest outcome.
  test('a file_cap limitation from the adapter is stated on the check run summary', async () => {
    setupAxiosMocks([
      { pattern: '/pulls/files', data: {
        files: [{ path: 'app.py', patch: '+x=1', additions: 1 }],
        limitation: { kind: 'file_cap', message: 'Reviewed 200 of 812 changed files' },
      } },
      { pattern: '/files/content', data: { files: [{ path: 'app.py', content: 'x=1\n' }] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    const checkRun = axios.post.mock.calls.find(([url]) => String(url).includes('/check-runs'));
    expect(checkRun).toBeDefined();
    expect(checkRun[1].summary).toContain('Reviewed 200 of 812 changed files');
    // The cap is a coverage limit, not a failure: the run still completes and publishes.
    expect(checkRun[1].conclusion).toBe('success');
  });

  test('a run that read the whole pull request states no limitation', async () => {
    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'app.py', patch: '+x=1', additions: 1 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'app.py', content: 'x=1\n' }] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    const checkRun = axios.post.mock.calls.find(([url]) => String(url).includes('/check-runs'));
    expect(checkRun).toBeDefined();
    expect(checkRun[1].summary).not.toMatch(/Reviewed \d+ of \d+ changed files/);
  });

  test('posts review after tier1 returns findings', async () => {
    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'test_vuln.js', patch: '@@ -0,0 +1,2 @@\n+const existing = true;\n+eval(req.body.code);', additions: 2 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'test_vuln.js', content: 'const existing = true;\neval(req.body.code);\n' }] } },
      { pattern: '/tier1', data: { findings: [FINDING], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [FINDING], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/comments/inline', data: { comment_id: 11, success: true } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    // DB mocks: countCompleted, upsert (select), upsert (insert), markFixed, suppressions
    pool.query
      .mockResolvedValueOnce({ rows: [{ count: 1 }] })  // countCompleted
      .mockResolvedValueOnce({ rows: [] })                // findByFingerprint
      .mockResolvedValueOnce({ rows: [PERSISTED_FINDING] }) // insert finding
      .mockResolvedValueOnce({ rowCount: 0 })             // markFixed
      .mockResolvedValueOnce({ rows: [] })                // suppressions
      .mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] }); // remaining

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    // Review should be posted with REQUEST_CHANGES for critical finding
    const reviewCall = axios.post.mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes('reviews/submit')
    );
    expect(reviewCall).toBeTruthy();
    expect(reviewCall[1].event).toBe('REQUEST_CHANGES');
    expect(reviewCall[1].body).not.toContain('**Fix code:**');
    expect(reviewCall[1].body).toContain('The finding is annotated inline on the affected line below.');
    expect(reviewCall[1].body).toContain('1 of 1 annotated inline');
    expect(reviewCall[1].body).not.toContain('**Fix:** Replace eval/exec with safe alternatives.');

    const inlineCall = axios.post.mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes('comments/inline')
    );
    expect(inlineCall).toBeTruthy();
    expect(inlineCall[1].body).not.toContain('```suggestion');
    expect(inlineCall[1].body).toContain('**Fix:** Replace eval/exec with safe alternatives.');
    expect(inlineCall[1].body).not.toContain('**Candidate fix code:**');
    expect(inlineCall[1].body).toContain('const payload = JSON.parse(req.body.code);');
  });

  test('fails run when required review publication fails', async () => {
    const routes = [
      { pattern: '/pulls/files', data: { files: [{ path: 'test_vuln.js', patch: '@@ -0,0 +1,2 @@\n+const existing = true;\n+eval(req.body.code);', additions: 2 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'test_vuln.js', content: 'const existing = true;\neval(req.body.code);\n' }] } },
      { pattern: '/tier1', data: { findings: [FINDING], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [FINDING], filtered_count: 0, tier: 3 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ];

    axios.post.mockImplementation((url) => {
      for (const route of routes) {
        if (url.includes(route.pattern)) {
          return Promise.resolve({ data: route.data });
        }
      }
      if (url.includes('reviews/submit') || url.includes('comments/inline')) {
        return Promise.reject(new Error('502 Bad Gateway'));
      }
      return Promise.resolve({ data: {} });
    });

    pool.query
      .mockResolvedValueOnce({ rows: [{ count: 1 }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [PERSISTED_FINDING] })
      .mockResolvedValueOnce({ rowCount: 0 })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    // Review failure should be logged
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('PR analysis orchestration failed'),
      expect.any(Object)
    );
    // Failed publication remains retryable.
    const updateCall = pool.query.mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes("status = 'failed'")
    );
    expect(updateCall).toBeTruthy();
  });

  test('final publication includes tier2 findings once', async () => {
    const tier2Finding = {
      ...FINDING,
      rule_id: 'opengrep.cwe-89.sql-injection',
      fingerprint: 'fp-tier2',
      title: 'SQL injection via OpenGrep',
    };

    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'test_vuln.js', patch: '@@ -0,0 +1,2 @@\n+const existing = true;\n+eval(req.body.code);', additions: 2 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'test_vuln.js', content: 'const existing = true;\neval(req.body.code);\n' }] } },
      { pattern: '/tier1', data: { findings: [FINDING], tier: 1 } },
      { pattern: '/tier2', data: { findings: [tier2Finding], tier: 2 } },
      { pattern: '/tier3', data: { findings: [FINDING, tier2Finding], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/comments/inline', data: { comment_id: 11, success: true } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);

    pool.query.mockImplementation(async (sql, values) => {
      if (sql.includes('COUNT')) return { rows: [{count: 1}] };
      if (sql.includes('SELECT id FROM findings')) return {rows: [], rowCount: 0};
      if (sql.includes('INSERT INTO findings')) return {rows: [{...PERSISTED_FINDING, id: values[6], fingerprint: values[6]}]};
      return {rows: [], rowCount: 0};
    });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    // Review should be posted at least twice (once for tier1, once for tier2)
    const reviewCalls = axios.post.mock.calls.filter(
      (call) => typeof call[0] === 'string' && call[0].includes('reviews/submit')
    );
    expect(reviewCalls).toHaveLength(1);
  });

  test('final publication includes tier3 fixes without reposting', async () => {
    const tier1Finding = {
      ...FINDING,
      rule_id: 'sql.injection.raw_query',
      title: 'Potential SQL injection',
      category: 'SQL injection',
      cwe_id: 'CWE-89',
      code_snippet: 'db.query("SELECT * FROM users WHERE id = " + userId);',
      remediation: 'Use parameterized queries.',
      remediation_patch: '',
      line_start: 2,
      line_end: 2,
      fingerprint: 'fp-sql-1',
    };

    const tier3Finding = {
      ...tier1Finding,
      remediation_patch: 'db.query("SELECT * FROM users WHERE id = ?", [userId]);',
    };

    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'test_vuln.js', patch: '@@ -0,0 +1,2 @@\n+const existing = true;\n+db.query("SELECT * FROM users WHERE id = " + userId);', additions: 2 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'test_vuln.js', content: 'const existing = true;\ndb.query("SELECT * FROM users WHERE id = " + userId);\n' }] } },
      { pattern: '/tier1', data: { findings: [tier1Finding], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [tier3Finding], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/comments/inline', data: { comment_id: 11, success: true } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);

    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });
    pool.query
      .mockResolvedValueOnce({ rows: [{ count: 1 }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ id: 'finding-1', status: 'open', is_baseline: false, ...tier1Finding }] })
      .mockResolvedValueOnce({ rowCount: 0 })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    const reviewCalls = axios.post.mock.calls.filter(
      (call) => typeof call[0] === 'string' && call[0].includes('reviews/submit')
    );
    expect(reviewCalls).toHaveLength(1);
  });

  test('tier2 receives enriched files with full content snapshots', async () => {
    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'src/app.js', patch: '@@ -1,0 +1,2 @@\n+const value = req.query.file;\n+fs.readFile(value);', additions: 2 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'src/app.js', content: 'const value = req.query.file;\nfs.readFile(value);\n' }] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [], tier: 2 } },
      { pattern: '/tier3', data: { findings: [], filtered_count: 0, tier: 3 } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    const tier2Call = axios.post.mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes('/analyze/pr/tier2')
    );
    expect(tier2Call).toBeTruthy();
    expect(tier2Call[1].files[0]).toMatchObject({
      path: 'src/app.js',
      content: 'const value = req.query.file;\nfs.readFile(value);\n',
      reviewable_line_spans: [{ start: 1, end: 2 }],
    });
  });

  test('persists tier2 evidence_details for taint-backed findings', async () => {
    const tier2Finding = {
      rule_id: 'opengrep.cwe-22.path-traversal-fs',
      internal_type: 'path_traversal',
      title: 'File system access with user-controlled path',
      description: 'Path traversal risk',
      category: 'path traversal',
      cwe_id: 'CWE-22',
      owasp_category: 'A01:2021',
      severity: 'high',
      confidence: 0.91,
      exploitability: 'high',
      file_path: 'src/download.js',
      line_start: 2,
      line_end: 2,
      code_snippet: 'fs.readFile(file)',
      evidence: 'OpenGrep AST match on rule `cwe-22.path-traversal-fs`',
      remediation: 'Validate the path against an allowlist.',
      remediation_patch: 'const file = path.basename(req.query.file);',
      fingerprint: 'fp-tier2-evidence',
      analysis_scope: 'taint-intraprocedural',
      source: 'request-controlled file path',
      sink: 'filesystem access',
      sanitizers_seen: ['path.basename'],
      trace_summary: 'Taint-tracked flow from request input into fs.readFile.',
      evidence_details: {
        analysis_scope: 'taint-intraprocedural',
        is_taint_based: true,
        source_type: 'request-controlled file path',
        source_expr: 'req.query.file',
        sink_type: 'filesystem access',
        sink_expr: 'fs.readFile(file)',
        sanitizer_exprs: ['path.basename'],
        trace_steps: [
          { kind: 'source', expr: 'req.query.file' },
          { kind: 'assignment', expr: 'const file = req.query.file' },
          { kind: 'sink', expr: 'fs.readFile(file)' },
        ],
        trace_summary: 'Taint-tracked flow from request input into fs.readFile.',
        reviewability: 'changed-lines-only',
      },
    };

    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'src/download.js', patch: '@@ -1,0 +1,2 @@\n+const file = req.query.file;\n+fs.readFile(file);', additions: 2 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'src/download.js', content: 'const file = req.query.file;\nfs.readFile(file);\n' }] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [tier2Finding], tier: 2 } },
      { pattern: '/tier3', data: { findings: [tier2Finding], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/comments/inline', data: { comment_id: 11, success: true } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);

    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });
    pool.query
      .mockResolvedValueOnce({ rows: [{ count: 1 }] }) // countCompleted
      .mockResolvedValueOnce({ rows: [] }) // findByFingerprint
      .mockResolvedValueOnce({ rows: [{ id: 'finding-tier2', status: 'open', is_baseline: false, ...tier2Finding }] }) // insert
      .mockResolvedValueOnce({ rowCount: 0 }) // markFixed
      .mockResolvedValueOnce({ rows: [] }) // suppressions
      .mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    const insertCall = pool.query.mock.calls.find(
      (call) => typeof call[0] === 'string' && call[0].includes('INSERT INTO findings')
    );
    expect(insertCall).toBeTruthy();

    const evidenceJson = insertCall[1][23];
    const parsed = JSON.parse(evidenceJson);
    expect(parsed).toMatchObject({
      analysis_scope: 'taint-intraprocedural',
      is_taint_based: true,
      source_type: 'request-controlled file path',
      source_expr: 'req.query.file',
      sink_type: 'filesystem access',
      sink_expr: 'fs.readFile(file)',
      sanitizer_exprs: ['path.basename'],
      trace_summary: 'Taint-tracked flow from request input into fs.readFile.',
      reviewability: 'changed-lines-only',
    });
    expect(parsed.trace_steps).toEqual([
      { kind: 'source', label: 'source', expr: 'req.query.file', file: 'src/download.js', line: null },
      { kind: 'assignment', label: 'assignment', expr: 'const file = req.query.file', file: 'src/download.js', line: null },
      { kind: 'sink', label: 'sink', expr: 'fs.readFile(file)', file: 'src/download.js', line: null },
    ]);
  });

  test('persists surface-decision telemetry for reviewer visibility', async () => {
    const tier2Finding = {
      ...FINDING,
      id: 'finding-surface-1',
      file_path: 'src/app.js',
      line_start: 2,
      analysis_scope: 'taint-intraprocedural',
      source: 'request-controlled input',
      sink: 'dangerous sink',
      evidence_details: {
        analysis_scope: 'taint-intraprocedural',
        reviewability: 'changed-lines-only',
        sanitizer_status: 'none',
        trace_summary: 'Request input reaches dangerous sink.',
      },
    };

    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'src/app.js', patch: '@@ -1,0 +1,2 @@\n+const value = req.query.file;\n+eval(value);', additions: 2 }] } },
      { pattern: '/files/content', data: { files: [{ path: 'src/app.js', content: 'const value = req.query.file;\neval(value);\n' }] } },
      { pattern: '/tier1', data: { findings: [], tier: 1 } },
      { pattern: '/tier2', data: { findings: [tier2Finding], tier: 2 } },
      { pattern: '/tier3', data: { findings: [tier2Finding], filtered_count: 0, tier: 3 } },
      { pattern: '/reviews/submit', data: { review_id: 1 } },
      { pattern: '/comments/inline', data: { comment_id: 11, success: true } },
      { pattern: '/check-runs', data: { check_run_id: 2 } },
    ]);

    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });
    pool.query
      .mockResolvedValueOnce({ rows: [{ count: 1 }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ status: 'open', is_baseline: false, ...tier2Finding }] })
      .mockResolvedValueOnce({ rowCount: 0 })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValue({ rowCount: 1, rows: [{ count: 1 }] });

    jest.isolateModules(() => {
      const mod = require('../src/services/prAnalysisOrchestrator');
      mod.triggerAnalysisJob(BASE_PAYLOAD);
    });
    await flushAsync();

    const surfaceUpdateCall = pool.query.mock.calls.find(
      (call) => typeof call[0] === 'string'
        && call[0].includes('SET evidence_details = COALESCE(evidence_details,')
    );
    expect(surfaceUpdateCall).toBeTruthy();

    const metadata = JSON.parse(surfaceUpdateCall[1][0]);
    expect(metadata).toEqual({
      surface_decision: 'inline',
      surface_reason: 'strong_taint_evidence',
    });
  });
});
