const { __private } = require('../src/services/prAnalysisOrchestrator');

// The ten-repository trial read 65 comments and 40 of them said one sentence twice: the
// headline, then the same words again after "Fix:". The rules set a finding's title,
// description and remediation from one rule message, so a renderer that prints all three
// unconditionally repeats itself on every rule that does. Both renderers drop a field that
// repeats what the reader has already been shown; the Action's copy of this rule lives in
// `action/orchestrator/run.py` and its own test asserts the same shapes.
const finding = (over = {}) => ({
  title: 'EJS unescaped output tag. `<%-` writes raw HTML; use `<%=` so the value is escaped',
  description: 'EJS unescaped output tag. `<%-` writes raw HTML; use `<%=` so the value is escaped',
  remediation: 'EJS unescaped output tag. `<%-` writes raw HTML; use `<%=` so the value is escaped',
  evidence: 'OpenGrep AST match on rule `cwe-79.ejs-unescaped-output`',
  severity: 'high', confidence: 0.9, cwe_id: 'CWE-79', file_path: 'views/admin.ejs', line_start: 17,
  ...over,
});

const build = (over) => __private.buildReviewComment(finding(over), {});
const occurrences = (body, sentence) => body.split(sentence).length - 1;

describe('a finding comment says each thing once', () => {
  test('a remediation that repeats the title is dropped', () => {
    const body = build();
    expect(occurrences(body, 'EJS unescaped output tag')).toBe(1);
    expect(body).not.toContain('**Fix:**');
  });

  test('a remediation that adds something is kept', () => {
    const body = build({ remediation: 'Replace `<%-` with `<%=` on this line.' });
    expect(body).toContain('**Fix:** Replace');
    expect(occurrences(body, 'EJS unescaped output tag')).toBe(1);
  });

  test('spacing and a trailing stop do not make a repeat look different', () => {
    const body = build({ remediation: '  EJS unescaped output tag. `<%-` writes raw HTML; use `<%=` so the value is escaped.  ' });
    expect(body).not.toContain('**Fix:**');
  });

  test('the evidence line is never dropped, because it says where the match came from', () => {
    expect(build()).toContain('OpenGrep AST match');
  });
});
