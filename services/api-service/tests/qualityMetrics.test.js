const quality = require('../src/services/qualityMetrics');

function row(overrides = {}) {
  return {
    findings_new: 0, fixes_published: 0, applied_in_app: 0, applied_on_github: 0,
    dismissed: 0, accepted_risk: 0, suppressed: 0, thread_resolved: 0,
    thread_resolved_without_fix: 0, fixed_by_reanalysis: 0, residual_after_apply: 0,
    ...overrides,
  };
}

describe('applyRate', () => {
  test('counts a fix applied either way against the fixes that were published', () => {
    expect(quality.applyRate(row({ fixes_published: 10, applied_in_app: 3, applied_on_github: 2 }))).toBe(0.5);
  });

  test('is null rather than zero when nothing was published', () => {
    expect(quality.applyRate(row({ applied_in_app: 4 }))).toBeNull();
  });

  test('is zero when fixes were published and none were taken', () => {
    expect(quality.applyRate(row({ fixes_published: 6 }))).toBe(0);
  });

  test('reads counts that arrive from pg as strings', () => {
    expect(quality.applyRate(row({ fixes_published: '4', applied_in_app: '1', applied_on_github: '1' }))).toBe(0.5);
  });
});

describe('dismissRate', () => {
  test('counts dismissals, suppressions and threads resolved without a fix', () => {
    const summary = row({
      findings_new: 20, dismissed: 4, suppressed: 3, thread_resolved: 9, thread_resolved_without_fix: 3,
    });
    expect(quality.dismissRate(summary)).toBe(0.5);
  });

  test('ignores a resolved thread that had a fix behind it', () => {
    expect(quality.dismissRate(row({ findings_new: 10, thread_resolved: 5, thread_resolved_without_fix: 0 }))).toBe(0);
  });

  test('is null rather than zero when no finding was raised', () => {
    expect(quality.dismissRate(row({ dismissed: 2 }))).toBeNull();
  });
});

describe('residualRate', () => {
  test('measures the residue against the fixes that were actually applied', () => {
    expect(quality.residualRate(row({ applied_in_app: 6, applied_on_github: 2, residual_after_apply: 2 }))).toBe(0.25);
  });

  test('is null rather than zero when nothing was applied', () => {
    expect(quality.residualRate(row({ residual_after_apply: 3 }))).toBeNull();
  });
});

describe('totals', () => {
  test('adds every count column across days', () => {
    const summed = quality.totals([
      row({ findings_new: 2, dismissed: 1 }),
      row({ findings_new: 3, dismissed: 2, suppressed: 1 }),
    ]);
    expect(summed.findings_new).toBe(5);
    expect(summed.dismissed).toBe(3);
    expect(summed.suppressed).toBe(1);
  });

  test('tolerates a null row', () => {
    expect(quality.totals([null, row({ findings_new: 1 })]).findings_new).toBe(1);
  });

  test('an empty window sums to zero on every column', () => {
    const summed = quality.totals([]);
    for (const column of quality.COUNT_COLUMNS) expect(summed[column]).toBe(0);
  });
});

describe('summarize', () => {
  test('computes the rates from the sum rather than averaging daily rates', () => {
    // Averaging the two days would give 0.75; the honest number is 4 of 5.
    const summary = quality.summarize([
      row({ fixes_published: 4, applied_in_app: 3 }),
      row({ fixes_published: 1, applied_in_app: 1 }),
    ]);
    expect(summary.apply_rate).toBe(0.8);
    expect(summary.applied).toBe(4);
  });

  test('an empty window reports every rate as null, not zero', () => {
    const summary = quality.summarize([]);
    expect(summary.apply_rate).toBeNull();
    expect(summary.dismiss_rate).toBeNull();
    expect(summary.residual_rate).toBeNull();
    expect(summary.findings_new).toBe(0);
  });

  test('carries the identity it is given', () => {
    expect(quality.summarize([], { rule_id: 'sql-injection' }).rule_id).toBe('sql-injection');
  });
});

describe('rankRules', () => {
  test('orders by dismiss rate, then by how often the rule fired', () => {
    const rules = [
      quality.summarize([row({ findings_new: 10, dismissed: 1 })], { rule_id: 'low' }),
      quality.summarize([row({ findings_new: 10, dismissed: 5 })], { rule_id: 'noisy-quiet' }),
      quality.summarize([row({ findings_new: 40, dismissed: 20 })], { rule_id: 'noisy-loud' }),
    ];
    expect(quality.rankRules(rules).map((rule) => rule.rule_id))
      .toEqual(['noisy-loud', 'noisy-quiet', 'low']);
  });

  test('a rule with no denominator sorts last rather than first', () => {
    const rules = [
      quality.summarize([row({ dismissed: 1 })], { rule_id: 'no-findings' }),
      quality.summarize([row({ findings_new: 10 })], { rule_id: 'never-dismissed' }),
    ];
    expect(quality.rankRules(rules).map((rule) => rule.rule_id))
      .toEqual(['never-dismissed', 'no-findings']);
  });

  test('keeps at most the requested number of rules', () => {
    const rules = Array.from({ length: 30 }, (_, index) =>
      quality.summarize([row({ findings_new: 10, dismissed: index })], { rule_id: `rule-${index}` }));
    expect(quality.rankRules(rules, 20)).toHaveLength(20);
    expect(quality.rankRules(rules, 20)[0].rule_id).toBe('rule-29');
  });

  test('does not reorder the array it was given', () => {
    const rules = [
      quality.summarize([row({ findings_new: 10, dismissed: 1 })], { rule_id: 'a' }),
      quality.summarize([row({ findings_new: 10, dismissed: 9 })], { rule_id: 'b' }),
    ];
    quality.rankRules(rules);
    expect(rules.map((rule) => rule.rule_id)).toEqual(['a', 'b']);
  });
});

describe('ratio', () => {
  test('refuses a zero, negative or unusable denominator', () => {
    expect(quality.ratio(1, 0)).toBeNull();
    expect(quality.ratio(1, -3)).toBeNull();
    expect(quality.ratio(1, Number.NaN)).toBeNull();
  });
});
