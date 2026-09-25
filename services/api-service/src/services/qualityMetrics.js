// The three numbers the outcome log exists to produce, and nothing else. Every function
// here is pure: it takes count rows and returns numbers, touching neither the database
// nor the clock, so the definitions can be read and tested without a schema.
//
// A rate is null, never zero, when its denominator is zero. Zero would read as "nobody
// applied our fixes"; null reads as "we published nothing to apply", which is the truth.

const COUNT_COLUMNS = [
  'findings_new', 'fixes_published', 'applied_in_app', 'applied_on_github', 'dismissed',
  'accepted_risk', 'suppressed', 'thread_resolved', 'thread_resolved_without_fix',
  'fixed_by_reanalysis', 'residual_after_apply',
];

// Counts arrive from pg as strings when the column is a bigint and as numbers when it is
// an integer, so every read goes through this.
function count(row, column) {
  const value = Number(row?.[column]);
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function ratio(numerator, denominator) {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator)) return null;
  if (denominator <= 0) return null;
  return numerator / denominator;
}

// Distinct findings that were applied, however they were applied. The two columns are
// disjoint by construction: a finding applied in the app on a day is not counted again
// under applied_on_github for that day, so the sum never double counts.
function appliedCount(row) {
  return count(row, 'applied_in_app') + count(row, 'applied_on_github');
}

// Of the fixes we published, how many did anyone take? The one number that says whether
// the fixes are worth publishing at all.
function applyRate(row) {
  return ratio(appliedCount(row), count(row, 'fixes_published'));
}

// Of the findings we raised, how many were rejected? A dismissal, a suppression, and a
// review thread closed without the finding ever being fixed all mean the same thing.
function dismissRate(row) {
  const rejected = count(row, 'dismissed')
    + count(row, 'suppressed')
    + count(row, 'thread_resolved_without_fix');
  return ratio(rejected, count(row, 'findings_new'));
}

// Of the fixes that were applied, how many left a blocking finding behind? A high
// residual rate means the fixes land but do not finish the job.
function residualRate(row) {
  return ratio(count(row, 'residual_after_apply'), appliedCount(row));
}

// Sum a set of daily rows into one. Counts add across days and across grains of the same
// kind; rates never do, which is why they are computed from the sum and not averaged.
function totals(rows = []) {
  const summed = Object.fromEntries(COUNT_COLUMNS.map((column) => [column, 0]));
  for (const row of rows) {
    if (!row) continue;
    for (const column of COUNT_COLUMNS) summed[column] += count(row, column);
  }
  return summed;
}

// The shape every caller returns: the counts that were summed, and the three rates read
// off them. `extra` carries whatever identifies the row, such as a rule id.
function summarize(rows = [], extra = {}) {
  const summed = totals(rows);
  return {
    ...extra,
    ...summed,
    applied: appliedCount(summed),
    apply_rate: applyRate(summed),
    dismiss_rate: dismissRate(summed),
    residual_rate: residualRate(summed),
  };
}

// The rules worth showing: the ones people reject most, and among equally rejected rules
// the ones that fire most. A rule with no dismiss rate has no denominator, so it sorts
// last rather than first.
function rankRules(summaries = [], limit = 20) {
  return [...summaries]
    .sort((a, b) => {
      const left = a.dismiss_rate == null ? -1 : a.dismiss_rate;
      const right = b.dismiss_rate == null ? -1 : b.dismiss_rate;
      if (left !== right) return right - left;
      return count(b, 'findings_new') - count(a, 'findings_new');
    })
    .slice(0, limit);
}

module.exports = {
  COUNT_COLUMNS, ratio, appliedCount, applyRate, dismissRate, residualRate,
  totals, summarize, rankRules,
};
