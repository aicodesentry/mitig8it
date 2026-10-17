// The confidence a finding carries, with where it came from. Once the API's
// RULE_CALIBRATION_ENABLED is on, the analysis service records the rule's precision on the
// finding (evidence_details.extra.rule_precision): measured from reviewed findings, or the
// rule's static prior until it has enough of them. A hand-set constant is never shown as if it
// were a measurement. Without that record the percentage is shown on its own, as before.
// A measured precision is what is printed when there is one; `confidence` stays the static
// constant the API's inline-comment gate reads, so it is not overwritten upstream.
export function confidencePercent(finding) {
  const precision = finding?.evidence_details?.extra?.rule_precision
  const measured = precision?.basis === 'measured' ? Number(precision.precision) : NaN
  return Math.round((Number.isFinite(measured) ? measured : Number(finding?.confidence)) * 100)
}

export function confidenceBasis(finding) {
  const precision = finding?.evidence_details?.extra?.rule_precision
  if (!precision || typeof precision !== 'object') return ''
  const outcomes = Number(precision.outcomes) || 0
  const minimum = Number(precision.minimum_outcomes) || 0
  if (precision.basis === 'measured') {
    return `measured on ${outcomes} reviewed finding${outcomes === 1 ? '' : 's'}`
  }
  if (precision.basis === 'static_prior') {
    return `rule prior, not yet measured: ${outcomes} of ${minimum} reviewed findings`
  }
  return ''
}

export function confidenceLabel(finding) {
  const basis = confidenceBasis(finding)
  return basis ? `${confidencePercent(finding)}% (${basis})` : `${confidencePercent(finding)}%`
}
