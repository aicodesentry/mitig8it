import { describe, expect, it } from 'vitest'
import { confidenceLabel } from '../confidence'

const finding = (rulePrecision) => ({
  confidence: 0.8,
  evidence_details: rulePrecision ? { extra: { rule_precision: rulePrecision } } : {},
})

describe('confidenceLabel', () => {
  it('names a measured precision and how many reviewed findings it rests on', () => {
    expect(confidenceLabel(finding({ basis: 'measured', precision: 0.65, outcomes: 22, minimum_outcomes: 20 })))
      .toBe('65% (measured on 22 reviewed findings)')
  })

  it('never presents a static prior as a measurement', () => {
    expect(confidenceLabel(finding({ basis: 'static_prior', outcomes: 3, minimum_outcomes: 20 })))
      .toBe('80% (rule prior, not yet measured: 3 of 20 reviewed findings)')
  })

  it('is the bare percentage when the finding carries no calibration', () => {
    expect(confidenceLabel(finding(undefined))).toBe('80%')
    expect(confidenceLabel({ confidence: 0.9 })).toBe('90%')
  })
})
