import { describe, expect, it } from 'vitest'
import { severityStyle } from '../PullRequestFindingsPage'

describe('severity rendering', () => {
  it('keeps informational findings grey', () => {
    expect(severityStyle('info')).toContain('neutral')
    expect(severityStyle('info')).not.toContain('red')
    expect(severityStyle('info')).not.toContain('orange')
  })

  it('leaves the existing severities alone', () => {
    expect(severityStyle('critical')).toContain('red')
    expect(severityStyle('high')).toContain('orange')
    expect(severityStyle('medium')).toContain('amber')
    expect(severityStyle('low')).toContain('sky')
  })

  it('falls back to the informational style for unknown severities', () => {
    expect(severityStyle('nonsense')).toBe(severityStyle('info'))
    expect(severityStyle(undefined)).toBe(severityStyle('info'))
  })
})
