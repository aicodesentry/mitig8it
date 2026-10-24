import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  listByPR: vi.fn(),
  createSuppression: vi.fn(),
}))

vi.mock('../../services/api', () => ({
  findingAPI: { listByPR: api.listByPR },
  suppressionAPI: { create: api.createSuppression },
  DISMISSAL_REASONS: [
    { value: 'not_exploitable', label: 'Not exploitable here' },
    { value: 'test_or_sample_code', label: 'Test or sample code' },
    { value: 'wrong_rule_match', label: 'Wrong rule match' },
    { value: 'other', label: 'Other' },
  ],
}))

vi.mock('../../components/RemediationPanel', () => ({ default: () => null }))
vi.mock('../../services/privateCache', () => ({ getPrivateCacheEpoch: () => 1 }))

import PullRequestFindingsPage, { severityStyle } from '../PullRequestFindingsPage'

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

describe('suppressing a finding', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.listByPR.mockResolvedValue({
      findings: [{
        id: 'finding-1',
        repository_id: 'repo-1',
        title: 'SQL injection',
        category: 'SQL injection',
        severity: 'high',
        confidence: 0.9,
      }],
      pull_request: { head_sha: 'abc' },
    })
    api.createSuppression.mockResolvedValue({})
  })

  const renderPage = () => render(
    <MemoryRouter><PullRequestFindingsPage /></MemoryRouter>
  )

  it('asks for a reason before suppressing', async () => {
    renderPage()
    await screen.findByText('SQL injection')

    expect(screen.queryByLabelText('Reason')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Suppress' }))
    expect(screen.getByLabelText('Reason')).toBeTruthy()
    expect(api.createSuppression).not.toHaveBeenCalled()
  })

  it('sends the chosen reason rather than a hard-coded one', async () => {
    renderPage()
    await screen.findByText('SQL injection')

    fireEvent.click(screen.getByRole('button', { name: 'Suppress' }))
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'wrong_rule_match' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm suppress' }))

    await waitFor(() => expect(api.createSuppression).toHaveBeenCalledTimes(1))
    expect(api.createSuppression).toHaveBeenCalledWith(
      expect.objectContaining({ finding_id: 'finding-1', repository_id: 'repo-1', reason: 'wrong_rule_match' })
    )
  })

  it('marks the finding suppressed after a confirmed suppression', async () => {
    api.createSuppression.mockResolvedValue({ suppression: { id: 'sup-1', finding_id: 'finding-1' } })
    renderPage()
    await screen.findByText('SQL injection')

    fireEvent.click(screen.getByRole('button', { name: 'Suppress' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm suppress' }))

    // The reload returns the finding unchanged: a suppression row does not change the
    // finding's status until the next analysis applies it.
    expect(await screen.findByTestId('suppressed-badge-finding-1')).toHaveTextContent('Suppressed')
    expect(screen.getByText(/takes effect on the next analysis/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Suppress' })).toBeNull()
  })

  it('does not mark the finding when the suppression fails', async () => {
    api.createSuppression.mockRejectedValue(new Error('403'))
    renderPage()
    await screen.findByText('SQL injection')

    fireEvent.click(screen.getByRole('button', { name: 'Suppress' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm suppress' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not suppress')
    expect(screen.queryByTestId('suppressed-badge-finding-1')).toBeNull()
  })

  it('shows a finding an analysis already suppressed', async () => {
    api.listByPR.mockResolvedValue({
      findings: [{
        id: 'finding-1', repository_id: 'repo-1', title: 'SQL injection', category: 'SQL injection',
        severity: 'high', confidence: 0.9, status: 'dismissed', suppression_applied: true,
      }],
      pull_request: { head_sha: 'abc' },
    })
    renderPage()

    expect(await screen.findByTestId('suppressed-badge-finding-1')).toHaveTextContent('Suppressed')
    expect(screen.queryByRole('button', { name: 'Suppress' })).toBeNull()
  })

  it('offers every reason the API accepts', async () => {
    renderPage()
    await screen.findByText('SQL injection')
    fireEvent.click(screen.getByRole('button', { name: 'Suppress' }))

    const values = [...screen.getByLabelText('Reason').options].map((option) => option.value)
    expect(values).toEqual(['not_exploitable', 'test_or_sample_code', 'wrong_rule_match', 'other'])
  })
})
