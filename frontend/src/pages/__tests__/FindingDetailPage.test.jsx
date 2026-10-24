import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  get: vi.fn(),
  updateStatus: vi.fn(),
}))

vi.mock('../../services/api', () => ({
  findingAPI: { get: api.get, updateStatus: api.updateStatus },
  DISMISSAL_REASONS: [
    { value: 'not_exploitable', label: 'Not exploitable here' },
    { value: 'test_or_sample_code', label: 'Test or sample code' },
    { value: 'wrong_rule_match', label: 'Wrong rule match' },
    { value: 'other', label: 'Other' },
  ],
}))

vi.mock('../../components/RemediationPanel', () => ({ default: () => null }))

import FindingDetailPage from '../FindingDetailPage'

const FINDING = {
  id: 'finding-1',
  title: 'SQL injection',
  category: 'SQL injection',
  severity: 'high',
  confidence: 0.9,
  status: 'open',
  dismissal_reason: null,
  repository_full_name: 'acme/api',
  pr_number: 42,
  pull_request_id: 'pr-1',
}

// The bare UPDATE ... RETURNING * row: no repository name, and the PR number under its
// column name. An older API revision still returns this shape.
const BARE_ROW = {
  id: 'finding-1',
  title: 'SQL injection',
  category: 'SQL injection',
  severity: 'high',
  confidence: 0.9,
  pull_request_id: 'pr-1',
  pull_request_number: 42,
}

const renderPage = () => render(
  <MemoryRouter initialEntries={['/dashboard/findings/finding-1']}>
    <Routes>
      <Route path="/dashboard/findings/:findingId" element={<FindingDetailPage />} />
    </Routes>
  </MemoryRouter>
)

beforeEach(() => {
  vi.clearAllMocks()
  api.get.mockResolvedValue({ finding: FINDING })
})

describe('status changes', () => {
  it('keeps the repository name and PR number in the header after a dismissal', async () => {
    api.updateStatus.mockResolvedValue({
      finding: { ...BARE_ROW, status: 'dismissed', dismissal_reason: 'not_exploitable' },
    })
    renderPage()
    await screen.findByText('SQL injection', { selector: 'h1' })

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))

    expect(await screen.findByTestId('finding-status')).toHaveTextContent('Dismissed')
    expect(screen.getByTestId('finding-status')).toHaveTextContent('Not exploitable here')
    expect(screen.getByText(/acme\/api/)).toHaveTextContent('acme/api • PR #42')
    expect(screen.queryByText(/undefined/)).toBeNull()
  })

  it.each([
    ['Accept Risk', 'accepted_risk', 'Accepted risk'],
    ['Mark Fixed', 'fixed', 'Fixed'],
    ['Mark Open', 'open', 'Open'],
  ])('keeps the header after %s', async (button, status, label) => {
    api.updateStatus.mockResolvedValue({ finding: { ...BARE_ROW, status, dismissal_reason: null } })
    renderPage()
    await screen.findByText('SQL injection', { selector: 'h1' })

    fireEvent.click(screen.getByRole('button', { name: button }))

    await vi.waitFor(() => expect(api.updateStatus).toHaveBeenCalledWith('finding-1', status, null))
    expect(await screen.findByTestId('finding-status')).toHaveTextContent(label)
    expect(screen.getByText(/acme\/api/)).toHaveTextContent('acme/api • PR #42')
  })

  it('shows the current status on load', async () => {
    api.get.mockResolvedValue({
      finding: { ...FINDING, status: 'dismissed', dismissal_reason: 'wrong_rule_match' },
    })
    renderPage()

    expect(await screen.findByTestId('finding-status')).toHaveTextContent('Dismissed')
    expect(screen.getByTestId('finding-status')).toHaveTextContent('Wrong rule match')
  })
})
