import { act, render, screen } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import ReportsPage from '../ReportsPage'
import { reportsAPI, repositoryAPI } from '../../services/api'
const auth = vi.hoisted(() => ({ user: { id: 'A' } }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../../services/api', () => ({
  reportsAPI: { getPRAnalyses: vi.fn(), getSummary: vi.fn(), getQuality: vi.fn() },
  repositoryAPI: { getRepositories: vi.fn() },
  formatRate: (rate) => (typeof rate === 'number' && Number.isFinite(rate) ? `${Math.round(rate * 100)}%` : 'n/a'),
}))
beforeEach(() => {
  localStorage.clear(); vi.clearAllMocks(); auth.user = { id: 'A' }
  reportsAPI.getSummary.mockResolvedValue({ summary: null })
  reportsAPI.getQuality.mockResolvedValue({ overall: null, by_rule: [] })
  repositoryAPI.getRepositories.mockResolvedValue({ repositories: [] })
})
it('never displays legacy private caches for a signed-in account', async () => {
  localStorage.setItem('reports_cache_main', JSON.stringify({ data: [{ id: 1, repository_name: 'secret-A' }], timestamp: Date.now(), total: 1 }))
  reportsAPI.getPRAnalyses.mockResolvedValue({ analyses: [], total: 0 })
  render(<ReportsPage />)
  expect(screen.queryByText('secret-A')).not.toBeInTheDocument()
  await screen.findByText(/No analyses found/)
})
it('discards an earlier account request after switching accounts', async () => {
  let resolveA
  reportsAPI.getPRAnalyses.mockImplementationOnce(() => new Promise(resolve => { resolveA = resolve }))
    .mockResolvedValue({ analyses: [], total: 0 })
  const view = render(<ReportsPage />)
  auth.user = { id: 'B' }; view.rerender(<ReportsPage />)
  await act(async () => resolveA({ analyses: [{ id: 1, repository_name: 'secret-A' }], total: 1 }))
  expect(screen.queryByText('secret-A')).not.toBeInTheDocument()
  expect(Object.values(localStorage).join('')).not.toContain('secret-A')
})
it('clears rendered account data immediately even when the next account refresh fails', async () => {
  reportsAPI.getPRAnalyses.mockResolvedValueOnce({ analyses: [{ id: 1, repository_name: 'secret-A' }], total: 1 })
  const view = render(<ReportsPage />)
  await screen.findByText('secret-A')
  reportsAPI.getPRAnalyses.mockRejectedValueOnce(new Error('offline'))
  const log = vi.spyOn(console, 'error').mockImplementation(() => {})
  auth.user = { id: 'B' }; view.rerender(<ReportsPage />)
  expect(screen.queryByText('secret-A')).not.toBeInTheDocument()
  await screen.findByText(/Failed to load reports/)
  expect(screen.queryByText('secret-A')).not.toBeInTheDocument()
  log.mockRestore()
})
it('does not restore private caches when an outstanding request completes after logout', async () => {
  const { clearPrivateCaches } = await import('../../services/privateCache')
  let resolve
  reportsAPI.getPRAnalyses.mockImplementationOnce(() => new Promise(done => { resolve = done }))
  render(<ReportsPage />)
  clearPrivateCaches()
  await act(async () => resolve({ analyses: [{ id: 1, repository_name: 'secret-A' }], total: 1 }))
  expect(screen.queryByText('secret-A')).not.toBeInTheDocument()
  expect(Object.keys(localStorage).filter(key => key.startsWith('reports_cache_'))).toEqual([])
})

const RULES = [
  { rule_id: 'weak-hash', findings_new: 12, dismiss_rate: 0.75, apply_rate: 0.1 },
  { rule_id: 'sql-injection', findings_new: 30, dismiss_rate: 0.05, apply_rate: null },
]

it('lists the rules by dismiss rate in the order the API returned them', async () => {
  reportsAPI.getPRAnalyses.mockResolvedValue({ analyses: [], total: 0 })
  reportsAPI.getQuality.mockResolvedValue({ overall: null, by_rule: RULES })
  render(<ReportsPage />)
  await screen.findByText('Rules by dismiss rate')
  const rules = screen.getAllByText(/weak-hash|sql-injection/).map(node => node.textContent)
  expect(rules).toEqual(['weak-hash', 'sql-injection'])
  expect(screen.getByText('75%')).toBeInTheDocument()
  expect(screen.getByText('12')).toBeInTheDocument()
})

it('shows n/a for a rule rate with no denominator', async () => {
  reportsAPI.getPRAnalyses.mockResolvedValue({ analyses: [], total: 0 })
  reportsAPI.getQuality.mockResolvedValue({ overall: null, by_rule: RULES })
  render(<ReportsPage />)
  await screen.findByText('Rules by dismiss rate')
  expect(screen.getByText('n/a')).toBeInTheDocument()
})

it('hides the rule table entirely when there is nothing to rank', async () => {
  reportsAPI.getPRAnalyses.mockResolvedValue({ analyses: [], total: 0 })
  render(<ReportsPage />)
  await screen.findByText(/No analyses found/)
  expect(screen.queryByText('Rules by dismiss rate')).not.toBeInTheDocument()
})

it('reads the thirty day window across every repository by default', async () => {
  reportsAPI.getPRAnalyses.mockResolvedValue({ analyses: [], total: 0 })
  render(<ReportsPage />)
  await screen.findByText(/No analyses found/)
  expect(reportsAPI.getQuality).toHaveBeenCalledWith({ window: 30 })
})

it('keeps the rule table empty when the quality report fails', async () => {
  const log = vi.spyOn(console, 'error').mockImplementation(() => {})
  reportsAPI.getPRAnalyses.mockResolvedValue({ analyses: [], total: 0 })
  reportsAPI.getQuality.mockRejectedValue(new Error('offline'))
  render(<ReportsPage />)
  await screen.findByText(/No analyses found/)
  expect(screen.queryByText('Rules by dismiss rate')).not.toBeInTheDocument()
  log.mockRestore()
})
