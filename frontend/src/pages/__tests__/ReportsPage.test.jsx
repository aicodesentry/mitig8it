import { act, render, screen } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import ReportsPage from '../ReportsPage'
import { reportsAPI, repositoryAPI } from '../../services/api'
const auth = vi.hoisted(() => ({ user: { id: 'A' } }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../../services/api', () => ({ reportsAPI: { getPRAnalyses: vi.fn(), getSummary: vi.fn() }, repositoryAPI: { getRepositories: vi.fn() } }))
beforeEach(() => {
  localStorage.clear(); vi.clearAllMocks(); auth.user = { id: 'A' }
  reportsAPI.getSummary.mockResolvedValue({ summary: null })
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
