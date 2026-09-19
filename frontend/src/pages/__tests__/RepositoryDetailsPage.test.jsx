import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { expect, it, vi } from 'vitest'
import RepositoryDetailsPage from '../RepositoryDetailsPage'
vi.mock('../../services/api', () => ({ repositoryAPI: {
  get: vi.fn().mockResolvedValue({ repository: { full_name: 'test/repo' } }),
  listPRs: vi.fn().mockResolvedValue({ pull_requests: [{ id: 1, critical_count: '2', high_count: '3' }] })
} }))
it('adds PostgreSQL string counts numerically', async () => {
  render(<MemoryRouter><RepositoryDetailsPage /></MemoryRouter>)
  expect(await screen.findByText('5')).toBeInTheDocument()
})
