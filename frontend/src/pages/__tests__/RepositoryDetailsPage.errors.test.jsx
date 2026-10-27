import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { beforeEach, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ get: vi.fn(), listPRs: vi.fn() }))
vi.mock('../../services/api', () => ({ repositoryAPI: { get: api.get, listPRs: api.listPRs } }))

import RepositoryDetailsPage from '../RepositoryDetailsPage'

const renderPage = () => render(
  <MemoryRouter initialEntries={['/dashboard/repositories/repo-1']}>
    <Routes>
      <Route path="/dashboard/repositories/:repositoryId" element={<RepositoryDetailsPage />} />
    </Routes>
  </MemoryRouter>
)

beforeEach(() => {
  vi.clearAllMocks()
  api.get.mockResolvedValue({ repository: { full_name: 'acme/api' } })
  api.listPRs.mockResolvedValue({ pull_requests: [] })
})

it('says the repository was not found on a 404 instead of loading forever', async () => {
  api.get.mockRejectedValue({ response: { status: 404 } })
  renderPage()

  expect(await screen.findByRole('alert')).toHaveTextContent('Repository not found')
  expect(screen.queryByText('Loading repository...')).toBeNull()
})

it('shows an error when the pull request list fails', async () => {
  api.listPRs.mockRejectedValue({ response: { status: 500 } })
  renderPage()

  expect(await screen.findByRole('alert')).toHaveTextContent('Could not load this repository')
  expect(screen.queryByText('Loading repository...')).toBeNull()
  expect(screen.queryByText('No pull requests yet.')).toBeNull()
})
