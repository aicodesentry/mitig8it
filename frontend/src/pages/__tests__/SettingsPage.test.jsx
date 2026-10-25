import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ list: vi.fn(), sync: vi.fn() }))
vi.mock('../../services/api', () => ({ installationAPI: { list: api.list, sync: api.sync } }))

import SettingsPage from '../SettingsPage'

beforeEach(() => {
  vi.clearAllMocks()
  api.list.mockResolvedValue({
    installations: [{ id: 1, account_login: 'acme', account_type: 'Organization', status: 'active' }],
  })
})

it('shows an error, not the empty state, when the installation list fails', async () => {
  api.list.mockRejectedValue({ response: { status: 500 } })
  render(<SettingsPage />)

  expect(await screen.findByRole('alert')).toHaveTextContent('Could not load installations')
  expect(screen.queryByText('No installations found.')).toBeNull()
})

it('shows the empty state only after a successful empty load', async () => {
  api.list.mockResolvedValue({ installations: [] })
  render(<SettingsPage />)

  expect(await screen.findByText('No installations found.')).toBeInTheDocument()
  expect(screen.queryByRole('alert')).toBeNull()
})

it('shows an error when Sync now fails', async () => {
  api.sync.mockRejectedValue({ response: { status: 502 } })
  render(<SettingsPage />)
  await screen.findByText('acme')

  fireEvent.click(screen.getByRole('button', { name: 'Sync now' }))

  expect(await screen.findByRole('alert')).toHaveTextContent('Could not sync installations')
  expect(screen.getByText('acme')).toBeInTheDocument()
})
