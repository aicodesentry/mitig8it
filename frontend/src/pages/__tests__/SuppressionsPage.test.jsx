import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ list: vi.fn(), remove: vi.fn() }))
vi.mock('../../services/api', () => ({ suppressionAPI: { list: api.list, remove: api.remove } }))

import SuppressionsPage from '../SuppressionsPage'

const SUPPRESSION = { id: 'sup-1', title: 'SQL injection', fingerprint: 'a'.repeat(64), reason: 'wrong_rule_match' }

beforeEach(() => {
  vi.clearAllMocks()
  api.list.mockResolvedValue({ suppressions: [SUPPRESSION] })
})

it('shows an error, not the empty state, when the list fails', async () => {
  api.list.mockRejectedValue({ response: { status: 500 } })
  render(<SuppressionsPage />)

  expect(await screen.findByRole('alert')).toHaveTextContent('Could not load suppressions')
  expect(screen.queryByText('No suppressions configured.')).toBeNull()
})

it('shows the empty state only after a successful empty load', async () => {
  api.list.mockResolvedValue({ suppressions: [] })
  render(<SuppressionsPage />)

  expect(await screen.findByText('No suppressions configured.')).toBeInTheDocument()
  expect(screen.queryByRole('alert')).toBeNull()
})

it('shows an error and keeps the row when removing fails', async () => {
  api.remove.mockRejectedValue({ response: { status: 403 } })
  render(<SuppressionsPage />)
  await screen.findByText('SQL injection')

  fireEvent.click(screen.getByRole('button', { name: 'Remove' }))

  expect(await screen.findByRole('alert')).toHaveTextContent('Could not remove this suppression')
  expect(screen.getByText('SQL injection')).toBeInTheDocument()
})
