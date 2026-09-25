import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ExamplesPage from '../ExamplesPage'

const authState = vi.hoisted(() => ({
  loginWithGitHub: vi.fn(),
  user: null,
}))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => authState,
}))

vi.mock('../../components/Header', () => ({
  default: () => <div>Header</div>,
}))

vi.mock('../../components/Footer', () => ({
  default: () => <div>Footer</div>,
}))

describe('ExamplesPage', () => {
  beforeEach(() => {
    authState.loginWithGitHub = vi.fn()
    authState.user = null
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <ExamplesPage />
      </MemoryRouter>
    )

  it('leads with the sample review and one line of copy', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'A sample review', level: 1 })).toBeInTheDocument()
    expect(
      screen.getByText('What a pull request looks like after Mitig8it has reviewed it.')
    ).toBeInTheDocument()
    expect(screen.getByText('mitig8it[bot]')).toBeInTheDocument()
    expect(screen.getByText('Suggested change')).toBeInTheDocument()
  })

  it('shows the real pull request screenshot with its caption', () => {
    renderPage()

    expect(
      screen.getByRole('img', { name: 'A Mitig8it review comment on a GitHub pull request' })
    ).toBeInTheDocument()
    expect(
      screen.getByText('A real finding on the pull request that introduced it.')
    ).toBeInTheDocument()
  })

  it('claims nothing that is not shipped', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'In every review' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Inline findings' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Severity and confidence' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Verified fixes' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'One-click apply' })).toBeInTheDocument()

    expect(screen.queryByText('Coming soon')).toBeNull()
    expect(screen.queryByText('In progress')).toBeNull()
    expect(screen.getAllByText('Live now').length).toBe(4)
  })

  it('closes with the shared call to action', () => {
    renderPage()

    expect(screen.getByRole('button', { name: 'Start with GitHub' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'See sample review' })).toHaveAttribute(
      'href',
      '/examples'
    )
  })

  it('offers the workspace to signed-in visitors', () => {
    authState.user = { github_username: 'neha' }

    renderPage()

    expect(screen.getByRole('link', { name: 'Open workspace' })).toHaveAttribute(
      'href',
      '/dashboard'
    )
    expect(screen.queryByRole('button', { name: 'Start with GitHub' })).toBeNull()
  })
})
