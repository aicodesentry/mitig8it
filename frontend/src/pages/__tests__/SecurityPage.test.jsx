import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import SecurityPage from '../SecurityPage'

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

describe('SecurityPage', () => {
  beforeEach(() => {
    authState.loginWithGitHub = vi.fn()
    authState.user = null
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <SecurityPage />
      </MemoryRouter>
    )

  it('states the boundaries in the hero', () => {
    renderPage()

    expect(
      screen.getByRole('heading', { name: 'What Mitig8it reads, writes, and keeps', level: 1 })
    ).toBeInTheDocument()
    expect(
      screen.getByText('The exact boundaries of the app, stated plainly.')
    ).toBeInTheDocument()
  })

  it('renders every boundary section', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'What it reads' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'What it writes' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'How a fix is verified' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Model calls' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Data kept' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Access' })).toBeInTheDocument()
  })

  it('shows the row that rules out unattended commits and merges', () => {
    renderPage()

    expect(screen.getByText('It never commits or merges on its own.')).toBeInTheDocument()
  })

  it('is honest about the verification sandbox', () => {
    renderPage()

    expect(
      screen.getByText(/development-grade local sandbox, without kernel isolation/i)
    ).toBeInTheDocument()
    expect(screen.getByText('Prove')).toBeInTheDocument()
    expect(screen.getByText('Regression test in a sandbox')).toBeInTheDocument()
  })

  it('advertises nothing as in progress or coming soon', () => {
    renderPage()

    expect(screen.queryByText('Coming soon')).toBeNull()
    expect(screen.queryByText('In progress')).toBeNull()
  })

  it('offers a security contact', () => {
    renderPage()

    expect(screen.getByRole('link', { name: 'support@mitig8it.com' })).toHaveAttribute(
      'href',
      'mailto:support@mitig8it.com'
    )
  })

  it('starts auth for signed-out visitors', () => {
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Start with GitHub' }))
    expect(authState.loginWithGitHub).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('link', { name: 'Open workspace' })).toBeNull()
  })

  it('opens the workspace for signed-in visitors', () => {
    authState.user = { github_username: 'neha' }

    renderPage()

    expect(screen.getByRole('link', { name: 'Open workspace' })).toHaveAttribute(
      'href',
      '/dashboard'
    )
    expect(screen.queryByRole('button', { name: 'Start with GitHub' })).toBeNull()
  })
})
