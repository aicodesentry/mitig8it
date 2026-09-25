import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AboutPage from '../AboutPage'

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

describe('AboutPage', () => {
  beforeEach(() => {
    authState.loginWithGitHub = vi.fn()
    authState.user = null
  })

  const renderPage = () =>
    render(
      <MemoryRouter>
        <AboutPage />
      </MemoryRouter>
    )

  it('states why the product exists in one line', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'Why Mitig8it exists', level: 1 })).toBeInTheDocument()
    expect(
      screen.getByText('Security review belongs in the pull request, with the fix attached.')
    ).toBeInTheDocument()
  })

  it('renders the three principles', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'Start in the pull request' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Fix, do not just flag' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Keep developers in control' })).toBeInTheDocument()
    expect(
      screen.getByText('Every finding ships with a proven, one-click fix.')
    ).toBeInTheDocument()
  })

  it('separates what is live from what is staged', () => {
    renderPage()

    expect(screen.getByRole('heading', { name: 'Live today' })).toBeInTheDocument()
    expect(screen.getByText('Nothing is applied or merged automatically.')).toBeInTheDocument()
    expect(screen.getAllByText('Live now').length).toBe(4)

    expect(screen.getByRole('heading', { name: 'Staged' })).toBeInTheDocument()
    expect(screen.getByText('More languages and rule families')).toBeInTheDocument()
    expect(
      screen.getByText('Merge-when-ready (parked, human approval required)')
    ).toBeInTheDocument()
    expect(screen.getAllByText('In progress').length).toBe(2)
  })

  it('never advertises anything as coming soon', () => {
    renderPage()

    expect(screen.queryByText('Coming soon')).toBeNull()
  })

  it('closes with the shared call to action', () => {
    renderPage()

    expect(screen.getByRole('button', { name: 'Start with GitHub' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'See sample review' })).toHaveAttribute(
      'href',
      '/examples'
    )
  })
})
