import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import HomePage from '../HomePage'
import PullRequestReviewPreview from '../PullRequestReviewPreview'

const authState = vi.hoisted(() => ({
  loginWithGitHub: vi.fn(),
  user: null,
}))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => authState,
}))

vi.mock('../Logo', () => ({
  default: () => <div>Mitig8it</div>,
}))

vi.mock('../Footer', () => ({
  default: () => <div>Footer</div>,
}))

describe('HomePage', () => {
  beforeEach(() => {
    authState.loginWithGitHub = vi.fn()
    authState.user = null
  })

  it('shows a tighter homepage with a focused nav and fix-first hero', () => {
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>
    )

    const navigation = screen.getByRole('navigation', { name: 'Main navigation' })

    expect(within(navigation).getByRole('link', { name: 'Examples' })).toBeInTheDocument()
    expect(within(navigation).getByRole('link', { name: 'Security' })).toBeInTheDocument()
    expect(within(navigation).getByRole('link', { name: 'About' })).toBeInTheDocument()
    expect(within(navigation).queryByRole('link', { name: 'Customers' })).toBeNull()

    expect(screen.getByRole('heading', { name: /Findings that come with fixes/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /Applied by you, in the PR/i })).toBeInTheDocument()
    expect(
      screen.getByText(
        /Mitig8it finds exploitable code in every pull request, proves a fix, and posts it as a one-click suggestion/i
      )
    ).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'See sample review' })[0]).toHaveAttribute(
      'href',
      '/examples'
    )
    expect(screen.getByRole('link', { name: /Read the security page/i })).toHaveAttribute(
      'href',
      '/security'
    )
    expect(screen.getAllByRole('button', { name: 'Start with GitHub' }).length).toBeGreaterThanOrEqual(1)
    expect(screen.queryByText(/In beta/i)).toBeNull()
    expect(screen.queryByText(/How we reduce false positives/i)).toBeNull()
  })

  it('renders every section heading with the new structure', () => {
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>
    )

    expect(screen.getByRole('heading', { name: 'Three steps' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'How a fix earns its place' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Live today' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Built to be trusted' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Try it on one repository' })).toBeInTheDocument()
    expect(screen.getByText('Nothing is applied or merged automatically.')).toBeInTheDocument()
  })

  it('claims nothing that is not shipped', () => {
    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>
    )

    expect(screen.queryByText('Coming soon')).toBeNull()
    expect(screen.queryByText('In progress')).toBeNull()
    expect(screen.getAllByText('Live now').length).toBe(4)
  })

  it('shows workspace entry for signed-in users', () => {
    authState.user = { github_username: 'neha' }

    render(
      <MemoryRouter>
        <HomePage />
      </MemoryRouter>
    )

    expect(screen.getAllByRole('link', { name: 'Open workspace' })[0]).toHaveAttribute('href', '/dashboard')
  })
})

describe('PullRequestReviewPreview', () => {
  it('renders the suggestion and the verification without animation', () => {
    render(<PullRequestReviewPreview animate={false} />)

    expect(screen.getByText('services/orders.js')).toBeInTheDocument()
    expect(screen.getByText('mitig8it[bot]')).toBeInTheDocument()
    expect(screen.getByText(/Potential SQL injection via string concatenation/i)).toBeInTheDocument()
    expect(screen.getByText('CWE-89 · Confidence 90%')).toBeInTheDocument()
    expect(screen.getByText('Suggested change')).toBeInTheDocument()

    expect(
      screen.getAllByText(
        `const result = await pool.query("SELECT id, status, total FROM orders WHERE id = '" + req.params.id + "'");`
      ).length
    ).toBeGreaterThanOrEqual(1)
    expect(
      screen.getByText(
        "const result = await pool.query('SELECT id, status, total FROM orders WHERE id = $1', [req.params.id]);"
      )
    ).toBeInTheDocument()

    expect(
      screen.getByText(
        'Verified: regression test failed on the original code and passed with this change.'
      )
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Commit suggestion' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Apply in Mitig8it' })).toBeNull()
  })
})
