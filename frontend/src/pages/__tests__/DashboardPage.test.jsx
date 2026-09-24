import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import DashboardPage from '../DashboardPage'

const authState = vi.hoisted(() => ({
  user: { github_username: 'neha' },
  githubAppInstallUrl: 'https://github.com/apps/mitig8it/installations/new',
}))

const onboardingState = vi.hoisted(() => ({
  loading: false,
  status: {
    needsOnboarding: true,
    needsFirstReview: false,
    hasInstall: false,
    hasRepoAccess: false,
    hasActiveRepo: false,
    hasFirstPullRequest: false,
    hasFirstReview: false,
    activeRepositoryCount: 0,
    installationCount: 0,
    repositoryCount: 0,
    analysisCount: 0,
    nextStep: 'install',
  },
}))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => authState,
}))

vi.mock('../../contexts/OnboardingContext', () => ({
  useOnboarding: () => onboardingState,
}))

const quality = vi.hoisted(() => ({ getQuality: vi.fn() }))

vi.mock('../../services/api', () => ({
  repositoryAPI: {
    getSummary: vi.fn().mockResolvedValue({
      summary: { total_analyses: 0, completed: 0, failed: 0, recent_7_days: 0 },
    }),
    list: vi.fn().mockResolvedValue({ repositories: [] }),
    listPRs: vi.fn(),
  },
  reportsAPI: { getQuality: quality.getQuality },
  formatRate: (rate) =>
    (typeof rate === 'number' && Number.isFinite(rate) ? `${Math.round(rate * 100)}%` : 'n/a'),
}))

vi.mock('../../components/PageSection', () => ({
  PageHeader: ({ title, description, actions }) => (
    <div>
      <div>{title}</div>
      <div>{description}</div>
      <div>{actions}</div>
    </div>
  ),
  PageStats: ({ items }) => (
    <div>
      {items.map((item) => (
        <div key={item.label}>
          <div>{`${item.label}:${item.value}`}</div>
          {item.hint ? <div>{item.hint}</div> : null}
        </div>
      ))}
    </div>
  ),
}))

vi.mock('../../components/ui/pagination', () => ({
  Pagination: () => <div>Pagination</div>,
}))

const LIVE_WORKSPACE = {
  needsOnboarding: false,
  needsFirstReview: false,
  hasInstall: true,
  hasRepoAccess: true,
  hasActiveRepo: true,
  hasFirstPullRequest: true,
  hasFirstReview: true,
  activeRepositoryCount: 1,
  installationCount: 1,
  repositoryCount: 1,
  analysisCount: 3,
  nextStep: 'done',
}

describe('DashboardPage', () => {
  beforeEach(() => {
    quality.getQuality.mockReset()
    quality.getQuality.mockResolvedValue({ overall: null, by_rule: [] })
    onboardingState.loading = false
    onboardingState.status = {
      needsOnboarding: true,
      needsFirstReview: false,
      hasInstall: false,
      hasRepoAccess: false,
      hasActiveRepo: false,
      hasFirstPullRequest: false,
      hasFirstReview: false,
      activeRepositoryCount: 0,
      installationCount: 0,
      repositoryCount: 0,
      analysisCount: 0,
      nextStep: 'install',
    }
  })

  it('shows a guided first-run workspace instead of dashboard metrics before install', async () => {
    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    )

    expect(screen.getByText(/get your first review live/i)).toBeInTheDocument()
    expect(screen.getByText('Setup progress')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Install GitHub App' })).toHaveAttribute(
      'href',
      authState.githubAppInstallUrl
    )
    await screen.findByText('View setup guide')
    expect(screen.queryByText('Active repos:0')).toBeNull()
    expect(screen.queryByText(/Recent Pull Requests/i)).toBeNull()
  })

  it('switches the first-run action to waiting state once a PR exists', async () => {
    onboardingState.status = {
      needsOnboarding: false,
      needsFirstReview: true,
      hasInstall: true,
      hasRepoAccess: true,
      hasActiveRepo: true,
      hasFirstPullRequest: true,
      hasFirstReview: false,
      activeRepositoryCount: 1,
      installationCount: 1,
      repositoryCount: 1,
      analysisCount: 0,
      nextStep: 'wait-review',
    }

    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    )

    expect(await screen.findByText('Waiting for the first review')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to reports' })).toHaveAttribute('href', '/dashboard/reports')
    expect(screen.getByText('1 repo active')).toBeInTheDocument()
  })

  it('shows the live dashboard once the first review has landed', async () => {
    onboardingState.status = {
      needsOnboarding: false,
      needsFirstReview: false,
      hasInstall: true,
      hasRepoAccess: true,
      hasActiveRepo: true,
      hasFirstPullRequest: true,
      hasFirstReview: true,
      activeRepositoryCount: 1,
      installationCount: 1,
      repositoryCount: 1,
      analysisCount: 3,
      nextStep: 'done',
    }

    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    )

    expect(screen.getByText("neha's workspace")).toBeInTheDocument()
    expect(screen.getByText('Recent Pull Requests')).toBeInTheDocument()
    expect(await screen.findByText(/No pull requests yet/i)).toBeInTheDocument()
  })
})

describe('the quality tiles', () => {
  beforeEach(() => {
    quality.getQuality.mockReset()
    quality.getQuality.mockResolvedValue({ overall: null, by_rule: [] })
    onboardingState.loading = false
    onboardingState.status = LIVE_WORKSPACE
  })

  const renderDashboard = () => render(
    <MemoryRouter>
      <DashboardPage />
    </MemoryRouter>
  )

  it('reads the thirty day window', async () => {
    renderDashboard()
    await screen.findByText(/Apply rate \(30d\):/)
    expect(quality.getQuality).toHaveBeenCalledWith({ window: 30 })
  })

  it('shows the three rates as percentages', async () => {
    quality.getQuality.mockResolvedValue({
      overall: { apply_rate: 0.62, dismiss_rate: 0.1, residual_rate: 0.25 },
    })

    renderDashboard()

    expect(await screen.findByText('Apply rate (30d):62%')).toBeInTheDocument()
    expect(screen.getByText('Dismiss rate (30d):10%')).toBeInTheDocument()
    expect(screen.getByText('Residual rate (30d):25%')).toBeInTheDocument()
  })

  it('shows n/a rather than a zero when a rate has no denominator', async () => {
    quality.getQuality.mockResolvedValue({
      overall: { apply_rate: null, dismiss_rate: 0, residual_rate: null },
    })

    renderDashboard()

    expect(await screen.findByText('Apply rate (30d):n/a')).toBeInTheDocument()
    expect(screen.getByText('Residual rate (30d):n/a')).toBeInTheDocument()
    // A measured zero is a real answer and stays a zero.
    expect(screen.getByText('Dismiss rate (30d):0%')).toBeInTheDocument()
  })

  it('gives each tile a one-line definition', async () => {
    renderDashboard()
    expect(await screen.findByText(/Share of published fixes that were applied/)).toBeInTheDocument()
    expect(screen.getByText(/Share of new findings dismissed, suppressed, or resolved without a fix/)).toBeInTheDocument()
    expect(screen.getByText(/Share of applied fixes that left a blocking finding behind/)).toBeInTheDocument()
  })

  it('leaves the rest of the dashboard working when the report fails', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    quality.getQuality.mockRejectedValue(new Error('offline'))

    renderDashboard()

    expect(await screen.findByText('Apply rate (30d):n/a')).toBeInTheDocument()
    expect(screen.getByText('Recent Pull Requests')).toBeInTheDocument()
    log.mockRestore()
  })
})
