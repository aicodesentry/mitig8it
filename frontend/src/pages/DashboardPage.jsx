import { useAuth } from '../contexts/AuthContext'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useOnboarding } from '../contexts/OnboardingContext'
import { formatRate, repositoryAPI, reportsAPI } from '../services/api'
import { PageHeader, PageStats } from '../components/PageSection'
import { Pagination } from '../components/ui/pagination'
import { ArrowUpRight, CheckCircle2, CircleSlash, ExternalLink, GitPullRequest, Shield, ShieldAlert, Server, Search, Undo2, Wrench } from 'lucide-react'

// The window the quality tiles report on. Thirty days is long enough that a quiet week
// does not swing a rate, and short enough that a rule change shows up in it.
const QUALITY_WINDOW_DAYS = 30

const GITHUB_APP_URL = 'https://github.com/apps/mitig8it/installations/new'

const statusConfig = {
  merged: { label: 'Merged', dot: 'bg-purple-500', text: 'text-purple-600 dark:text-purple-400' },
  open: { label: 'Open', dot: 'bg-green-500', text: 'text-green-600 dark:text-green-400' },
  closed: { label: 'Closed', dot: 'bg-red-500', text: 'text-red-600 dark:text-red-400' },
  draft: { label: 'Draft', dot: 'bg-neutral-400', text: 'text-neutral-500 dark:text-neutral-400' },
}

const severityConfig = {
  critical: { label: 'C', bg: 'bg-red-500', text: 'text-white' },
  high: { label: 'H', bg: 'bg-orange-500', text: 'text-white' },
  medium: { label: 'M', bg: 'bg-amber-400', text: 'text-amber-900' },
  low: { label: 'L', bg: 'bg-sky-400', text: 'text-sky-900' },
}

const INSTALLATION_SETTINGS_URL = 'https://github.com/settings/installations'

function getFirstRunChecklist(status) {
  return [
    {
      id: 'install',
      title: 'Install GitHub App',
      detail: status.hasInstall
        ? `${status.installationCount} installation${status.installationCount === 1 ? '' : 's'} connected`
        : 'Install Mitig8it on one repository or organization.',
      done: status.hasInstall,
      current: status.nextStep === 'install',
    },
    {
      id: 'access',
      title: 'Grant repository access',
      detail: status.hasRepoAccess
        ? `${status.repositoryCount} repos visible to Mitig8it`
        : 'Grant access in GitHub, then sync here once.',
      done: status.hasRepoAccess,
      current: status.nextStep === 'grant-access',
    },
    {
      id: 'activate',
      title: 'Activate one repository',
      detail: status.hasActiveRepo
        ? `${status.activeRepositoryCount} repo${status.activeRepositoryCount === 1 ? '' : 's'} active`
        : 'Choose the first repository that should receive reviews.',
      done: status.hasActiveRepo,
      current: status.nextStep === 'connect-repo',
    },
    {
      id: 'review',
      title: 'Open a pull request',
      detail: status.hasFirstReview
        ? `${status.analysisCount} review${status.analysisCount === 1 ? '' : 's'} completed`
        : status.hasFirstPullRequest
          ? 'Pull request detected. Waiting for the first review.'
          : 'Open or update a PR to trigger the first review.',
      done: status.hasFirstReview,
      current: status.nextStep === 'open-pr' || status.nextStep === 'wait-review',
    },
  ]
}

function getFirstRunAction(status, githubAppInstallUrl) {
  if (!status.hasInstall) {
    return {
      title: 'Install the GitHub App',
      description: 'Start small. Install Mitig8it on one repository now, then expand later if the first run looks good.',
      primaryLabel: 'Install GitHub App',
      primaryHref: githubAppInstallUrl || GITHUB_APP_URL,
      primaryExternal: true,
      secondaryLabel: 'View setup guide',
      secondaryHref: '/dashboard/onboarding',
    }
  }

  if (!status.hasRepoAccess) {
    return {
      title: 'Grant repository access',
      description: 'Mitig8it is installed, but it still cannot see a repository to review. Broaden access in GitHub, then sync once here.',
      primaryLabel: 'Manage GitHub access',
      primaryHref: INSTALLATION_SETTINGS_URL,
      primaryExternal: true,
      secondaryLabel: 'View setup guide',
      secondaryHref: '/dashboard/onboarding',
    }
  }

  if (!status.hasActiveRepo) {
    return {
      title: 'Activate your first repository',
      description: 'Choose one repository to turn on reviews. Keep the first pass focused, then expand after the workflow is proven.',
      primaryLabel: 'Choose repository',
      primaryHref: '/dashboard/repositories',
      primaryExternal: false,
      secondaryLabel: 'View setup guide',
      secondaryHref: '/dashboard/onboarding',
    }
  }

  if (!status.hasFirstReview) {
    return {
      title: status.hasFirstPullRequest ? 'Waiting for the first review' : 'Open a pull request',
      description: status.hasFirstPullRequest
        ? 'Mitig8it has enough access. The dashboard will populate as soon as the first pull request review completes.'
        : 'Open or update a pull request in the active repository to trigger the first review.',
      primaryLabel: 'Go to reports',
      primaryHref: '/dashboard/reports',
      primaryExternal: false,
      secondaryLabel: 'View repositories',
      secondaryHref: '/dashboard/repositories',
    }
  }

  return {
    title: 'Your setup is complete',
    description: 'Mitig8it is connected and the first review has landed. Continue in the live dashboard.',
    primaryLabel: 'Open dashboard',
    primaryHref: '/dashboard/home',
    primaryExternal: false,
    secondaryLabel: 'View reports',
    secondaryHref: '/dashboard/reports',
  }
}

function FirstRunActionButton({ action }) {
  if (action.primaryExternal) {
    return (
      <a
        href={action.primaryHref}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-2 rounded-lg bg-neutral-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-100"
      >
        {action.primaryLabel}
        <ExternalLink className="h-4 w-4" />
      </a>
    )
  }

  return (
    <Link
      to={action.primaryHref}
      className="inline-flex items-center gap-2 rounded-lg bg-neutral-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-100"
    >
      {action.primaryLabel}
      <ArrowUpRight className="h-4 w-4" />
    </Link>
  )
}

function FirstRunWorkspace({ githubAppInstallUrl, status, user }) {
  const checklist = useMemo(() => getFirstRunChecklist(status), [status])
  const action = useMemo(() => getFirstRunAction(status, githubAppInstallUrl), [githubAppInstallUrl, status])

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
        <div className="max-w-3xl space-y-3">
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-neutral-500 dark:text-neutral-400">
            First Run
          </p>
          <h2 className="text-3xl font-semibold text-neutral-900 dark:text-white">
            {user?.github_username ? `${user.github_username}, get your first review live` : 'Get your first review live'}
          </h2>
          <p className="text-sm leading-6 text-neutral-600 dark:text-neutral-300">
            This workspace becomes useful once one repository is connected and the first pull request review lands. Until then, keep the setup tight and focus on the current step only.
          </p>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <section className="rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
          <div className="space-y-5">
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-neutral-500 dark:text-neutral-400">
                Current Step
              </p>
              <h3 className="text-2xl font-semibold text-neutral-900 dark:text-white">
                {action.title}
              </h3>
              <p className="max-w-2xl text-sm leading-6 text-neutral-600 dark:text-neutral-300">
                {action.description}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-4">
              <FirstRunActionButton action={action} />
              <Link
                to={action.secondaryHref}
                className="inline-flex items-center gap-2 text-sm font-medium text-neutral-600 hover:text-neutral-900 dark:text-neutral-300 dark:hover:text-white"
              >
                {action.secondaryLabel}
              </Link>
            </div>

            <div className="rounded-xl border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-950">
              <h4 className="text-sm font-semibold text-neutral-900 dark:text-white">
                What happens once setup is complete
              </h4>
              <div className="mt-3 space-y-3">
                {[
                  'Mitig8it comments directly on risky pull request lines.',
                  'GitHub gets a review summary with severity and remediation context.',
                  'Reports become the operating log once the first review lands.',
                ].map((line) => (
                  <div key={line} className="flex items-start gap-3">
                    <div className="mt-1 h-2 w-2 rounded-full bg-neutral-900 dark:bg-white" />
                    <p className="text-sm text-neutral-600 dark:text-neutral-300">{line}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <aside className="rounded-2xl border border-neutral-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
          <div>
            <h3 className="text-lg font-semibold text-neutral-900 dark:text-white">
              Setup progress
            </h3>
            <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
              Ignore everything except the current step.
            </p>
          </div>

          <div className="mt-5 space-y-3">
            {checklist.map((item, index) => (
              <div
                key={item.id}
                className={`rounded-xl border px-4 py-4 ${
                  item.done
                    ? 'border-emerald-200 bg-emerald-50 dark:border-emerald-900/60 dark:bg-emerald-950/20'
                    : item.current
                      ? 'border-neutral-900 bg-neutral-50 dark:border-white dark:bg-neutral-950'
                      : 'border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={`mt-0.5 flex h-8 w-8 items-center justify-center rounded-full text-sm font-semibold ${
                      item.done
                        ? 'bg-emerald-600 text-white'
                        : item.current
                          ? 'bg-neutral-900 text-white dark:bg-white dark:text-neutral-900'
                          : 'bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300'
                    }`}
                  >
                    {item.done ? <CheckCircle2 className="h-4 w-4" /> : index + 1}
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-neutral-900 dark:text-white">
                        {item.title}
                      </p>
                      {item.current ? (
                        <span className="rounded-full bg-neutral-900 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-white dark:bg-white dark:text-neutral-900">
                          Current
                        </span>
                      ) : null}
                    </div>
                    <p className="text-sm text-neutral-600 dark:text-neutral-300">
                      {item.detail}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </aside>
      </div>
    </div>
  )
}

const DashboardPage = () => {
  const { githubAppInstallUrl, user } = useAuth()
  const { loading: onboardingLoading, status: onboardingStatus } = useOnboarding()
  const [analysisSummary, setAnalysisSummary] = useState({
    total_analyses: 0, completed: 0, failed: 0, recent_7_days: 0
  })
  const [loading, setLoading] = useState(true)
  const [prInsights, setPrInsights] = useState([])
  const [insightsLoading, setInsightsLoading] = useState(true)
  const [insightsPage, setInsightsPage] = useState(1)
  const [quality, setQuality] = useState(null)
  const [qualityLoading, setQualityLoading] = useState(true)
  const insightsPerPage = 8

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const summaryData = await repositoryAPI.getSummary()
        setAnalysisSummary(summaryData.summary)
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error)
      } finally {
        setLoading(false)
      }
    }

    const fetchPRInsights = async () => {
      try {
        setInsightsLoading(true)
        const reposResponse = await repositoryAPI.list()
        const repositories = reposResponse.repositories || []
        const prLists = await Promise.allSettled(
          repositories.map(async (repo) => {
            const response = await repositoryAPI.listPRs(repo.id)
            return { repo, prs: response.pull_requests || [] }
          })
        )
        const prMap = new Map()
        prLists.forEach((result) => {
          if (result.status !== 'fulfilled') return
          const { repo, prs } = result.value
          prs.forEach((prItem) => {
            const prKey = `${repo.full_name}#${prItem.pr_number}`
            if (!prMap.has(prKey)) {
              prMap.set(prKey, {
                repository: repo.full_name,
                pr_number: prItem.pr_number,
                title: prItem.title,
                html_url: prItem.html_url,
                author: prItem.author,
                status: prItem.draft ? 'draft' : prItem.merged_at ? 'merged' : prItem.state || 'open',
                timestamp: prItem.created_at,
                severity_counts: {
                  critical: Number(prItem.critical_count || 0),
                  high: Number(prItem.high_count || 0),
                  medium: Number(prItem.medium_count || 0),
                  low: Number(prItem.low_count || 0),
                },
              })
            }
          })
        })
        setPrInsights(
          Array.from(prMap.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        )
      } catch (error) {
        console.error('Failed to fetch PR insights:', error)
      } finally {
        setInsightsLoading(false)
      }
    }

    // The quality report is a read of a pre-computed roll-up, so it is cheap and never
    // blocks the rest of the dashboard. A failure leaves the tiles reading "n/a".
    const fetchQuality = async () => {
      try {
        const data = await reportsAPI.getQuality({ window: QUALITY_WINDOW_DAYS })
        setQuality(data.overall || null)
      } catch (error) {
        console.error('Failed to fetch quality metrics:', error)
      } finally {
        setQualityLoading(false)
      }
    }

    fetchDashboardData()
    fetchPRInsights()
    fetchQuality()
  }, [])

  const severityTotals = useMemo(() => {
    return prInsights.reduce(
      (acc, pr) => {
        acc.critical += pr.severity_counts.critical
        acc.high += pr.severity_counts.high
        acc.medium += pr.severity_counts.medium
        acc.low += pr.severity_counts.low
        acc.total +=
          pr.severity_counts.critical +
          pr.severity_counts.high +
          pr.severity_counts.medium +
          pr.severity_counts.low
        return acc
      },
      { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    )
  }, [prInsights])

  const formatTime = (timestamp) => {
    if (!timestamp) return ''
    const date = new Date(timestamp)
    const now = new Date()
    const diffMs = now - date
    const diffMins = Math.floor(diffMs / 60000)
    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins}m`
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h`
    if (diffMins < 43200) return `${Math.floor(diffMins / 1440)}d`
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }

  const statVal = (v) => (loading || onboardingLoading ? '-' : v)
  const isFirstRunWorkspace = onboardingStatus.needsOnboarding || onboardingStatus.needsFirstReview

  if (isFirstRunWorkspace) {
    return (
      <FirstRunWorkspace
        githubAppInstallUrl={githubAppInstallUrl}
        status={onboardingStatus}
        user={user}
      />
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={user?.github_username ? `${user.github_username}'s workspace` : 'Dashboard'}
        description="Security posture across your repositories"
        actions={
          <Link
            to="/dashboard/reports"
            className="inline-flex items-center gap-2 rounded-lg bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-900 dark:hover:bg-neutral-100"
          >
            View reports
            <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
        }
      />

      <PageStats
        items={[
          { label: 'Active repos', value: statVal(onboardingStatus.activeRepositoryCount), icon: <Server className="h-4 w-4 text-neutral-600 dark:text-neutral-300" /> },
          { label: 'PRs tracked', value: statVal(prInsights.length), icon: <GitPullRequest className="h-4 w-4 text-neutral-600 dark:text-neutral-300" /> },
          { label: 'Scans run', value: statVal(analysisSummary.total_analyses), icon: <Search className="h-4 w-4 text-neutral-600 dark:text-neutral-300" /> },
          { label: 'Open findings', value: statVal(severityTotals.total), icon: <ShieldAlert className="h-4 w-4 text-neutral-600 dark:text-neutral-300" /> },
        ]}
      />

      <PageStats
        columns={3}
        items={[
          {
            label: `Apply rate (${QUALITY_WINDOW_DAYS}d)`,
            value: qualityLoading ? '-' : formatRate(quality?.apply_rate),
            hint: 'Share of published fixes that were applied, in the app or on GitHub.',
            icon: <Wrench className="h-4 w-4 text-neutral-600 dark:text-neutral-300" />,
          },
          {
            label: `Dismiss rate (${QUALITY_WINDOW_DAYS}d)`,
            value: qualityLoading ? '-' : formatRate(quality?.dismiss_rate),
            hint: 'Share of new findings dismissed, suppressed, or resolved without a fix.',
            icon: <CircleSlash className="h-4 w-4 text-neutral-600 dark:text-neutral-300" />,
          },
          {
            label: `Residual rate (${QUALITY_WINDOW_DAYS}d)`,
            value: qualityLoading ? '-' : formatRate(quality?.residual_rate),
            hint: 'Share of applied fixes that left a blocking finding behind.',
            icon: <Undo2 className="h-4 w-4 text-neutral-600 dark:text-neutral-300" />,
          },
        ]}
      />

      {severityTotals.total > 0 && (
        <div className="flex items-center gap-4 rounded-xl border border-neutral-200 bg-white px-5 py-3 dark:border-neutral-800 dark:bg-neutral-900">
          <Shield className="h-4 w-4 text-neutral-400" />
          <div className="flex flex-1 items-center gap-2">
            <div className="flex h-2 flex-1 overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-800">
              {severityTotals.critical > 0 && (
                <div className="bg-red-500" style={{ width: `${(severityTotals.critical / severityTotals.total) * 100}%` }} />
              )}
              {severityTotals.high > 0 && (
                <div className="bg-orange-500" style={{ width: `${(severityTotals.high / severityTotals.total) * 100}%` }} />
              )}
              {severityTotals.medium > 0 && (
                <div className="bg-amber-400" style={{ width: `${(severityTotals.medium / severityTotals.total) * 100}%` }} />
              )}
              {severityTotals.low > 0 && (
                <div className="bg-sky-400" style={{ width: `${(severityTotals.low / severityTotals.total) * 100}%` }} />
              )}
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs text-neutral-500 dark:text-neutral-400">
            {severityTotals.critical > 0 && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-red-500" />{severityTotals.critical} critical</span>}
            {severityTotals.high > 0 && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-orange-500" />{severityTotals.high} high</span>}
            {severityTotals.medium > 0 && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-400" />{severityTotals.medium} medium</span>}
            {severityTotals.low > 0 && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-sky-400" />{severityTotals.low} low</span>}
          </div>
        </div>
      )}

      <div>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">Recent Pull Requests</h2>
          <Link to="/dashboard/reports" className="text-xs font-medium text-neutral-500 hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-white">
            View reports
          </Link>
        </div>

        {insightsLoading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-16 animate-pulse rounded-lg bg-neutral-100 dark:bg-neutral-800" />
            ))}
          </div>
        ) : prInsights.length === 0 ? (
          <div className="rounded-xl border border-dashed border-neutral-200 px-6 py-12 text-center text-sm text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
            No pull requests yet. Connect repositories and sync to see PR activity.
          </div>
        ) : (
          <>
            <div className="divide-y divide-neutral-100 rounded-xl border border-neutral-200 bg-white dark:divide-neutral-800 dark:border-neutral-800 dark:bg-neutral-900">
              {prInsights
                .slice((insightsPage - 1) * insightsPerPage, insightsPage * insightsPerPage)
                .map((pr) => {
                  const st = statusConfig[pr.status] || statusConfig.open
                  return (
                    <div key={`${pr.repository}-${pr.pr_number}`} className="flex items-center gap-4 px-4 py-3 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                      <span className={`h-2 w-2 flex-shrink-0 rounded-full ${st.dot}`} title={st.label} />

                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-neutral-900 dark:text-white">
                          #{pr.pr_number} {pr.title || 'Untitled'}
                        </p>
                        <p className="truncate text-xs text-neutral-500 dark:text-neutral-400">
                          {pr.repository} · {pr.author} · <span className={st.text}>{st.label}</span> · {formatTime(pr.timestamp)}
                        </p>
                      </div>

                      <div className="hidden items-center gap-1 sm:flex">
                        {Object.entries(pr.severity_counts).map(([level, count]) => {
                          if (!count) return null
                          const cfg = severityConfig[level]
                          return (
                            <span key={level} className={`inline-flex h-5 min-w-[20px] items-center justify-center rounded px-1.5 text-[10px] font-bold ${cfg.bg} ${cfg.text}`}>
                              {count}
                            </span>
                          )
                        })}
                      </div>

                      <a
                        href={pr.html_url || `https://github.com/${pr.repository}/pull/${pr.pr_number}`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex-shrink-0 text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-200"
                        title="Open on GitHub"
                      >
                        <ArrowUpRight className="h-4 w-4" />
                      </a>
                    </div>
                  )
                })}
            </div>
            {prInsights.length > insightsPerPage && (
              <Pagination
                currentPage={insightsPage}
                totalPages={Math.ceil(prInsights.length / insightsPerPage)}
                onPageChange={setInsightsPage}
                className="pt-3"
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

export default DashboardPage
