import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { repositoryAPI } from '../services/api'

export default function RepositoryDetailsPage() {
  const { repositoryId } = useParams()
  const [repository, setRepository] = useState(null)
  const [summary, setSummary] = useState(null)
  const [pullRequests, setPullRequests] = useState([])

  useEffect(() => {
    const load = async () => {
      const repoData = await repositoryAPI.get(repositoryId)
      const prData = await repositoryAPI.listPRs(repositoryId)
      setRepository(repoData.repository)
      setSummary(repoData.summary)
      setPullRequests(prData.pull_requests || [])
    }

    load().catch((err) => {
      console.error(err)
    })
  }, [repositoryId])

  if (!repository) {
    return <div className="rounded-xl border border-neutral-200 dark:border-neutral-700 bg-white dark:bg-neutral-900 p-6 text-sm text-neutral-500 dark:text-neutral-400">Loading repository...</div>
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-neutral-200 dark:border-neutral-700 bg-white dark:bg-neutral-900 p-6">
        <h1 className="text-2xl font-semibold text-neutral-900 dark:text-white">{repository.full_name}</h1>
        <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
          Open: {summary?.open_findings || 0} • Dismissed: {summary?.dismissed_findings || 0} • Accepted risk: {summary?.accepted_risk_findings || 0}
        </p>
      </div>

      <div className="space-y-3">
        <h2 className="text-lg font-semibold text-neutral-900 dark:text-white">Pull Requests</h2>
        {pullRequests.length === 0 && (
          <div className="rounded-xl border border-neutral-200 dark:border-neutral-700 bg-white dark:bg-neutral-900 p-6 text-sm text-neutral-500 dark:text-neutral-400">No pull requests yet.</div>
        )}
        {pullRequests.map((pr) => (
          <div
            key={pr.id}
            className="flex items-center justify-between rounded-xl border border-neutral-200 dark:border-neutral-700 bg-white dark:bg-neutral-900 p-4 hover:border-neutral-300 dark:hover:border-neutral-600"
          >
            <Link to={`/dashboard/pull-requests/${pr.id}/findings`} className="flex-1 min-w-0">
              <p className="font-medium text-neutral-900 dark:text-white">#{pr.pr_number} {pr.title}</p>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">{pr.state} • {pr.author}</p>
            </Link>
            <div className="flex items-center gap-4">
              <div className="text-right text-sm text-neutral-600 dark:text-neutral-400">
                <p>Open findings: <span className="font-semibold text-neutral-900 dark:text-white">{pr.open_findings_count}</span></p>
                <p>Critical/High: <span className="font-semibold text-neutral-900 dark:text-white">{Number(pr.critical_count || 0) + Number(pr.high_count || 0)}</span></p>
              </div>
              {pr.html_url && (
                <a
                  href={pr.html_url}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="flex-shrink-0 rounded-lg border border-neutral-200 dark:border-neutral-700 px-3 py-1.5 text-xs font-medium text-neutral-700 dark:text-neutral-300 hover:bg-neutral-50 dark:hover:bg-neutral-800"
                >
                  View on GitHub
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
