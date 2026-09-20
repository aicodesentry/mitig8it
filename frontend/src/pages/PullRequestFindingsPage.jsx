import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import { findingAPI, suppressionAPI } from '../services/api'
import RemediationPanel from '../components/RemediationPanel'
import { getPrivateCacheEpoch } from '../services/privateCache'

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

// Findings in test code are informational: shown in grey, never blocking.
const severityStyles = {
  critical: 'bg-red-50 text-red-700',
  high: 'bg-orange-50 text-orange-700',
  medium: 'bg-amber-50 text-amber-700',
  low: 'bg-sky-50 text-sky-700',
  info: 'bg-neutral-100 text-neutral-600',
}

export function severityStyle(severity) {
  return severityStyles[String(severity || '').toLowerCase()] || severityStyles.info
}

export default function PullRequestFindingsPage() {
  const { pullRequestId } = useParams()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [headSha, setHeadSha] = useState(null)
  const requestVersion = useRef(0)

  const load = useCallback(async () => {
    const version = ++requestVersion.current
    const epoch = getPrivateCacheEpoch()
    setLoading(true)
    setError('')
    try {
      const data = await findingAPI.listByPR(pullRequestId, { status: 'all', min_confidence: 0 })
      if (version === requestVersion.current && epoch === getPrivateCacheEpoch()) {
        setFindings(data.findings || [])
        setHeadSha(data.pull_request?.head_sha || null)
      }
    } catch (_failure) {
      if (version === requestVersion.current && epoch === getPrivateCacheEpoch()) setError('Could not load findings. Refresh to try again.')
    } finally {
      if (version === requestVersion.current && epoch === getPrivateCacheEpoch()) setLoading(false)
    }
  }, [pullRequestId])

  useEffect(() => {
    setFindings([])
    setHeadSha(null)
    load()
    return () => { requestVersion.current += 1 }
  }, [load])

  const ordered = useMemo(() => {
    return [...findings].sort((a, b) => {
      const sevDiff = (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99)
      if (sevDiff !== 0) return sevDiff
      return Number(b.confidence) - Number(a.confidence)
    })
  }, [findings])

  const suppress = async (finding) => {
    try {
      await suppressionAPI.create({
      finding_id: finding.id,
      repository_id: finding.repository_id,
      reason: 'false_positive',
      notes: 'Suppressed from PR findings page'
      })
      await load()
    } catch (_failure) {
      setError('Could not suppress this finding. Refresh and check your access before retrying.')
    }
  }

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-semibold text-neutral-900">Pull Request Findings</h1>
      <RemediationPanel pullRequestId={pullRequestId} liveHeadSha={headSha} />

      {loading && <p role="status" className="text-sm text-neutral-600">Loading findings…</p>}
      {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
      {!loading && !error && ordered.length === 0 && (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5 text-sm text-emerald-800">
          No findings detected for this pull request.
        </div>
      )}

      {ordered.map((finding) => (
        <div key={finding.id} className="rounded-xl border border-neutral-200 bg-white p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-neutral-900">{finding.title}</h2>
              <p className="text-sm text-neutral-500">
                {finding.category} • confidence {Math.round(Number(finding.confidence) * 100)}%
              </p>
              <p className="mt-1 flex items-center gap-2">
                <span
                  data-testid={`severity-badge-${finding.id}`}
                  className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${severityStyle(finding.severity)}`}
                >
                  {finding.severity}
                </span>
                {finding.severity === 'info' && (
                  <span className="text-xs text-neutral-500">Test code — does not block</span>
                )}
              </p>
              {finding.remediation_patch && (
                <p className="mt-2 inline-flex rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700">
                  Suggested fix available
                </p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Link
                to={`/dashboard/findings/${finding.id}`}
                className="rounded-lg border border-neutral-300 px-3 py-2 text-xs font-semibold text-neutral-700"
              >
                Details
              </Link>
              <button
                onClick={() => suppress(finding)}
                className="rounded-lg border border-neutral-300 px-3 py-2 text-xs font-semibold text-neutral-700"
              >
                Suppress
              </button>
            </div>
          </div>
          <pre className="mt-4 overflow-x-auto rounded-lg bg-neutral-900 p-3 text-xs text-neutral-100">{finding.code_snippet || 'No snippet'}</pre>
          <p className="mt-3 text-sm text-neutral-700">{finding.evidence}</p>
          {finding.remediation && (
            <p className="mt-3 text-sm text-neutral-700"><strong>Recommended fix:</strong> {finding.remediation}</p>
          )}
          {finding.remediation_patch && <details className="mt-3 text-sm text-neutral-700">
            <summary className="cursor-pointer">View suggested code (verification required)</summary>
            <pre className="mt-2 overflow-auto rounded-lg bg-neutral-50 p-3 text-xs">{finding.remediation_patch}</pre>
          </details>}
        </div>
      ))}
    </div>
  )
}
