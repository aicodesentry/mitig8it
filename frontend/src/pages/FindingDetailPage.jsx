import { useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { findingAPI } from '../services/api'
import RemediationPanel from '../components/RemediationPanel'

export default function FindingDetailPage() {
  const { findingId } = useParams()
  const [finding, setFinding] = useState(null)

  useEffect(() => {
    findingAPI
      .get(findingId)
      .then((data) => setFinding(data.finding))
      .catch((err) => console.error(err))
  }, [findingId])

  if (!finding) {
    return <div className="rounded-xl border border-neutral-200 bg-white p-6 text-sm text-neutral-500">Loading finding...</div>
  }

  const setStatus = async (status) => {
    const updated = await findingAPI.updateStatus(
      finding.id,
      status,
      status === 'dismissed' ? 'false_positive' : null
    )
    setFinding(updated.finding)
  }

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-neutral-200 bg-white p-6">
        <h1 className="text-2xl font-semibold text-neutral-900">{finding.title}</h1>
        <p className="mt-2 text-sm text-neutral-600">
          {finding.repository_full_name} • PR #{finding.pr_number} • {finding.category}
        </p>
        <p className="mt-2 text-sm text-neutral-600">Severity: {finding.severity} • Confidence: {Math.round(Number(finding.confidence) * 100)}%</p>
      </div>

      <div className="rounded-xl border border-neutral-200 bg-white p-6">
        <h2 className="text-lg font-semibold text-neutral-900">Evidence</h2>
        <p className="mt-2 text-sm text-neutral-700">{finding.evidence}</p>
        <pre className="mt-4 overflow-x-auto rounded-lg bg-neutral-900 p-3 text-xs text-neutral-100">{finding.code_snippet || 'No snippet'}</pre>
      </div>

      <div className="rounded-xl border border-neutral-200 bg-white p-6">
        <h2 className="text-lg font-semibold text-neutral-900">Exploitability and Remediation</h2>
        <p className="mt-2 text-sm text-neutral-700">{finding.exploit_scenario}</p>
        <p className="mt-3 text-sm text-neutral-700">{finding.remediation}</p>
        {finding.remediation_patch && (
          <>
            <div className="mt-4 inline-flex rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700">
              Suggested fix available
            </div>
            <p className="mt-3 text-sm text-neutral-600">
              If this finding was posted back to GitHub on the pull request, the reviewer may be able to apply the suggested change directly from the review thread.
            </p>
            <pre className="mt-3 overflow-x-auto rounded-lg bg-neutral-900 p-3 text-xs text-neutral-100">{finding.remediation_patch}</pre>
          </>
        )}
      </div>

      <RemediationPanel pullRequestId={finding.pull_request_id} findingId={finding.id} />

      <div className="flex gap-2">
        <button onClick={() => setStatus('open')} className="rounded-lg border border-neutral-300 px-4 py-2 text-sm">Mark Open</button>
        <button onClick={() => setStatus('accepted_risk')} className="rounded-lg border border-neutral-300 px-4 py-2 text-sm">Accept Risk</button>
        <button onClick={() => setStatus('dismissed')} className="rounded-lg border border-neutral-300 px-4 py-2 text-sm">Dismiss</button>
        <button onClick={() => setStatus('fixed')} className="rounded-lg border border-neutral-300 px-4 py-2 text-sm">Mark Fixed</button>
      </div>
    </div>
  )
}
