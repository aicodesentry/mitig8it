import { useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { findingAPI, DISMISSAL_REASONS } from '../services/api'
import RemediationPanel from '../components/RemediationPanel'

const STATUS_LABELS = {
  open: 'Open',
  dismissed: 'Dismissed',
  accepted_risk: 'Accepted risk',
  fixed: 'Fixed',
}

const reasonLabel = (value) =>
  DISMISSAL_REASONS.find((option) => option.value === value)?.label || value

export default function FindingDetailPage() {
  const { findingId } = useParams()
  const [finding, setFinding] = useState(null)
  const [reason, setReason] = useState(DISMISSAL_REASONS[0].value)
  const [loadError, setLoadError] = useState('')
  const [updateError, setUpdateError] = useState('')

  useEffect(() => {
    let active = true
    setFinding(null)
    setLoadError('')
    findingAPI
      .get(findingId)
      .then((data) => {
        if (!active) return
        if (data?.finding) setFinding(data.finding)
        else setLoadError('Finding not found')
      })
      .catch((err) => {
        if (!active) return
        setLoadError(err?.response?.status === 404
          ? 'Finding not found'
          : 'Could not load this finding. Refresh to try again.')
      })
    return () => { active = false }
  }, [findingId])

  if (loadError) {
    return (
      <div role="alert" className="rounded-xl border border-neutral-200 bg-white p-6 text-sm text-neutral-700">
        {loadError}
      </div>
    )
  }

  if (!finding) {
    return <div className="rounded-xl border border-neutral-200 bg-white p-6 text-sm text-neutral-500">Loading finding...</div>
  }

  const setStatus = async (status) => {
    setUpdateError('')
    try {
      const updated = await findingAPI.updateStatus(
        finding.id,
        status,
        status === 'dismissed' ? reason : null
      )
      // Merge rather than replace: the PATCH row may lack the joined repository and PR
      // fields the header needs, and a missing field must not erase what is on screen.
      setFinding((previous) => ({ ...previous, ...updated.finding }))
    } catch (_failure) {
      setUpdateError('Could not update this finding. The status was not changed. Refresh and check your access before retrying.')
    }
  }

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-neutral-200 bg-white p-6">
        <h1 className="text-2xl font-semibold text-neutral-900">{finding.title}</h1>
        <p className="mt-2 text-sm text-neutral-600">
          {finding.repository_full_name} • PR #{finding.pr_number ?? finding.pull_request_number} • {finding.category}
        </p>
        <p className="mt-2 text-sm text-neutral-600">Severity: {finding.severity} • Confidence: {Math.round(Number(finding.confidence) * 100)}%</p>
        <p data-testid="finding-status" className="mt-2 text-sm text-neutral-600">
          Status: <span className="font-semibold text-neutral-900">{STATUS_LABELS[finding.status] || finding.status || 'Unknown'}</span>
          {finding.status === 'dismissed' && finding.dismissal_reason && (
            <> • Reason: {reasonLabel(finding.dismissal_reason)}</>
          )}
        </p>
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

      {updateError && <p role="alert" className="text-sm text-red-700">{updateError}</p>}

      <div className="flex gap-2">
        <button onClick={() => setStatus('open')} className="rounded-lg border border-neutral-300 px-4 py-2 text-sm">Mark Open</button>
        <button onClick={() => setStatus('accepted_risk')} className="rounded-lg border border-neutral-300 px-4 py-2 text-sm">Accept Risk</button>
        <button onClick={() => setStatus('fixed')} className="rounded-lg border border-neutral-300 px-4 py-2 text-sm">Mark Fixed</button>
      </div>

      <div className="rounded-xl border border-neutral-200 bg-white p-6">
        <h2 className="text-lg font-semibold text-neutral-900">Dismiss this finding</h2>
        <p className="mt-1 text-sm text-neutral-600">The reason is recorded and feeds the rule quality numbers.</p>
        <fieldset className="mt-3 space-y-2">
          <legend className="sr-only">Dismissal reason</legend>
          {DISMISSAL_REASONS.map((option) => (
            <label key={option.value} className="flex items-center gap-2 text-sm text-neutral-700">
              <input
                type="radio"
                name="dismissal-reason"
                value={option.value}
                checked={reason === option.value}
                onChange={() => setReason(option.value)}
              />
              {option.label}
            </label>
          ))}
        </fieldset>
        <button
          onClick={() => setStatus('dismissed')}
          className="mt-4 rounded-lg border border-neutral-300 px-4 py-2 text-sm"
        >
          Dismiss
        </button>
      </div>
    </div>
  )
}
