import { useCallback, useEffect, useRef, useState } from 'react'
import { remediationAPI } from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import { getPrivateCacheEpoch } from '../services/privateCache'
import { unifiedDiff } from '../lib/lineDiff'

const terminal = new Set(['ready', 'completed', 'merged', 'cancelled', 'superseded', 'unsupported', 'inconclusive', 'failed', 'expired', 'blocked', 'rejected'])
// A merge intent keeps moving while it is blocked or in flight, so only these four end it.
const mergeTerminal = new Set(['merged', 'cancelled', 'expired', 'superseded'])
const blockedActionStates = new Set(['blocked', 'rejected', 'failed', 'expired', 'superseded'])
const settledActionStates = new Set(['completed', 'blocked', 'rejected', 'failed', 'expired', 'superseded', 'cancelled'])
const cancellableMerge = new Set(['waiting_for_application', 'waiting_for_checks', 'eligible', 'blocked'])
// Previews are readable while ready and after an application commit superseded them.
const previewable = new Set(['ready', 'superseded'])
const label = (state) => String(state || 'queued').replaceAll('_', ' ')
const errorMessage = (error) => error?.response?.data?.error || 'Could not refresh repair status. Refresh before taking another action.'
const buttonClass = 'rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50'
const smallButtonClass = 'rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-50'
const STALE_HEAD_MESSAGE = 'The pull request has new commits since these fixes were generated; regenerate to continue.'
const STALE_CANDIDATE_MESSAGE = 'Stale: the pull request head moved after this fix was verified. It will not be rebased or reapplied.'
const HUMAN_MERGE_CAPTION = 'Each fix is committed to the pull request branch only when you ask for it here, as one commit against the exact reviewed head. Merging stays a human action on GitHub.'

const mergeDescriptions = {
  waiting_for_application: 'Waiting for the reviewed fixes to be committed to the pull request.',
  waiting_for_checks: 'Waiting for the required checks and reviews on the applied commit.',
  eligible: 'Required checks and reviews passed. The merge can proceed.',
  merging: 'The merge request was sent to GitHub.',
  merged: 'The pull request was merged.',
  blocked: 'GitHub is blocking this merge.',
  expired: 'The merge request expired before the checks completed. Request it again if you still want it.',
  cancelled: 'The merge request was cancelled.',
  superseded: 'New commits replaced the reviewed batch, so the merge request no longer applies.',
  reconciling: 'Checking with GitHub whether the merge completed.',
}

const rejectionReasons = {
  stale_head: STALE_HEAD_MESSAGE,
  manifest_mismatch: 'The reviewed fix no longer matches the verified evidence. Generate new fixes to continue.',
  candidate_stale: 'The pull request head moved after this fix was verified, so nothing was applied. Regenerate remaining fixes.',
  subset_not_verified: 'This combination of fixes was not verified together. Apply one fix at a time, or apply all verified fixes.',
  job_not_ready: 'The repair job was not ready when this request arrived. Generate new fixes to continue.',
  flag_disabled: 'Automatic application is turned off for this repository.',
  permission_revoked: 'Your write access to this repository was revoked, so nothing was applied.',
}

const reasonText = (code) => {
  if (!code) return ''
  return rejectionReasons[code] || `The server reported: ${label(code)}.`
}

export const coverageSentence = (verified, manual) => {
  const fixes = `${verified} verified ${verified === 1 ? 'fix' : 'fixes'}`
  if (!manual) return fixes
  return `${fixes}; ${manual} ${manual === 1 ? 'finding needs' : 'findings need'} manual work`
}

const checkPassed = (check) => {
  const raw = check?.outcome ?? check?.status ?? check?.result ?? check?.passed
  if (raw === true) return true
  if (raw === false) return false
  return typeof raw === 'string' ? raw.trim().toLowerCase() === 'passed' : null
}

// Only what the evidence records is claimed. A checks list that carries no behavior
// check means the sandbox never proved behavior, whatever the overall status says.
const behaviorOutcome = (evidence) => {
  if (!evidence || evidence.status !== 'passed') return 'not verified'
  const checks = Array.isArray(evidence.checks) ? evidence.checks : null
  if (!checks) return 'verified by sandbox checks'
  const behavior = checks.find((check) => /behavio/i.test(String(check?.name ?? check?.type ?? check?.kind ?? check ?? '')))
  if (!behavior) return 'not verified by a behavior check'
  const passed = checkPassed(behavior)
  if (passed === false) return 'not preserved'
  return passed === true ? 'verified by a behavior check' : 'not verified by a behavior check'
}

const limitText = (item) => {
  if (typeof item === 'string') return item
  return item?.reason || item?.message || item?.description || item?.detail || item?.path || 'Unspecified coverage limit'
}

// Blockers arrive as codes with optional prose, and older records as bare strings.
const blockerText = (blocker) => {
  if (typeof blocker === 'string') return blocker
  if (!blocker) return 'Unspecified merge blocker'
  const code = blocker.code ? label(blocker.code) : ''
  const message = blocker.message || blocker.reason || blocker.description || blocker.detail || ''
  if (code && message) return `${code}: ${message}`
  return code || message || 'Unspecified merge blocker'
}

const expiryText = (value) => {
  if (!value) return ''
  const when = new Date(value)
  return Number.isNaN(when.getTime()) ? '' : `Merge request expires ${when.toLocaleString()}`
}

// A server-supplied unified diff is authoritative; the client diff is only a fallback.
const serverDiff = (text, path) => {
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n')
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  const header = []
  let index = 0
  while (index < lines.length && /^(diff |index |--- |\+\+\+ )/.test(lines[index])) { header.push(lines[index]); index += 1 }
  return {
    path,
    header,
    rows: lines.slice(index).map((line) => ({
      type: line.startsWith('+') ? 'added' : line.startsWith('-') ? 'removed' : 'context',
      line,
    })),
  }
}

const candidatePaths = (candidate) => {
  const paths = Array.isArray(candidate.paths) && candidate.paths.length
    ? candidate.paths
    : (candidate.changes || []).map((change) => change?.path).filter(Boolean)
  return [...new Set(paths)]
}

const findingLabel = (finding, id) => {
  if (!finding) return id
  const where = finding.file_path ? ` (${finding.file_path}${finding.line_start ? `:${finding.line_start}` : ''})` : ''
  return `${finding.title || id}${where}`
}

// Candidates grouped by the file they change, in the order the server lists files. A
// candidate that changes several files is shown once, under its first file.
export const groupByFile = (candidates, files) => {
  const order = Array.isArray(files) && files.length ? files.map((file) => file.path) : []
  const seen = new Set()
  const groups = new Map()
  for (const candidate of candidates) {
    const paths = candidatePaths(candidate)
    const path = paths.find((p) => order.includes(p)) || paths[0] || 'file'
    if (!groups.has(path)) groups.set(path, [])
    if (!seen.has(candidate.id)) { groups.get(path).push(candidate); seen.add(candidate.id) }
  }
  const ordered = [...order.filter((path) => groups.has(path)), ...[...groups.keys()].filter((path) => !order.includes(path))]
  return ordered.map((path) => ({ path, candidates: groups.get(path), file: (files || []).find((file) => file.path === path) || null }))
}

// Remount on account/PR changes: no private state or consent crosses that boundary.
export default function RemediationPanel({ pullRequestId, findingId = null, liveHeadSha = null }) {
  const { user } = useAuth()
  const actor = user?.id || user?.user_id
  if (!actor || !pullRequestId) return null
  return <RepairSession key={`${actor}:${pullRequestId}`} pullRequestId={pullRequestId} findingId={findingId} liveHeadSha={liveHeadSha} />
}

export function RepairSession({ pullRequestId, findingId = null, liveHeadSha = null }) {
  const [state, setState] = useState(null)
  const [preview, setPreview] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [rejectedHead, setRejectedHead] = useState(null)
  const [feedback, setFeedback] = useState({})
  const mounted = useRef(true)
  const epoch = useRef(getPrivateCacheEpoch())
  const revision = useRef(0)
  const working = useRef(false)
  const consent = useRef(null)
  const current = useCallback(() => mounted.current && epoch.current === getPrivateCacheEpoch(), [])

  const refresh = useCallback(async () => {
    const request = ++revision.current
    try {
      const latest = await remediationAPI.latest(pullRequestId)
      let nextPreview = null
      if (previewable.has(latest.job?.state)) nextPreview = await remediationAPI.preview(latest.job.id)
      if (!current() || request !== revision.current) return
      setState(latest)
      setPreview(nextPreview)
      setError('')
    } catch (failure) {
      if (current() && request === revision.current) setError(errorMessage(failure))
    }
  }, [current, pullRequestId])

  useEffect(() => {
    mounted.current = true
    refresh()
    return () => { mounted.current = false; revision.current += 1 }
  }, [refresh])

  const active = state && ((state.job && !terminal.has(state.job.state)) || (state.action && !terminal.has(state.action.state))
    || (state.merge_intent?.state && !mergeTerminal.has(state.merge_intent.state)))
  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(() => { if (!working.current) refresh() }, 5000)
    return () => clearInterval(timer)
  }, [active, refresh])

  const perform = async (operation, message, onFailure) => {
    if (working.current || !current()) return
    working.current = true
    setBusy(true)
    setError('')
    setNotice('')
    revision.current += 1
    try {
      await operation()
      if (!current()) return
      setNotice(message)
      await refresh()
    } catch (failure) {
      if (!current()) return
      if (!onFailure || !onFailure(failure)) setError(errorMessage(failure))
    } finally {
      working.current = false
      if (current()) setBusy(false)
    }
  }

  const allCandidates = preview?.candidates || []
  const allSkipped = preview?.skipped || []
  const previewHead = preview?.head_sha || null
  const previewApplicable = preview ? preview.applicable !== false : false
  const staleHead = Boolean(previewHead && previewApplicable && ((liveHeadSha && liveHeadSha !== previewHead) || rejectedHead === previewHead))
  const applicableCandidates = allCandidates.filter((candidate) => (candidate.status || 'applicable') === 'applicable')
  const staleCandidates = allCandidates.filter((candidate) => candidate.status === 'stale')

  // Consent binds the exact ordered subset and the digest the server computed for it.
  // A different subset is a different consent with its own idempotency key.
  const apply = (candidateIds, manifestDigest, description) => {
    if (!preview || error || staleHead || !manifestDigest || !candidateIds.length) return
    const manifest = `${state.job.id}:${manifestDigest}:${candidateIds.join(',')}`
    if (consent.current?.manifest !== manifest) consent.current = { manifest, key: crypto.randomUUID() }
    const payload = {
      head_sha: preview.head_sha, base_sha: preview.base_sha, manifest_digest: manifestDigest,
      candidate_ids: candidateIds, merge_when_ready: false, idempotency_key: consent.current.key,
    }
    perform(() => remediationAPI.apply(state.job.id, payload),
      `${description} requested. Follow the commit and verification status below. Merging stays a human action on GitHub.`,
      (failure) => {
        if (failure?.response?.status !== 409) return false
        if (failure?.response?.data?.code === 'candidate_stale') return false
        setRejectedHead(preview.head_sha)
        return true
      })
  }

  const generate = (message = 'Repair generation requested.') => perform(
    () => remediationAPI.generate(pullRequestId, { idempotency_key: crypto.randomUUID() }),
    message,
  )

  const sendFeedback = async (candidateId, outcome) => {
    setFeedback((previous) => ({ ...previous, [candidateId]: outcome }))
    try {
      await remediationAPI.feedback(state.job.id, { candidate_id: candidateId, outcome })
    } catch (_failure) {
      // Feedback is optional. A missing or failing route must never interrupt the repair flow.
    }
  }

  const capabilities = state?.capabilities || {}
  const findings = new Map((preview?.findings || []).map((finding) => [finding.id, finding]))
  const candidates = findingId ? allCandidates.filter((candidate) => (candidate.finding_ids || []).includes(findingId)) : allCandidates
  const skipped = findingId ? allSkipped.filter((item) => item.finding_id === findingId) : allSkipped
  const groups = groupByFile(candidates, preview?.files)
  const verification = preview?.verification || null
  const coverageGaps = [...(verification?.coverage_gaps || []), ...(verification?.limitations || [])]
  const action = state?.action || null
  const mergeIntent = state?.merge_intent || null
  const mergeBlockers = mergeIntent?.blockers || []
  const mergeExpiry = mergeIntent && !mergeTerminal.has(mergeIntent.state) ? expiryText(mergeIntent.expires_at) : ''
  const mergeAttempts = Number(mergeIntent?.merge_attempts || 0)
  const actionBlocked = Boolean(action && blockedActionStates.has(action.state))
  const actionInFlight = Boolean(action && !settledActionStates.has(action.state))
  const blockedReason = actionBlocked ? reasonText(action.rejection_reason || action.reason) : ''
  const jobFinished = !state?.job || terminal.has(state.job.state)
  const showGenerate = Boolean(capabilities.generate && (jobFinished || actionBlocked) && !staleCandidates.length)
  const showRegenerate = Boolean(capabilities.generate && staleCandidates.length)
  const regenerateBlocked = busy || Boolean(error) || actionInFlight
  const applicable = previewApplicable && applicableCandidates.length > 0 && Boolean(preview?.manifest_digest) && !actionInFlight
  const applyBlocked = busy || Boolean(error) || staleHead || !capabilities.apply || !applicable

  const renderCandidate = (candidate) => {
    const limits = [...(candidate.evidence?.limitations || candidate.limitations || []), ...coverageGaps]
    const behavior = behaviorOutcome(candidate.evidence)
    const level = candidate.verification_level || candidate.evidence?.verification_level || null
    const treeOid = candidate.evidence?.verified_tree_oid || preview.verified_tree_oid || null
    const unverified = level === 'development_unverified'
    const status = candidate.status || 'applicable'
    const stale = status === 'stale'
    const applied = status === 'applied'
    const linked = candidate.finding_ids || []
    return (
      <article key={candidate.id} aria-label={candidate.title || 'Recommended fix'} data-status={status}
        className={`space-y-2 rounded-lg border border-neutral-200 p-4 ${stale ? 'bg-neutral-50 opacity-60' : ''}`}>
        <div>
          <h4 className="font-medium">{candidate.title || 'Recommended fix'}</h4>
          {linked.length > 0 && <ul className="mt-1 text-xs text-neutral-600">
            {linked.map((id) => <li key={id} className="break-all">Finding: {findingLabel(findings.get(id), id)}</li>)}
          </ul>}
          {linked.length === 0 && <p className="text-xs text-neutral-500">Findings: not linked</p>}
        </div>
        {stale && <p role="status" className="text-sm font-medium text-neutral-700">{STALE_CANDIDATE_MESSAGE}</p>}
        {applied && <p role="status" className="text-sm font-medium text-emerald-800">
          Applied{candidate.applied_commit_sha ? <> in commit <code>{candidate.applied_commit_sha.slice(0, 12)}</code></> : ''}.
        </p>}
        {candidate.rationale && <p className="text-sm text-neutral-700">{candidate.rationale}</p>}
        {(candidate.changes || []).map((change, index) => {
          const path = change.path || 'file'
          const diff = typeof change.unified_diff === 'string' && change.unified_diff.trim()
            ? serverDiff(change.unified_diff, path)
            : unifiedDiff(change.original, change.replacement, { path, startLine: change.start_line || change.line_start || 1 })
          return (
            <div key={`${change.path}:${index}`}>
              <p className="break-all text-sm font-medium">{change.path}</p>
              <pre className="mt-2 overflow-auto rounded bg-neutral-50 p-3 text-xs text-neutral-900">
                {diff.header.map((line, headerIndex) => <span key={`${headerIndex}:${line}`} className="block text-neutral-500">{line}</span>)}
                {diff.rows.map((row, rowIndex) => <span key={`${rowIndex}:${row.line}`}
                  className={`block ${row.type === 'added' ? 'bg-emerald-50 text-emerald-900' : row.type === 'removed' ? 'bg-red-50 text-red-900' : 'text-neutral-700'}`}>{row.line}</span>)}
              </pre>
            </div>
          )
        })}
        <p className="text-sm text-neutral-600">Behavior preserved: {behavior}</p>
        <p className={`text-sm ${unverified ? 'rounded bg-amber-50 p-2 font-medium text-amber-900' : 'text-neutral-600'}`}>
          {unverified
            ? 'Verification level: development unverified. This fix was not verified in an isolated sandbox.'
            : `Verification level: ${label(level || 'unknown')}`}
        </p>
        {limits.length > 0 && <div className="rounded bg-amber-50 p-2 text-xs text-amber-900">
          <p className="font-medium">Coverage limits</p>
          <ul className="mt-1 list-disc pl-4">{limits.map((limit, index) => <li key={`${limitText(limit)}:${index}`}>{limitText(limit)}</li>)}</ul>
        </div>}
        <details className="text-xs text-neutral-600">
          <summary className="cursor-pointer">Audit the exact revision</summary>
          <div className="mt-1 break-all font-mono">
            <p>head {preview.head_sha || 'unknown'}</p>
            <p>tree {treeOid || 'not recorded'}</p>
            <p>evidence {candidate.evidence?.evidence_digest || verification?.evidence_digest || 'not recorded'}</p>
            <p>consent {candidate.manifest_digest || 'not recorded'}</p>
          </div>
        </details>
        <div className="flex flex-wrap items-center gap-2">
          {status === 'applicable' && <button type="button" className={`${buttonClass} bg-neutral-900 text-white`}
            disabled={applyBlocked || !candidate.manifest_digest}
            onClick={() => apply([candidate.id], candidate.manifest_digest, 'Application of this fix')}>Apply this fix</button>}
          <span className="flex flex-wrap items-center gap-2 text-xs text-neutral-600">
            <span>Was this fix useful?</span>
            {feedback[candidate.id]
              ? <span>Thanks. Your feedback was recorded.</span>
              : <>
                <button type="button" className={smallButtonClass} onClick={() => sendFeedback(candidate.id, 'accepted')}>Yes</button>
                <button type="button" className={smallButtonClass} onClick={() => sendFeedback(candidate.id, 'rejected')}>No</button>
              </>}
          </span>
        </div>
      </article>
    )
  }

  return (
    <section aria-labelledby="remediation-title" className="space-y-4 rounded-xl border border-neutral-200 bg-white p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="remediation-title" className="text-lg font-semibold text-neutral-900">Recommended fixes</h2>
          <p className="mt-1 text-sm text-neutral-600">
            {findingId ? 'Repository-aware repair for this finding, checked before you apply it.' : 'Repository-aware repairs, checked before you apply them one at a time.'}
          </p>
        </div>
        <button className={buttonClass} disabled={busy} onClick={refresh}>Refresh status</button>
      </div>
      {error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-800">{error}</p>}
      {notice && <p role="status" className="text-sm text-emerald-800">{notice}</p>}
      {!state && !error && <p role="status" className="text-sm text-neutral-600">Loading repair status…</p>}
      {state && !state.job && <p className="text-sm text-neutral-600">{capabilities.generate
        ? 'Generate fixes to inspect their code changes and verification results.'
        : 'Verified repairs are not enabled for this repository. Existing recommendations remain available below.'}</p>}
      {state?.job && <div role="status" className="rounded-lg bg-neutral-50 p-3 text-sm">
        <p className="font-medium capitalize">Repair: {label(state.job.state)}</p>
        {!terminal.has(state.job.state) && <p>Current step: {label(state.job.stage || state.job.state)}. You can leave this page and return later.</p>}
        {state.job.reason && <p className="mt-1">{reasonText(state.job.reason)}</p>}
      </div>}
      {staleHead && <div role="status" className="rounded-lg bg-amber-50 p-3 text-sm text-amber-900">
        <p className="font-medium">{STALE_HEAD_MESSAGE}</p>
      </div>}
      {action && <div role="status" className="rounded-lg bg-blue-50 p-3 text-sm text-blue-900">
        <p className="font-medium capitalize">Application: {label(action.state)}</p>
        {actionBlocked && blockedReason && <p className="mt-1">{blockedReason}</p>}
        {!actionBlocked && action.reason && <p>{reasonText(action.reason)}</p>}
        {action.commit_sha && <p>Commit: <code>{action.commit_sha.slice(0, 12)}</code></p>}
        {action.state === 'completed' && <p>The applied commit was re-analysed. The residual report is posted on the pull request.</p>}
        {mergeIntent?.state && <>
          <p className="mt-1">Merge: {label(mergeIntent.state)}</p>
          {mergeDescriptions[mergeIntent.state] && <p>{mergeDescriptions[mergeIntent.state]}</p>}
          {mergeBlockers.length > 0 && <ul className="mt-1 list-disc pl-5">
            {mergeBlockers.map((blocker, index) => <li key={`${blockerText(blocker)}:${index}`}>{blockerText(blocker)}</li>)}
          </ul>}
          {mergeIntent.cancellation_reason && <p>Cancellation reason: {label(mergeIntent.cancellation_reason)}</p>}
          {mergeIntent.observed_merge_sha && <p>Merge commit: <code>{mergeIntent.observed_merge_sha.slice(0, 12)}</code></p>}
          {mergeAttempts > 0 && <p>Merge attempts: {mergeAttempts}</p>}
          {mergeExpiry && <p>{mergeExpiry}</p>}
          {cancellableMerge.has(mergeIntent.state) && <button className={`${buttonClass} mt-2`} disabled={busy}
            onClick={() => perform(() => remediationAPI.cancelMerge(action.id), 'Merge request cancelled.')}>Cancel scheduled merge</button>}
        </>}
      </div>}
      {preview && <div className="space-y-4">
        <p className="text-sm font-medium"><span>{coverageSentence(allCandidates.length, allSkipped.length)}</span> · reviewed commit <code>{preview.head_sha?.slice(0, 12)}</code></p>
        {staleCandidates.length > 0 && <div role="status" className="rounded-lg bg-neutral-100 p-3 text-sm text-neutral-800">
          <p className="font-medium">{staleCandidates.length === 1 ? '1 remaining fix is stale' : `${staleCandidates.length} remaining fixes are stale`}: the pull request head moved when a fix was applied.</p>
          <p>Regenerate to get fixes verified against the new head for the findings that are still open.</p>
        </div>}
        {findingId && candidates.length === 0 && skipped.length === 0 && <p className="text-sm text-neutral-600">
          No verified fix was generated for this finding.
        </p>}
        {groups.map((group) => {
          const groupApplicable = group.candidates.filter((candidate) => (candidate.status || 'applicable') === 'applicable')
          const file = group.file
          const fileApply = groupApplicable.length > 1 && file && file.candidate_ids?.length === groupApplicable.length
          return (
            <section key={group.path} aria-label={group.path} className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="break-all text-sm font-semibold">{group.path}</h3>
                {fileApply && <button type="button" className={buttonClass} disabled={applyBlocked || !file.verified_together || !file.manifest_digest}
                  onClick={() => apply(file.candidate_ids, file.manifest_digest, `Application of all fixes in ${group.path}`)}>
                  Apply all fixes in this file
                </button>}
              </div>
              {fileApply && !file.verified_together && <p className="text-xs text-neutral-600">
                These fixes were not verified together. Apply them one at a time, or apply all {applicableCandidates.length} verified fixes.
              </p>}
              {group.candidates.map(renderCandidate)}
            </section>
          )
        })}
        {verification?.outcome && <p className="text-sm text-neutral-600">Verification outcome: {label(verification.outcome)}</p>}
        {skipped.length > 0 && <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-900">
          <p className="font-medium">{skipped.length === 1 ? '1 finding needs manual work' : `${skipped.length} findings need manual work`}</p>
          <ul className="mt-2 list-disc pl-5">{skipped.map((item, index) => <li key={item.finding_id || index}>{item.reason}</li>)}</ul>
        </div>}
      </div>}
      <div className={findingId
        ? 'flex flex-wrap gap-2 rounded-lg border border-neutral-200 bg-neutral-50 p-3'
        : 'flex flex-wrap gap-2'}>
        {findingId && <p className="w-full text-xs font-medium text-neutral-500">Pull request actions</p>}
        {showGenerate && <button className={buttonClass} disabled={busy || Boolean(error)} onClick={() => generate()}>
          {state?.job ? 'Generate new fixes' : 'Generate fixes'}
        </button>}
        {showRegenerate && <>
          <button className={buttonClass} disabled={regenerateBlocked}
            onClick={() => generate('Regeneration requested for the findings still open on the new head.')}>Regenerate remaining fixes</button>
          {actionInFlight && <p className="self-center text-xs text-neutral-600">Waiting for the analysis of the applied commit before regenerating.</p>}
        </>}
        {state?.job && !terminal.has(state.job.state) && <button className={buttonClass} disabled={busy}
          onClick={() => perform(() => remediationAPI.cancel(state.job.id), 'Cancellation requested.')}>Cancel generation</button>}
        {previewApplicable && applicableCandidates.length > 0 && <>
          <button className={buttonClass} disabled={applyBlocked}
            onClick={() => apply(applicableCandidates.map((candidate) => candidate.id), preview.manifest_digest, 'Application of all verified fixes')}>
            Apply all {applicableCandidates.length} verified fixes
          </button>
          {!capabilities.apply && <p className="self-center text-xs text-neutral-600">Applying fixes is turned off for this repository.</p>}
          <p className="w-full text-xs text-neutral-500">{HUMAN_MERGE_CAPTION}</p>
        </>}
      </div>
    </section>
  )
}
