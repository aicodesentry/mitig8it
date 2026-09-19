import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import RemediationPanel, { RepairSession, coverageSentence } from '../RemediationPanel'
import { remediationAPI } from '../../services/api'
import { clearPrivateCaches } from '../../services/privateCache'

const auth = vi.hoisted(() => ({ user: { id: 'alice' } }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../../services/api', () => ({ remediationAPI: {
  latest: vi.fn(), preview: vi.fn(), generate: vi.fn(), apply: vi.fn(), cancel: vi.fn(), cancelMerge: vi.fn(), feedback: vi.fn(),
} }))
const ready = { job: { id: 'job-1', state: 'ready' }, action: null, merge_intent: null, capabilities: { generate: true, apply: true, merge: true } }
const preview = { job_id: 'job-1', head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40), manifest_digest: 'digest',
  verified_tree_oid: 'e'.repeat(40),
  candidates: [{ id: 'fix-1', finding_ids: ['finding-1'], rationale: 'Preserve query behavior with parameters',
    verification_level: 'sandbox_verified',
    evidence: { status: 'passed', evidence_digest: 'd'.repeat(64), verified_tree_oid: 'e'.repeat(40) },
    changes: [{ path: 'src/query.js', original: 'const sql = base\nunsafe(value)', replacement: 'const sql = base\nsafe(value)', new_sha256: 'c'.repeat(64) }] }],
  verification: { outcome: 'passed', evidence_digest: 'd'.repeat(64), coverage_gaps: ['Only the changed files were scanned'] },
  skipped: [{ finding_id: 'finding-2', reason: 'The required behavior could not be verified' }] }
beforeEach(() => {
  vi.clearAllMocks()
  auth.user = { id: 'alice' }
  remediationAPI.latest.mockResolvedValue(ready)
  remediationAPI.preview.mockResolvedValue(preview)
  remediationAPI.apply.mockResolvedValue({ action: { id: 'action-1', state: 'requested' } })
  remediationAPI.feedback.mockResolvedValue({})
})

it('presents exact changes and manual coverage before accepting consent', async () => {
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('+safe(value)')
  expect(screen.getByText('-unsafe(value)')).toBeInTheDocument()
  expect(screen.getByText('1 verified fix; 1 finding needs manual work')).toBeInTheDocument()
  expect(screen.getByText('1 finding needs manual work')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Apply 1 fixes and merge when ready' }))
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledTimes(1))
  expect(remediationAPI.apply).toHaveBeenCalledWith('job-1', expect.objectContaining({
    head_sha: preview.head_sha, base_sha: preview.base_sha, manifest_digest: 'digest', candidate_ids: ['fix-1'], merge_when_ready: true,
  }))
})

it('states partial coverage honestly with correct pluralisation', () => {
  expect(coverageSentence(3, 2)).toBe('3 verified fixes; 2 findings need manual work')
  expect(coverageSentence(1, 1)).toBe('1 verified fix; 1 finding needs manual work')
  expect(coverageSentence(2, 0)).toBe('2 verified fixes')
  expect(coverageSentence(0, 1)).toBe('0 verified fixes; 1 finding needs manual work')
})

it('renders a unified diff with context, removal and addition lines', async () => {
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('+safe(value)')
  expect(screen.getByText('--- a/src/query.js')).toBeInTheDocument()
  expect(screen.getByText('+++ b/src/query.js')).toBeInTheDocument()
  expect(screen.getByText('@@ -1,2 +1,2 @@')).toBeInTheDocument()
  expect(screen.getByText(' const sql = base', { normalizer: (text) => text })).toBeInTheDocument()
})

it('shows behaviour, verification level, coverage limits and the auditable revision', async () => {
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Behavior preserved: verified by sandbox checks')
  expect(screen.getByText('Verification level: sandbox verified')).toBeInTheDocument()
  expect(screen.getByText('Only the changed files were scanned')).toBeInTheDocument()
  expect(screen.getByText('Verification outcome: passed')).toBeInTheDocument()
  expect(screen.getByText(`head ${'a'.repeat(40)}`)).toBeInTheDocument()
  expect(screen.getByText(`tree ${'e'.repeat(40)}`)).toBeInTheDocument()
  expect(screen.getByText(`evidence ${'d'.repeat(64)}`)).toBeInTheDocument()
})

it('claims a behaviour check only when the evidence lists one that passed', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, candidates: [{ ...preview.candidates[0],
    evidence: { status: 'passed', checks: [{ name: 'behavior_preserved', outcome: 'passed' }, { name: 'lint', outcome: 'passed' }] } }] })
  const view = render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Behavior preserved: verified by a behavior check')

  remediationAPI.preview.mockResolvedValue({ ...preview, candidates: [{ ...preview.candidates[0],
    evidence: { status: 'passed', checks: [{ name: 'lint', outcome: 'passed' }] } }] })
  view.rerender(<RepairSession pullRequestId="pr-1" key="no-behavior-check" />)
  await screen.findByText('Behavior preserved: not verified by a behavior check')
})

it('reads limitations, tree oid and verification level from the candidate evidence', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, verified_tree_oid: null,
    candidates: [{ ...preview.candidates[0], verification_level: null,
      evidence: { status: 'failed', verification_level: 'sandbox_verified', verified_tree_oid: '9'.repeat(40),
        limitations: [{ code: 'no_tests', message: 'The repository has no test command' }] } }] })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Behavior preserved: not verified')
  expect(screen.getByText('Verification level: sandbox verified')).toBeInTheDocument()
  expect(screen.getByText(`tree ${'9'.repeat(40)}`)).toBeInTheDocument()
  expect(screen.getByText('The repository has no test command')).toBeInTheDocument()
})

it('prefers the unified diff the server supplies over the client diff', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, candidates: [{ ...preview.candidates[0],
    changes: [{ path: 'src/query.js', original: 'unsafe(value)', replacement: 'safe(value)',
      unified_diff: '--- a/src/query.js\n+++ b/src/query.js\n@@ -7,2 +7,2 @@\n const sql = base\n-unsafe(value)\n+safe(value)\n' }] }] })
  render(<RepairSession pullRequestId="pr-1" />)
  expect(await screen.findByText('@@ -7,2 +7,2 @@')).toBeInTheDocument()
  expect(screen.getByText('+safe(value)')).toBeInTheDocument()
  expect(screen.getByText('-unsafe(value)')).toBeInTheDocument()
  expect(screen.queryByText('@@ -1,2 +1,2 @@')).not.toBeInTheDocument()
})

it('warns in amber when a candidate was never verified in a sandbox', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview,
    candidates: [{ ...preview.candidates[0], verification_level: 'development_unverified', evidence: null, limitations: ['No regression test was produced'] }] })
  render(<RepairSession pullRequestId="pr-1" />)
  const warning = await screen.findByText('Verification level: development unverified. This fix was not verified in an isolated sandbox.')
  expect(warning.className).toContain('amber')
  expect(screen.getByText('Behavior preserved: not verified')).toBeInTheDocument()
  expect(screen.getByText('No regression test was produced')).toBeInTheDocument()
})

it('renders only the matching candidate for a single finding and keeps batch actions secondary', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, candidates: [
    preview.candidates[0],
    { ...preview.candidates[0], id: 'fix-2', finding_ids: ['finding-9'], rationale: 'Contain the resolved path', changes: [{ path: 'src/files.js', original: 'open(p)', replacement: 'openInside(base, p)' }] },
  ] })
  render(<RepairSession pullRequestId="pr-1" findingId="finding-1" />)
  await screen.findByText('Preserve query behavior with parameters')
  expect(screen.queryByText('Contain the resolved path')).not.toBeInTheDocument()
  expect(screen.getByText('Pull request actions')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Apply 2 verified fixes' })).toBeEnabled()
})

it('shows the manual work reason for the selected finding only', async () => {
  render(<RepairSession pullRequestId="pr-1" findingId="finding-2" />)
  await screen.findByText('The required behavior could not be verified')
  expect(screen.queryByText('Preserve query behavior with parameters')).not.toBeInTheDocument()
})

it('lists the finding IDs beside each candidate in the batch view', async () => {
  render(<RepairSession pullRequestId="pr-1" />)
  expect(await screen.findByText('Findings: finding-1')).toBeInTheDocument()
})

it('blocks application when the pull request head moved past the preview', async () => {
  render(<RepairSession pullRequestId="pr-1" liveHeadSha={'f'.repeat(40)} />)
  await screen.findByText('The pull request has new commits since these fixes were generated; regenerate to continue.')
  expect(screen.getByRole('button', { name: 'Apply 1 verified fixes' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Generate new fixes' })).toBeEnabled()
})

it('maps an apply conflict to the stale head state', async () => {
  remediationAPI.apply.mockRejectedValueOnce({ response: { status: 409, data: { error: 'Preview revision or manifest has changed' } } })
  render(<RepairSession pullRequestId="pr-1" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Apply 1 verified fixes' }))
  await screen.findByText('The pull request has new commits since these fixes were generated; regenerate to continue.')
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Apply 1 verified fixes' })).toBeDisabled()
})

it('explains a rejected action in plain words and keeps generation available', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'ready' },
    action: { id: 'action-1', state: 'rejected', rejection_reason: 'permission_revoked' } })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Your write access to this repository was revoked, so nothing was applied.')
  expect(screen.getByRole('button', { name: 'Generate new fixes' })).toBeEnabled()
})

it('disables rather than hides actions the server capabilities withhold', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, capabilities: { generate: true, apply: true, merge: false } })
  render(<RepairSession pullRequestId="pr-1" />)
  expect(await screen.findByRole('button', { name: 'Apply 1 fixes and merge when ready' })).toBeDisabled()
  expect(screen.getByText('Merge on application is turned off for this repository.')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Apply 1 verified fixes' })).toBeEnabled()
})

it('disables application with a reason when applying is turned off', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, capabilities: { generate: true, apply: false, merge: true } })
  render(<RepairSession pullRequestId="pr-1" />)
  expect(await screen.findByRole('button', { name: 'Apply 1 verified fixes' })).toBeDisabled()
  expect(screen.getByText('Applying fixes is turned off for this repository.')).toBeInTheDocument()
})

it('describes each merge state and only offers cancellation while cancellable', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'completed' },
    action: { id: 'action-1', state: 'completed' },
    merge_intent: { id: 'intent-1', action_id: 'action-1', state: 'blocked', merge_attempts: 2,
      expires_at: '2099-01-01T00:00:00.000Z',
      blockers: [{ code: 'review_required', message: 'A required review is missing' }, 'Checks are still running'] } })
  const view = render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('GitHub is blocking this merge.')
  expect(screen.getByText('review required: A required review is missing')).toBeInTheDocument()
  expect(screen.getByText('Checks are still running')).toBeInTheDocument()
  expect(screen.getByText('Merge attempts: 2')).toBeInTheDocument()
  expect(screen.getByText(/Merge request expires/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Cancel scheduled merge' })).toBeInTheDocument()

  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'completed' },
    action: { id: 'action-1', state: 'completed' },
    merge_intent: { id: 'intent-1', action_id: 'action-1', state: 'merged', blockers: [], observed_merge_sha: 'f'.repeat(40) } })
  view.rerender(<RepairSession pullRequestId="pr-1" key="merged" />)
  await screen.findByText('The pull request was merged.')
  expect(screen.getByText('f'.repeat(12))).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Cancel scheduled merge' })).not.toBeInTheDocument()
})

it('treats an in-flight merge as waiting and offers no buttons for it', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'completed' },
    action: { id: 'action-1', state: 'completed' },
    merge_intent: { id: 'intent-1', action_id: 'action-1', state: 'merging', blockers: [] } })
  const view = render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('The merge request was sent to GitHub.')
  expect(screen.queryByRole('button', { name: 'Cancel scheduled merge' })).not.toBeInTheDocument()

  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'completed' },
    action: { id: 'action-1', state: 'completed' },
    merge_intent: { id: 'intent-1', action_id: 'action-1', state: 'reconciling', blockers: [] } })
  view.rerender(<RepairSession pullRequestId="pr-1" key="reconciling" />)
  await screen.findByText('Checking with GitHub whether the merge completed.')
  expect(screen.queryByRole('button', { name: 'Cancel scheduled merge' })).not.toBeInTheDocument()
})

it('names the cancellation reason once a merge intent is cancelled', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'completed' },
    action: { id: 'action-1', state: 'completed' },
    merge_intent: { id: 'intent-1', action_id: 'action-1', state: 'cancelled', blockers: [], cancellation_reason: 'requested_by_actor' } })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('The merge request was cancelled.')
  expect(screen.getByText('Cancellation reason: requested by actor')).toBeInTheDocument()
})

it('records per candidate feedback and stays silent when the route is missing', async () => {
  remediationAPI.feedback.mockRejectedValue({ response: { status: 404 } })
  render(<RepairSession pullRequestId="pr-1" />)
  const article = (await screen.findByText('Preserve query behavior with parameters')).closest('article')
  fireEvent.click(within(article).getByRole('button', { name: 'Yes' }))
  await waitFor(() => expect(remediationAPI.feedback).toHaveBeenCalledWith('job-1', { candidate_id: 'fix-1', outcome: 'accepted' }))
  expect(await screen.findByText('Thanks. Your feedback was recorded.')).toBeInTheDocument()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it('does not submit twice while a write is in flight', async () => {
  let resolve
  remediationAPI.apply.mockImplementation(() => new Promise(done => { resolve = done }))
  render(<RepairSession pullRequestId="pr-1" />)
  const button = await screen.findByRole('button', { name: 'Apply 1 verified fixes' })
  fireEvent.click(button); fireEvent.click(button)
  expect(remediationAPI.apply).toHaveBeenCalledTimes(1)
  await act(async () => resolve({}))
})

it('blocks applying a stale preview after a failed refresh', async () => {
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('+safe(value)')
  remediationAPI.latest.mockRejectedValueOnce(new Error('offline'))
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  await screen.findByRole('alert')
  expect(screen.getByRole('button', { name: 'Apply 1 verified fixes' })).toBeDisabled()
  expect(remediationAPI.apply).not.toHaveBeenCalled()
})

it('reuses the application identity after an uncertain request and refresh', async () => {
  remediationAPI.apply.mockRejectedValueOnce(new Error('response lost'))
  render(<RepairSession pullRequestId="pr-1" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Apply 1 verified fixes' }))
  await screen.findByRole('alert')
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  fireEvent.click(screen.getByRole('button', { name: 'Apply 1 verified fixes' }))
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledTimes(2))
  expect(remediationAPI.apply.mock.calls[0][1].idempotency_key).toBe(remediationAPI.apply.mock.calls[1][1].idempotency_key)
})

it('discards outstanding private results on account change', async () => {
  let resolve
  remediationAPI.latest.mockImplementationOnce(() => new Promise(done => { resolve = done }))
    .mockResolvedValue({ job: null, capabilities: {} })
  const view = render(<RemediationPanel pullRequestId="pr-1" />)
  auth.user = { id: 'bob' }; view.rerender(<RemediationPanel pullRequestId="pr-1" />)
  await act(async () => resolve(ready))
  expect(screen.queryByText('+safe(value)')).not.toBeInTheDocument()
})

it('discards requests when private session epoch is cleared', async () => {
  let resolve
  remediationAPI.latest.mockImplementation(() => new Promise(done => { resolve = done }))
  render(<RepairSession pullRequestId="pr-1" />)
  clearPrivateCaches()
  await act(async () => resolve(ready))
  expect(screen.queryByText('+safe(value)')).not.toBeInTheDocument()
})

it('recovers pending application status from the server on reload', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'completed' },
    action: { id: 'action-1', state: 'checking', commit_sha: 'c'.repeat(40) },
    merge_intent: { id: 'intent-1', action_id: 'action-1', state: 'waiting_for_checks', blockers: [], merge_attempts: 0 } })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Application: checking')
  expect(screen.queryByRole('button', { name: 'Apply 1 verified fixes' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Cancel scheduled merge' }))
  await waitFor(() => expect(remediationAPI.cancelMerge).toHaveBeenCalledWith('action-1'))
})
