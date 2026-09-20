import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import RemediationPanel, { RepairSession, coverageSentence, groupByFile } from '../RemediationPanel'
import { remediationAPI } from '../../services/api'
import { clearPrivateCaches } from '../../services/privateCache'

const auth = vi.hoisted(() => ({ user: { id: 'alice' } }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../../services/api', () => ({ remediationAPI: {
  latest: vi.fn(), preview: vi.fn(), generate: vi.fn(), apply: vi.fn(), cancel: vi.fn(), cancelMerge: vi.fn(), feedback: vi.fn(),
} }))
const ready = { job: { id: 'job-1', state: 'ready' }, action: null, merge_intent: null, capabilities: { generate: true, apply: true, merge: false } }
const fixOne = { id: 'fix-1', finding_ids: ['finding-1'], rationale: 'Preserve query behavior with parameters',
  verification_level: 'sandbox_verified', status: 'applicable', manifest_digest: 'digest-fix-1', paths: ['src/query.js'],
  evidence: { status: 'passed', evidence_digest: 'd'.repeat(64), verified_tree_oid: 'e'.repeat(40) },
  changes: [{ path: 'src/query.js', original: 'const sql = base\nunsafe(value)', replacement: 'const sql = base\nsafe(value)', new_sha256: 'c'.repeat(64) }] }
const fixTwo = { ...fixOne, id: 'fix-2', finding_ids: ['finding-9'], rationale: 'Contain the resolved path', manifest_digest: 'digest-fix-2',
  paths: ['src/files.js'], changes: [{ path: 'src/files.js', original: 'open(p)', replacement: 'openInside(base, p)' }] }
const preview = { job_id: 'job-1', job_state: 'ready', applicable: true, head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40), manifest_digest: 'digest',
  verified_tree_oid: 'e'.repeat(40),
  candidates: [fixOne],
  files: [{ path: 'src/query.js', candidate_ids: ['fix-1'], verified_together: true, manifest_digest: 'digest-fix-1' }],
  findings: [{ id: 'finding-1', title: 'SQL injection', file_path: 'src/query.js', line_start: 12, severity: 'high' }],
  verification: { outcome: 'passed', evidence_digest: 'd'.repeat(64), coverage_gaps: ['Only the changed files were scanned'] },
  skipped: [{ finding_id: 'finding-2', reason: 'The required behavior could not be verified' }] }
const twoFilePreview = { ...preview, candidates: [fixOne, fixTwo], manifest_digest: 'digest-batch',
  files: [{ path: 'src/query.js', candidate_ids: ['fix-1'], verified_together: true, manifest_digest: 'digest-fix-1' },
    { path: 'src/files.js', candidate_ids: ['fix-2'], verified_together: true, manifest_digest: 'digest-fix-2' }],
  findings: [...preview.findings, { id: 'finding-9', title: 'Path traversal', file_path: 'src/files.js', line_start: 3, severity: 'high' }] }
beforeEach(() => {
  vi.clearAllMocks()
  auth.user = { id: 'alice' }
  remediationAPI.latest.mockResolvedValue(ready)
  remediationAPI.preview.mockResolvedValue(preview)
  remediationAPI.apply.mockResolvedValue({ action: { id: 'action-1', state: 'requested' } })
  remediationAPI.generate.mockResolvedValue({ job: { id: 'job-2', state: 'queued' } })
  remediationAPI.feedback.mockResolvedValue({})
})

it('presents each finding with its fix and applies one fix by explicit request without merging', async () => {
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('+safe(value)')
  expect(screen.getByText('-unsafe(value)')).toBeInTheDocument()
  expect(screen.getByText('Finding: SQL injection (src/query.js:12)')).toBeInTheDocument()
  expect(screen.getByText('1 verified fix; 1 finding needs manual work')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /merge when ready/ })).not.toBeInTheDocument()
  expect(screen.getByText(/Merging stays a human action on GitHub/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Apply this fix' }))
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledTimes(1))
  expect(remediationAPI.apply).toHaveBeenCalledWith('job-1', expect.objectContaining({
    head_sha: preview.head_sha, base_sha: preview.base_sha, manifest_digest: 'digest-fix-1', candidate_ids: ['fix-1'], merge_when_ready: false,
  }))
})

it('groups fixes by file and offers a file button and a batch button with their own consent digests', async () => {
  remediationAPI.preview.mockResolvedValue(twoFilePreview)
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Contain the resolved path')
  expect(screen.getByRole('heading', { name: 'src/query.js' })).toBeInTheDocument()
  expect(screen.getByRole('heading', { name: 'src/files.js' })).toBeInTheDocument()
  expect(screen.getAllByRole('button', { name: 'Apply this fix' })).toHaveLength(2)
  fireEvent.click(screen.getByRole('button', { name: 'Apply all 2 verified fixes' }))
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledWith('job-1', expect.objectContaining({
    manifest_digest: 'digest-batch', candidate_ids: ['fix-1', 'fix-2'], merge_when_ready: false,
  })))
})

it('offers a file level button only for a file with several fixes and disables it when they were not verified together', async () => {
  const sameFile = { ...fixTwo, paths: ['src/query.js'], changes: [{ path: 'src/query.js', original: 'a', replacement: 'b' }] }
  const third = { ...fixTwo, id: 'fix-3', finding_ids: ['finding-3'], rationale: 'Escape the shell argument', paths: ['src/other.js'], changes: [{ path: 'src/other.js', original: 'c', replacement: 'd' }] }
  remediationAPI.preview.mockResolvedValue({ ...twoFilePreview, candidates: [fixOne, sameFile, third], manifest_digest: 'digest-batch',
    files: [{ path: 'src/query.js', candidate_ids: ['fix-1', 'fix-2'], verified_together: false, manifest_digest: null },
      { path: 'src/other.js', candidate_ids: ['fix-3'], verified_together: true, manifest_digest: 'digest-fix-3' }] })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Contain the resolved path')
  expect(screen.getByRole('button', { name: 'Apply all fixes in this file' })).toBeDisabled()
  expect(screen.getByText('These fixes were not verified together. Apply them one at a time, or apply all 3 verified fixes.')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Apply all 3 verified fixes' })).toBeEnabled()

  const verifiedFile = groupByFile([fixOne, sameFile], [{ path: 'src/query.js', candidate_ids: ['fix-1', 'fix-2'], verified_together: true, manifest_digest: 'digest-file' }])
  expect(verifiedFile).toHaveLength(1)
  expect(verifiedFile[0].candidates.map((candidate) => candidate.id)).toEqual(['fix-1', 'fix-2'])
})

it('applies a whole file when the server verified that combination', async () => {
  const sameFile = { ...fixTwo, paths: ['src/query.js'], changes: [{ path: 'src/query.js', original: 'a', replacement: 'b' }] }
  remediationAPI.preview.mockResolvedValue({ ...twoFilePreview, candidates: [fixOne, sameFile], manifest_digest: 'digest-batch',
    files: [{ path: 'src/query.js', candidate_ids: ['fix-1', 'fix-2'], verified_together: true, manifest_digest: 'digest-batch' }] })
  render(<RepairSession pullRequestId="pr-1" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Apply all fixes in this file' }))
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledWith('job-1', expect.objectContaining({
    manifest_digest: 'digest-batch', candidate_ids: ['fix-1', 'fix-2'], merge_when_ready: false,
  })))
})

it('shows applied and stale fixes greyed with no apply button and offers regeneration once the analysis is done', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'superseded' },
    action: { id: 'action-1', state: 'completed', commit_sha: 'c'.repeat(40) } })
  remediationAPI.preview.mockResolvedValue({ ...twoFilePreview, job_state: 'superseded', applicable: false, manifest_digest: null,
    candidates: [{ ...fixOne, status: 'applied', applied_commit_sha: 'c'.repeat(40) }, { ...fixTwo, status: 'stale', stale_reason: 'head_changed' }] })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Stale: the pull request head moved after this fix was verified. It will not be rebased or reapplied.')
  expect(screen.getByText(/1 remaining fix is stale/)).toBeInTheDocument()
  expect(screen.getByText(/Applied/, { selector: 'p' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Apply this fix' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Apply all/ })).not.toBeInTheDocument()
  const stale = screen.getByText('Contain the resolved path').closest('article')
  expect(stale.getAttribute('data-status')).toBe('stale')
  expect(stale.className).toContain('opacity-60')
  fireEvent.click(screen.getByRole('button', { name: 'Regenerate remaining fixes' }))
  await waitFor(() => expect(remediationAPI.generate).toHaveBeenCalledWith('pr-1', expect.objectContaining({ idempotency_key: expect.any(String) })))
  expect(await screen.findByText('Regeneration requested for the findings still open on the new head.')).toBeInTheDocument()
})

it('waits for the analysis of the applied commit before allowing regeneration', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'superseded' },
    action: { id: 'action-1', state: 'checking', commit_sha: 'c'.repeat(40) } })
  remediationAPI.preview.mockResolvedValue({ ...twoFilePreview, job_state: 'superseded', applicable: false, manifest_digest: null,
    candidates: [{ ...fixOne, status: 'applied', applied_commit_sha: 'c'.repeat(40) }, { ...fixTwo, status: 'stale', stale_reason: 'head_changed' }] })
  render(<RepairSession pullRequestId="pr-1" />)
  expect(await screen.findByRole('button', { name: 'Regenerate remaining fixes' })).toBeDisabled()
  expect(screen.getByText('Waiting for the analysis of the applied commit before regenerating.')).toBeInTheDocument()
  expect(screen.getByText('Application: checking')).toBeInTheDocument()
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
  expect(screen.getByText('consent digest-fix-1')).toBeInTheDocument()
})

it('claims a behaviour check only when the evidence lists one that passed', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, candidates: [{ ...fixOne,
    evidence: { status: 'passed', checks: [{ name: 'behavior_preserved', outcome: 'passed' }, { name: 'lint', outcome: 'passed' }] } }] })
  const view = render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Behavior preserved: verified by a behavior check')

  remediationAPI.preview.mockResolvedValue({ ...preview, candidates: [{ ...fixOne,
    evidence: { status: 'passed', checks: [{ name: 'lint', outcome: 'passed' }] } }] })
  view.rerender(<RepairSession pullRequestId="pr-1" key="no-behavior-check" />)
  await screen.findByText('Behavior preserved: not verified by a behavior check')
})

it('reads limitations, tree oid and verification level from the candidate evidence', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, verified_tree_oid: null,
    candidates: [{ ...fixOne, verification_level: null,
      evidence: { status: 'failed', verification_level: 'sandbox_verified', verified_tree_oid: '9'.repeat(40),
        limitations: [{ code: 'no_tests', message: 'The repository has no test command' }] } }] })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Behavior preserved: not verified')
  expect(screen.getByText('Verification level: sandbox verified')).toBeInTheDocument()
  expect(screen.getByText(`tree ${'9'.repeat(40)}`)).toBeInTheDocument()
  expect(screen.getByText('The repository has no test command')).toBeInTheDocument()
})

it('prefers the unified diff the server supplies over the client diff', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, candidates: [{ ...fixOne,
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
    candidates: [{ ...fixOne, verification_level: 'development_unverified', evidence: null, limitations: ['No regression test was produced'] }] })
  render(<RepairSession pullRequestId="pr-1" />)
  const warning = await screen.findByText('Verification level: development unverified. This fix was not verified in an isolated sandbox.')
  expect(warning.className).toContain('amber')
  expect(screen.getByText('Behavior preserved: not verified')).toBeInTheDocument()
  expect(screen.getByText('No regression test was produced')).toBeInTheDocument()
})

it('renders only the matching candidate for a single finding and keeps batch actions secondary', async () => {
  remediationAPI.preview.mockResolvedValue(twoFilePreview)
  render(<RepairSession pullRequestId="pr-1" findingId="finding-1" />)
  await screen.findByText('Preserve query behavior with parameters')
  expect(screen.queryByText('Contain the resolved path')).not.toBeInTheDocument()
  expect(screen.getByText('Pull request actions')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Apply this fix' })).toBeEnabled()
  expect(screen.getByRole('button', { name: 'Apply all 2 verified fixes' })).toBeEnabled()
})

it('shows the manual work reason for the selected finding only', async () => {
  render(<RepairSession pullRequestId="pr-1" findingId="finding-2" />)
  await screen.findByText('The required behavior could not be verified')
  expect(screen.queryByText('Preserve query behavior with parameters')).not.toBeInTheDocument()
})

it('falls back to the finding id when the preview carries no finding metadata', async () => {
  remediationAPI.preview.mockResolvedValue({ ...preview, findings: [] })
  render(<RepairSession pullRequestId="pr-1" />)
  expect(await screen.findByText('Finding: finding-1')).toBeInTheDocument()
})

it('blocks application when the pull request head moved past the preview', async () => {
  render(<RepairSession pullRequestId="pr-1" liveHeadSha={'f'.repeat(40)} />)
  await screen.findByText('The pull request has new commits since these fixes were generated; regenerate to continue.')
  expect(screen.getByRole('button', { name: 'Apply this fix' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Apply all 1 verified fixes' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Generate new fixes' })).toBeEnabled()
})

it('maps an apply conflict to the stale head state', async () => {
  remediationAPI.apply.mockRejectedValueOnce({ response: { status: 409, data: { error: 'Preview revision or manifest has changed' } } })
  render(<RepairSession pullRequestId="pr-1" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Apply this fix' }))
  await screen.findByText('The pull request has new commits since these fixes were generated; regenerate to continue.')
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Apply this fix' })).toBeDisabled()
})

it('reports a stale candidate rejection in plain words without hiding the preview', async () => {
  remediationAPI.apply.mockRejectedValueOnce({ response: { status: 409, data: { error: 'A selected fix is stale: the pull request head moved since it was verified. Regenerate remaining fixes.', code: 'candidate_stale' } } })
  render(<RepairSession pullRequestId="pr-1" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Apply this fix' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('A selected fix is stale')
})

it('explains a rejected action in plain words and keeps generation available', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'ready' },
    action: { id: 'action-1', state: 'rejected', rejection_reason: 'permission_revoked' } })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Your write access to this repository was revoked, so nothing was applied.')
  expect(screen.getByRole('button', { name: 'Generate new fixes' })).toBeEnabled()
})

it('explains an unverified combination rejection', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, action: { id: 'action-1', state: 'rejected', rejection_reason: 'subset_not_verified' } })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('This combination of fixes was not verified together. Apply one fix at a time, or apply all verified fixes.')
})

it('disables application with a reason when applying is turned off', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, capabilities: { generate: true, apply: false, merge: false } })
  render(<RepairSession pullRequestId="pr-1" />)
  expect(await screen.findByRole('button', { name: 'Apply this fix' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Apply all 1 verified fixes' })).toBeDisabled()
  expect(screen.getByText('Applying fixes is turned off for this repository.')).toBeInTheDocument()
})

it('never offers a merge button even when the operator flag reports merge as available', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, capabilities: { generate: true, apply: true, merge: true } })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByRole('button', { name: 'Apply this fix' })
  expect(screen.queryByRole('button', { name: /merge/i })).not.toBeInTheDocument()
})

it('describes an existing merge intent and only offers cancellation while cancellable', async () => {
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
  expect(screen.getByRole('button', { name: 'Cancel scheduled merge' })).toBeInTheDocument()

  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'completed' },
    action: { id: 'action-1', state: 'completed' },
    merge_intent: { id: 'intent-1', action_id: 'action-1', state: 'merged', blockers: [], observed_merge_sha: 'f'.repeat(40) } })
  view.rerender(<RepairSession pullRequestId="pr-1" key="merged" />)
  await screen.findByText('The pull request was merged.')
  expect(screen.queryByRole('button', { name: 'Cancel scheduled merge' })).not.toBeInTheDocument()
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
  const button = await screen.findByRole('button', { name: 'Apply this fix' })
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
  expect(screen.getByRole('button', { name: 'Apply this fix' })).toBeDisabled()
  expect(remediationAPI.apply).not.toHaveBeenCalled()
})

it('reuses the application identity after an uncertain request and refresh', async () => {
  remediationAPI.apply.mockRejectedValueOnce(new Error('response lost'))
  render(<RepairSession pullRequestId="pr-1" />)
  fireEvent.click(await screen.findByRole('button', { name: 'Apply this fix' }))
  await screen.findByRole('alert')
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }))
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  fireEvent.click(screen.getByRole('button', { name: 'Apply this fix' }))
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledTimes(2))
  expect(remediationAPI.apply.mock.calls[0][1].idempotency_key).toBe(remediationAPI.apply.mock.calls[1][1].idempotency_key)
})

it('uses a fresh consent identity for a different subset', async () => {
  remediationAPI.preview.mockResolvedValue(twoFilePreview)
  render(<RepairSession pullRequestId="pr-1" />)
  const buttons = await screen.findAllByRole('button', { name: 'Apply this fix' })
  fireEvent.click(buttons[0])
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledTimes(1))
  fireEvent.click(screen.getAllByRole('button', { name: 'Apply this fix' })[1])
  await waitFor(() => expect(remediationAPI.apply).toHaveBeenCalledTimes(2))
  expect(remediationAPI.apply.mock.calls[0][1].idempotency_key).not.toBe(remediationAPI.apply.mock.calls[1][1].idempotency_key)
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

it('recovers pending application status from the server on reload and hides apply buttons', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'superseded' },
    action: { id: 'action-1', state: 'checking', commit_sha: 'c'.repeat(40) } })
  remediationAPI.preview.mockResolvedValue({ ...preview, job_state: 'superseded', applicable: false, manifest_digest: null,
    candidates: [{ ...fixOne, status: 'applied', applied_commit_sha: 'c'.repeat(40) }] })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Application: checking')
  expect(screen.getAllByText('c'.repeat(12)).length).toBeGreaterThan(0)
  expect(screen.queryByRole('button', { name: 'Apply this fix' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Apply all/ })).not.toBeInTheDocument()
})
