import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import RemediationPanel, { RepairSession, coverageSentence } from '../RemediationPanel'
import { remediationAPI } from '../../services/api'
import { clearPrivateCaches } from '../../services/privateCache'

const auth = vi.hoisted(() => ({ user: { id: 'alice' } }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../../services/api', () => ({ remediationAPI: {
  latest: vi.fn(), preview: vi.fn(), generate: vi.fn(), cancel: vi.fn(), feedback: vi.fn(),
} }))
const ready = { job: { id: 'job-1', state: 'ready' }, action: null, capabilities: { generate: true, publish: true } }
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
  remediationAPI.generate.mockResolvedValue({ job: { id: 'job-2', state: 'queued' } })
  remediationAPI.feedback.mockResolvedValue({})
})

it('presents each finding with its fix and points at GitHub for applying it', async () => {
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('+safe(value)')
  expect(screen.getByText('-unsafe(value)')).toBeInTheDocument()
  expect(screen.getByText('Finding: SQL injection (src/query.js:12)')).toBeInTheDocument()
  expect(screen.getByText('1 verified fix; 1 finding needs manual work')).toBeInTheDocument()
  expect(screen.getByText(/Commit suggestion/)).toBeInTheDocument()
  expect(screen.getByText(/cannot push to your repository/)).toBeInTheDocument()
})

// The App holds no write access to repository contents, so the panel must offer no
// control that would commit or merge anything.
it('offers no button that applies a fix or merges the pull request', async () => {
  remediationAPI.preview.mockResolvedValue(twoFilePreview)
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('+safe(value)')
  expect(screen.queryByRole('button', { name: /^Apply/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /merge/i })).not.toBeInTheDocument()
  expect(remediationAPI.apply).toBeUndefined()
  expect(remediationAPI.cancelMerge).toBeUndefined()
})

it('shows applied and stale fixes greyed with no apply button and offers regeneration once the analysis is done', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'superseded' },
    action: { id: 'action-1', state: 'completed', commit_sha: 'c'.repeat(40) } })
  remediationAPI.preview.mockResolvedValue({ ...twoFilePreview, job_state: 'superseded', applicable: false, manifest_digest: null,
    candidates: [{ ...fixOne, status: 'applied', applied_commit_sha: 'c'.repeat(40) }, { ...fixTwo, status: 'stale', stale_reason: 'head_changed' }] })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Stale: the pull request head moved after this fix was verified. It will not be rebased or reapplied.')
  expect(screen.getByText(/1 remaining fix is stale/)).toBeInTheDocument()
  expect(screen.getByText(/Applied on GitHub/, { selector: 'p' })).toBeInTheDocument()
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
  expect(screen.getByText('Applied on GitHub: checking')).toBeInTheDocument()
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
  expect(screen.getByRole('button', { name: 'Generate new fixes' })).toBeEnabled()
})

it('explains a rejected action in plain words and keeps generation available', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'ready' },
    action: { id: 'action-1', state: 'rejected', rejection_reason: 'permission_revoked' } })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('The server reported: permission revoked.')
  expect(screen.getByRole('button', { name: 'Generate new fixes' })).toBeEnabled()
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

it('recovers the observed application status from the server on reload', async () => {
  remediationAPI.latest.mockResolvedValue({ ...ready, job: { id: 'job-1', state: 'superseded' },
    action: { id: 'action-1', state: 'checking', commit_sha: 'c'.repeat(40) } })
  remediationAPI.preview.mockResolvedValue({ ...preview, job_state: 'superseded', applicable: false, manifest_digest: null,
    candidates: [{ ...fixOne, status: 'applied', applied_commit_sha: 'c'.repeat(40) }] })
  render(<RepairSession pullRequestId="pr-1" />)
  await screen.findByText('Applied on GitHub: checking')
  expect(screen.getAllByText('c'.repeat(12)).length).toBeGreaterThan(0)
})
