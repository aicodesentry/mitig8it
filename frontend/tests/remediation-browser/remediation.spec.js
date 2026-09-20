import { test, expect } from '@playwright/test'

const pr = '11111111-1111-4111-8111-111111111111'
const headSha = 'a'.repeat(40)

const finding = { id: 'finding', title: 'SQL injection', category: 'injection', severity: 'high', confidence: 0.99,
  code_snippet: 'query(input)', remediation: 'Use query parameters.', remediation_patch: 'query(sql, [input])' }

const firstFix = { id: 'candidate', finding_ids: ['finding'], rationale: 'Preserve the query while separating input values.',
  verification_level: 'sandbox_verified', status: 'applicable', manifest_digest: 'd'.repeat(64), paths: ['src/query.js'],
  evidence: { status: 'passed', evidence_digest: 'a'.repeat(64), verified_tree_oid: 'e'.repeat(40) },
  changes: [{ path: 'src/query.js', original: 'query(input)', replacement: 'query(sql, [input])', new_sha256: 'c'.repeat(64) }] }
const otherFix = { ...firstFix, id: 'other', finding_ids: ['third'], rationale: 'Contain the resolved path.', manifest_digest: 'f'.repeat(64),
  paths: ['src/files.js'], changes: [{ path: 'src/files.js', original: 'open(p)', replacement: 'openInside(base, p)' }] }
const previewBody = {
  job_id: 'job', job_state: 'ready', applicable: true, head_sha: headSha, base_sha: 'b'.repeat(40), manifest_digest: '1'.repeat(64), verified_tree_oid: 'e'.repeat(40),
  candidates: [firstFix, otherFix],
  files: [{ path: 'src/query.js', candidate_ids: ['candidate'], verified_together: true, manifest_digest: 'd'.repeat(64) },
    { path: 'src/files.js', candidate_ids: ['other'], verified_together: true, manifest_digest: 'f'.repeat(64) }],
  findings: [{ id: 'finding', title: 'SQL injection', file_path: 'src/query.js', line_start: 4, severity: 'high' },
    { id: 'third', title: 'Path traversal', file_path: 'src/files.js', line_start: 9, severity: 'high' }],
  verification: { outcome: 'passed', evidence_digest: 'a'.repeat(64), coverage_gaps: ['Only the changed files were scanned.'] },
  skipped: [{ finding_id: 'second', reason: 'Business behavior needs manual review.' }],
}
// After the first fix is applied the head moved: that fix is applied, the other is stale.
const appliedPreviewBody = {
  ...previewBody, job_state: 'superseded', applicable: false, manifest_digest: null,
  candidates: [{ ...firstFix, status: 'applied', applied_commit_sha: 'c'.repeat(40) }, { ...otherFix, status: 'stale', stale_reason: 'head_changed' }],
}

// One fixture shape for every scenario: only the account and the live head change.
function installFixture(page, options = {}) {
  const session = { user: options.user || { id: 'user-1', github_username: 'developer' }, livePrHead: options.livePrHead || headSha }
  const counters = { writes: 0, applied: false, cancelled: false }
  page.route('**/*', async route => {
    const url = new URL(route.request().url())
    if (!['localhost', '127.0.0.1'].includes(url.hostname)) return route.abort()
    const path = url.pathname
    if (!path.startsWith('/api/') && !path.startsWith('/auth/')) return route.continue()
    const respond = body => route.fulfill({ status: 200, contentType: 'application/json', headers: {
      'access-control-allow-origin': 'http://127.0.0.1:5179', 'access-control-allow-credentials': 'true',
      'access-control-allow-headers': 'content-type,x-csrf-protection,cache-control,pragma',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
    }, body: JSON.stringify(body) })
    if (route.request().method() === 'OPTIONS') return respond({})
    if (path === '/auth/me') return respond({ user: session.user })
    if (path === '/api/installations') return respond({ installations: [{ id: 1, status: 'active' }] })
    if (path === '/api/repositories') return respond({ repositories: [{ id: 'repo', full_name: 'fixture/security', is_active: true }] })
    if (path === '/api/reports/summary') return respond({ summary: { total_analyses: 1, completed: 1 } })
    if (path === `/api/pull-requests/${pr}/findings`) {
      if (session.user.id !== 'user-1') return respond({ findings: [], pull_request: null })
      return respond({ findings: [finding], pull_request: { id: pr, head_sha: session.livePrHead } })
    }
    if (path === `/api/pull-requests/${pr}/remediations`) {
      if (session.user.id !== 'user-1') return respond({ capabilities: { generate: true, apply: true, merge: true }, job: null, action: null, merge_intent: null })
      return respond({
        capabilities: { generate: true, apply: true, merge: false }, job: { id: 'job', state: counters.applied ? 'superseded' : 'ready' },
        action: counters.applied ? { id: 'action', state: 'checking', reason: null, rejection_reason: null, commit_sha: 'c'.repeat(40) } : null,
        merge_intent: null,
      })
    }
    if (path === '/api/remediations/job/preview') return respond(counters.applied ? appliedPreviewBody : previewBody)
    if (path === '/api/remediations/job/apply') {
      expect(route.request().headers()['x-csrf-protection']).toBe('1')
      expect(route.request().postDataJSON()).toMatchObject({ manifest_digest: 'd'.repeat(64), head_sha: headSha, candidate_ids: ['candidate'] })
      counters.writes += 1; counters.applied = true
      return respond({ action: { id: 'action', state: 'requested' } })
    }
    if (path === '/api/remediations/job/feedback') return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'Not found' }) })
    if (path === '/api/remediation-actions/action/cancel-merge') {
      counters.cancelled = true
      return respond({ state: 'cancelled', github_cancellation: null,
        merge_intent: { id: 'intent', action_id: 'action', state: 'cancelled', blockers: [], merge_attempts: 0,
          cancellation_reason: 'requested_by_actor', latest_policy_checks: {} } })
    }
    return route.fulfill({ status: 404, body: JSON.stringify({ error: 'Unexpected fixture request' }) })
  })
  return { session, counters }
}

test('reviewed fix survives reload, applies once by explicit request, and never offers a merge', async ({ page }) => {
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  const { counters } = installFixture(page)
  await page.goto(`/dashboard/pull-requests/${pr}/findings`)
  await expect(page.getByText('Preserve the query while separating input values.')).toBeVisible()
  await expect(page.getByText('2 verified fixes; 1 finding needs manual work')).toBeVisible()
  await expect(page.getByText('Merging stays a human action on GitHub.')).toBeVisible()
  await expect(page.getByRole('button', { name: /merge when ready/ })).toHaveCount(0)
  await page.getByRole('button', { name: 'Yes' }).first().click()
  await expect(page.getByText('Thanks. Your feedback was recorded.')).toBeVisible()
  await page.getByRole('button', { name: 'Apply this fix' }).first().click()
  await expect(page.getByText('Application: checking')).toBeVisible()
  expect(counters.writes).toBe(1)
  await page.reload()
  await expect(page.getByText('Application: checking')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Apply this fix' })).toHaveCount(0)
  await expect(page.getByText('Stale: the pull request head moved after this fix was verified. It will not be rebased or reapplied.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Regenerate remaining fixes' })).toBeDisabled()
  expect(errors).toEqual([])
  expect(counters.writes).toBe(1)
})

test('a new commit on the pull request blocks the reviewed batch until it is regenerated', async ({ page }) => {
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  const { counters } = installFixture(page, { livePrHead: 'f'.repeat(40) })
  await page.goto(`/dashboard/pull-requests/${pr}/findings`)
  await expect(page.getByText('The pull request has new commits since these fixes were generated; regenerate to continue.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Apply this fix' }).first()).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Apply all 2 verified fixes' })).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Generate new fixes' })).toBeEnabled()
  expect(counters.writes).toBe(0)
  expect(errors).toEqual([])
})

test('switching accounts never shows the previous account private preview', async ({ page }) => {
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  const { session } = installFixture(page)
  await page.goto(`/dashboard/pull-requests/${pr}/findings`)
  await expect(page.getByText('Preserve the query while separating input values.')).toBeVisible()
  session.user = { id: 'user-2', github_username: 'other' }
  await page.reload()
  await expect(page.getByText('Generate fixes to inspect their code changes and verification results.')).toBeVisible()
  await expect(page.getByText('Preserve the query while separating input values.')).toHaveCount(0)
  await expect(page.getByText('query(sql, [input])')).toHaveCount(0)
  expect(errors).toEqual([])
})
