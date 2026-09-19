import { test, expect } from '@playwright/test'

const pr = '11111111-1111-4111-8111-111111111111'
const headSha = 'a'.repeat(40)

const finding = { id: 'finding', title: 'SQL injection', category: 'injection', severity: 'high', confidence: 0.99,
  code_snippet: 'query(input)', remediation: 'Use query parameters.', remediation_patch: 'query(sql, [input])' }

const previewBody = {
  job_id: 'job', head_sha: headSha, base_sha: 'b'.repeat(40), manifest_digest: 'd'.repeat(64), verified_tree_oid: 'e'.repeat(40),
  candidates: [{ id: 'candidate', finding_ids: ['finding'], rationale: 'Preserve the query while separating input values.',
    verification_level: 'sandbox_verified',
    evidence: { status: 'passed', evidence_digest: 'a'.repeat(64), verified_tree_oid: 'e'.repeat(40) },
    changes: [{ path: 'src/query.js', original: 'query(input)', replacement: 'query(sql, [input])', new_sha256: 'c'.repeat(64) }] }],
  verification: { outcome: 'passed', evidence_digest: 'a'.repeat(64), coverage_gaps: ['Only the changed files were scanned.'] },
  skipped: [{ finding_id: 'second', reason: 'Business behavior needs manual review.' }],
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
        capabilities: { generate: true, apply: true, merge: true }, job: { id: 'job', state: counters.applied ? 'completed' : 'ready' },
        action: counters.applied ? { id: 'action', state: 'checking', reason: null, rejection_reason: null, commit_sha: 'c'.repeat(40) } : null,
        merge_intent: counters.applied
          ? { id: 'intent', action_id: 'action', state: counters.cancelled ? 'cancelled' : 'waiting_for_checks',
            blockers: [], merge_attempts: 0, expires_at: '2099-01-01T00:00:00.000Z', applied_sha: 'c'.repeat(40),
            observed_merge_sha: null, last_evaluated_at: null, merge_method: 'squash',
            cancellation_reason: counters.cancelled ? 'requested_by_actor' : null, latest_policy_checks: {} }
          : null,
      })
    }
    if (path === '/api/remediations/job/preview') return respond(previewBody)
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

test('reviewed batch survives reload, applies once, and exposes merge cancellation', async ({ page }) => {
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  const { counters } = installFixture(page)
  await page.goto(`/dashboard/pull-requests/${pr}/findings`)
  await expect(page.getByText('Preserve the query while separating input values.')).toBeVisible()
  await expect(page.getByText('1 verified fix; 1 finding needs manual work')).toBeVisible()
  await page.getByRole('button', { name: 'Yes' }).first().click()
  await expect(page.getByText('Thanks. Your feedback was recorded.')).toBeVisible()
  await page.getByRole('button', { name: 'Apply 1 fixes and merge when ready' }).click()
  await expect(page.getByText('Application: checking')).toBeVisible()
  expect(counters.writes).toBe(1)
  await page.reload()
  await expect(page.getByText('Application: checking')).toBeVisible()
  await expect(page.getByText('Merge: waiting for checks', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Cancel scheduled merge' }).click()
  await expect(page.getByText('Merge: cancelled', { exact: true })).toBeVisible()
  await expect(page.getByText('Cancellation reason: requested by actor')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Cancel scheduled merge' })).toHaveCount(0)
  expect(errors).toEqual([])
  expect(counters.writes).toBe(1)
})

test('a new commit on the pull request blocks the reviewed batch until it is regenerated', async ({ page }) => {
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  const { counters } = installFixture(page, { livePrHead: 'f'.repeat(40) })
  await page.goto(`/dashboard/pull-requests/${pr}/findings`)
  await expect(page.getByText('The pull request has new commits since these fixes were generated; regenerate to continue.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Apply 1 verified fixes' })).toBeDisabled()
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
