/* global localStorage */
// Run with an isolated Playwright Page. All auth/API traffic is intercepted.
module.exports = async function runSecuritySmoke(page) {
  const base = 'http://127.0.0.1:5178';
  const errors = [];
  const assertions = [];
  let account = 'A';
  let reportFailure = false;
  let analysisMode = 'success';
  let analyzed = 0;
  page.on('pageerror', error => errors.push(error.message));
  await page.unrouteAll({ behavior: 'wait' });
  await page.route('**/*', async route => {
    const rawUrl = route.request().url();
    const url = { hostname: rawUrl.match(/^https?:\/\/([^/:]+)/)?.[1],
      pathname: rawUrl.replace(/^https?:\/\/[^/]+/, '').split('?')[0] };
    if (!['localhost', '127.0.0.1'].includes(url.hostname)) return route.abort();
    if (!url.pathname.startsWith('/api/') && !url.pathname.startsWith('/auth/')) return route.continue();
    const headers = { 'access-control-allow-origin': base, 'access-control-allow-credentials': 'true',
      'access-control-allow-headers': 'content-type,x-csrf-protection,cache-control,pragma',
      'access-control-allow-methods': 'GET,POST,OPTIONS', 'content-type': 'application/json' };
    const reply = (body, status = 200) => route.fulfill({ status, headers, body: JSON.stringify(body) });
    if (route.request().method() === 'OPTIONS') return reply({});
    const path = url.pathname;
    if (path === '/auth/me') return reply({ user: { id: account, github_username: `fixture-${account}` } });
    if (path === '/auth/logout') return reply({ success: true });
    if (path === '/api/installations') return reply({ installations: [{ id: 1, status: 'active' }] });
    if (path === '/api/repositories') return reply({ repositories: [{ id: 'repo', github_id: 1, full_name: `fixture/${account}`, is_active: true }] });
    if (path === '/api/reports/summary') return reply({ summary: { total_analyses: 1, completed: 1, failed: 0, recent_7_days: 1 } });
    if (path === '/api/reports/pr-analyses') return reportFailure ? reply({ error: 'fixture unavailable' }, 503) : reply({ analyses: [{ id: 'analysis', repository_name: `private-${account}`, pr_number: 1, status: 'completed' }], total: 1 });
    if (path === '/api/analysis/health') return reply({ status: 'ok', remaining_uses: 5 });
    if (path === '/api/analysis/history') return reply({ analyses: [], total: 0 });
    if (path === '/api/analysis/analyze') {
      analyzed += 1;
      if (route.request().headers()['x-csrf-protection'] !== '1') throw new Error('Missing CSRF header');
      if (analysisMode === 'quota') return reply({ error: 'Fixture daily quota exhausted', remaining_uses: 0 }, 429);
      if (analysisMode === 'failure') return reply({ error: 'Fixture analysis unavailable', remaining_uses: 5 }, 502);
      return reply({ analysis_id: 'fixture-scan', remaining_uses: 4, total_vulnerabilities: 1, critical_count: 1, high_count: 0, medium_count: 0, low_count: 0, vulnerabilities: [{ type: 'code_injection', severity: 'critical', line_number: 1, confidence: 1, description: 'Fixture unsafe eval', code_snippet: 'eval(input())', recommendation: 'Use safe parsing' }] });
    }
    return reply({ error: `Unexpected fixture request: ${path}` }, 404);
  });
  await page.goto(base + '/dashboard/reports');
  await page.getByText('private-A', { exact: true }).waitFor();
  assertions.push('Account A report rendered');
  await page.getByRole('button', { name: /sign out|logout|log out/i }).click();
  await page.waitForURL(base + '/');
  const remaining = await page.evaluate(() => Object.keys(localStorage).filter(key => key.startsWith('reports_cache_')));
  if (remaining.length) throw new Error('Private report cache survived logout');
  account = 'B'; reportFailure = true;
  await page.goto(base + '/dashboard/reports');
  await page.getByText('Failed to load reports. Please try again.').waitFor();
  if (await page.getByText('private-A', { exact: true }).count()) throw new Error('Account A report leaked');
  assertions.push('Account B failed refresh reveals no account A metadata; logout cleared report caches');
  await page.screenshot({ path: '/private/tmp/mitig8it-browser-account-isolation.png', fullPage: true });
  await page.goto(base + '/dashboard/analysis');
  await page.getByText('Service Online', { exact: true }).waitFor();
  await page.getByPlaceholder('Paste your code here...').fill('eval(input())');
  await page.getByRole('button', { name: 'Analyze Code', exact: true }).click();
  await page.getByText('Fixture unsafe eval', { exact: false }).waitFor();
  assertions.push('Authenticated CSRF-protected playground displays vulnerability');
  await page.screenshot({ path: '/private/tmp/mitig8it-browser-playground.png', fullPage: true });
  analysisMode = 'quota';
  await page.getByRole('button', { name: 'Analyze Code', exact: true }).click();
  await page.getByText('Fixture daily quota exhausted', { exact: true }).waitFor();
  if (!await page.getByRole('button', { name: 'Analyze Code', exact: true }).isDisabled()) throw new Error('Quota did not disable submission');
  assertions.push('429 quota response shown and submission disabled');
  analysisMode = 'failure';
  await page.reload();
  await page.getByText('Service Online', { exact: true }).waitFor();
  await page.getByPlaceholder('Paste your code here...').fill('eval(input())');
  await page.getByRole('button', { name: 'Analyze Code', exact: true }).click();
  await page.getByText('Fixture analysis unavailable', { exact: true }).waitFor();
  if (await page.getByText('No Issues Detected!', { exact: true }).count()) throw new Error('Failure rendered as clean result');
  assertions.push('502 analysis failure shown without clean result');
  if (errors.length) throw new Error(`Browser runtime errors: ${errors.join('; ')}`);
  await page.unrouteAll({ behavior: 'wait' });
  return { assertions, analyzed, runtimeErrors: errors, screenshots: ['/private/tmp/mitig8it-browser-account-isolation.png', '/private/tmp/mitig8it-browser-playground.png'] };
};
