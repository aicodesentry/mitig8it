const express = require('express');
const { createHash, randomUUID } = require('crypto');
const { pool, transaction } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { callAnalysisTier } = require('../services/prAnalysisOrchestrator');
const { normalizeFinding } = require('../services/findingUtils');
const logger = require('../utils/logger');

const router = express.Router();
const DAILY_LIMIT = 5;
const EXTENSIONS = Object.freeze({ python: 'py', javascript: 'js', typescript: 'ts', java: 'java',
  go: 'go', ruby: 'rb', php: 'php', csharp: 'cs', c: 'c', cpp: 'cpp', rust: 'rs', kotlin: 'kt', swift: 'swift' });
const quotaSql = `SELECT COUNT(*)::int AS count FROM playground_analyses
  WHERE user_id = $1
    AND created_at >= (date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
    AND (status = 'completed' OR (status = 'processing' AND created_at > NOW() - INTERVAL '10 minutes'))`;

function quota(count) {
  const tomorrow = new Date();
  tomorrow.setUTCHours(24, 0, 0, 0);
  return { remaining_uses: Math.max(0, DAILY_LIMIT - count), resets_at: tomorrow.toISOString() };
}

router.use(authenticateToken);
router.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

router.get('/health', async (req, res) => {
  try {
    const health = await callAnalysisTier('/analyze/pr/tier1', {
      repository_full_name: 'playground/health', pull_request_number: 0, commit_sha: '0'.repeat(40), files: [],
    }, 10000);
    if (!Array.isArray(health.findings)) throw new Error('Incomplete analysis response');
    const usage = await pool.query(quotaSql, [req.user.user_id]);
    res.json({ status: 'ok', service: 'analysis-service', ...quota(Number(usage.rows[0].count)) });
  } catch (_error) {
    res.status(503).json({ status: 'unavailable', error: 'Analysis service is unavailable' });
  }
});

router.get('/history', async (req, res) => {
  const limit = Math.max(1, Math.min(20, Number.parseInt(req.query.limit, 10) || 10));
  const result = await pool.query(
    `SELECT id AS analysis_id, language, created_at AS timestamp,
       (result->>'total_vulnerabilities')::int AS total_vulnerabilities,
       jsonb_build_object('critical', result->'critical_count', 'high', result->'high_count',
         'medium', result->'medium_count', 'low', result->'low_count') AS severity_counts
     FROM playground_analyses WHERE user_id = $1 AND status = 'completed'
     ORDER BY created_at DESC LIMIT $2`, [req.user.user_id, limit]
  );
  res.json({ analyses: result.rows, total: result.rows.length });
});

router.post('/analyze', async (req, res) => {
  const { code, language = 'python' } = req.body || {};
  if (typeof code !== 'string' || !code.trim() || Buffer.byteLength(code, 'utf8') > 100000
      || !Object.hasOwn(EXTENSIONS, language)) {
    return res.status(400).json({ error: 'Provide nonempty code up to 100 KB and a supported language' });
  }

  const runId = randomUUID();
  const used = await transaction(async client => {
    // Serialize reservations across API instances without holding a DB connection during scanning.
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`playground:${req.user.user_id}`]);
    const usage = await client.query(quotaSql, [req.user.user_id]);
    const count = Number(usage.rows[0].count);
    if (count >= DAILY_LIMIT) return null;
    await client.query(`INSERT INTO playground_analyses (id, user_id, language, status)
      VALUES ($1, $2, $3, 'processing')`, [runId, req.user.user_id, language]);
    return count + 1;
  });
  if (used === null) {
    return res.status(429).json({ error: 'Daily analysis limit reached; resets at midnight UTC',
      code: 'DAILY_LIMIT', ...quota(DAILY_LIMIT) });
  }

  try {
    const path = `playground.${EXTENSIONS[language]}`;
    const source = code.replace(/\r\n/g, '\n');
    const lines = source.split('\n');
    const patch = `@@ -0,0 +1,${lines.length} @@\n${lines.map(line => `+${line}`).join('\n')}`;
    const payload = { repository_full_name: 'playground/code', pull_request_number: 0,
      commit_sha: createHash('sha1').update(source).digest('hex'),
      files: [{ path, content: source, patch, status: 'added', additions: lines.length, deletions: 0,
        reviewable_line_spans: [{ start: 1, end: lines.length }] }] };
    const tier1 = await callAnalysisTier('/analyze/pr/tier1', payload, 30000);
    const tier2 = await callAnalysisTier('/analyze/pr/tier2', payload, 120000);
    if (!Array.isArray(tier1.findings) || !Array.isArray(tier2.findings)) {
      throw new Error('Incomplete analysis response');
    }
    // The playground runs deterministic and AST checks; it does not publish GitHub feedback.
    const findings = [...new Map([...tier1.findings, ...tier2.findings].map(raw => {
      const finding = normalizeFinding(raw);
      return [finding.fingerprint, finding];
    })).values()];
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    const vulnerabilities = findings.map(finding => {
      const severity = Object.hasOwn(counts, finding.severity) ? finding.severity : 'low';
      counts[severity] += 1;
      return { type: finding.category || finding.internal_type, severity,
        line_number: finding.line_start, confidence: finding.confidence,
        description: finding.description || finding.title, code_snippet: finding.code_snippet,
        recommendation: finding.remediation };
    });
    const result = { analysis_id: runId, timestamp: new Date().toISOString(), language, status: 'completed',
      vulnerabilities, total_vulnerabilities: vulnerabilities.length,
      critical_count: counts.critical, high_count: counts.high, medium_count: counts.medium, low_count: counts.low,
      style_issues: [], total_style_issues: 0, style_categories: {}, ...quota(used) };
    await pool.query(`UPDATE playground_analyses SET status = 'completed', result = $2::jsonb
      WHERE id = $1 AND user_id = $3`, [runId, JSON.stringify(result), req.user.user_id]);
    const usage = await pool.query(quotaSql, [req.user.user_id]);
    return res.json({ ...result, ...quota(Number(usage.rows[0].count)) });
  } catch (error) {
    await pool.query("UPDATE playground_analyses SET status = 'failed' WHERE id = $1 AND user_id = $2", [runId, req.user.user_id]);
    logger.warn('Playground analysis failed', { runId, error: error.message });
    const usage = await pool.query(quotaSql, [req.user.user_id]);
    return res.status(502).json({ error: 'Analysis could not complete. Please try again.', ...quota(Number(usage.rows[0].count)) });
  }
});

module.exports = router;
