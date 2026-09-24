const express = require('express');
const { pool } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const analysisDb = require('../db/analysisRuns');
const findingsDb = require('../db/findings');
const qualityMetricsDb = require('../db/qualityMetrics');
const quality = require('../services/qualityMetrics');
const { notifyAnalysisQueued } = require('../services/prAnalysisOrchestrator');

const router = express.Router();

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// The two windows the daily roll-up is kept wide enough to answer. Anything else is
// refused rather than silently rounded to one of them.
const QUALITY_WINDOWS = new Set([7, 30]);
const QUALITY_RULE_LIMIT = 20;

router.get('/pr-analyses', authenticateToken, async (req, res) => {
  try {
    const { repository_id, status, limit = 50, offset = 0 } = req.query;

    if (repository_id) {
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(repository_id)) {
        return res.status(400).json({
          error: 'Invalid repository ID format',
          details: 'Repository ID must be a valid UUID',
        });
      }
    }

    const pagination = {
      repositoryId: repository_id,
      status,
      limit: parseInt(limit, 10),
      offset: parseInt(offset, 10),
    };

    const data = await analysisDb.listAnalyses(req.user.user_id, pagination);

    res.json({
      success: true,
      analyses: data.rows,
      total: data.total,
      limit: pagination.limit,
      offset: pagination.offset,
    });
  } catch (error) {
    console.error('Error fetching PR analyses:', error);
    res.status(500).json({ error: 'Failed to fetch PR analyses' });
  }
});

router.get('/pr-analyses/:analysisId', authenticateToken, async (req, res) => {
  try {
    const { analysisId } = req.params;

    const analysis = await analysisDb.getAnalysisById(analysisId, req.user.user_id);

    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }

    const findings = await findingsDb.listByAnalysisRun(analysisId);
    analysis.findings = findings;
    analysis.total_findings = findings.length;
    analysis.severity_counts = findings.reduce((acc, f) => {
      const s = f.severity || 'low';
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });

    res.json({ success: true, analysis });
  } catch (error) {
    console.error('Error fetching analysis details:', error);
    res.status(500).json({ error: 'Failed to fetch analysis details' });
  }
});

router.get('/summary', authenticateToken, async (req, res) => {
  try {
    const summary = await analysisDb.querySummary(req.user.user_id);

    res.json({
      success: true,
      summary: {
        total_analyses: parseInt(summary.total, 10),
        completed: parseInt(summary.completed, 10),
        failed: parseInt(summary.failed, 10),
        recent_7_days: parseInt(summary.recent, 10),
      },
    });
  } catch (error) {
    console.error('Error fetching summary:', error);
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

/**
 * The quality of the findings and of the fixes, read from the daily roll-up the
 * reconciler maintains. Nothing is computed from the raw log here: the route reads rows
 * and sums them, so a slow log can never make the dashboard slow.
 */
router.get('/quality', authenticateToken, async (req, res) => {
  try {
    const { window = '30', repository_id: repositoryId = null } = req.query;
    const days = Number.parseInt(window, 10);
    if (!QUALITY_WINDOWS.has(days)) {
      return res.status(400).json({ error: 'Invalid window', allowed: [...QUALITY_WINDOWS] });
    }
    if (repositoryId && !UUID_PATTERN.test(repositoryId)) {
      return res.status(400).json({ error: 'Invalid repository ID format' });
    }
    // A repository the caller cannot reach is refused, rather than answered with the
    // empty roll-up a scoped query would return. The two are not the same answer.
    if (repositoryId && !(await qualityMetricsDb.userCanReadRepository(req.user.user_id, repositoryId))) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    const installationIds = await qualityMetricsDb.installationIdsForUser(req.user.user_id);
    if (!installationIds.length) {
      return res.json({ success: true, window: days, repository_id: repositoryId || null,
        overall: quality.summarize([]), by_rule: [] });
    }

    const scope = { installationIds, days, repositoryId: repositoryId || null };
    const [overallRows, ruleRows] = await Promise.all([
      qualityMetricsDb.readWindow({ ...scope, byRule: false }),
      qualityMetricsDb.readWindow({ ...scope, byRule: true }),
    ]);

    const byRuleId = new Map();
    for (const row of ruleRows) {
      const key = row.rule_id;
      if (!byRuleId.has(key)) byRuleId.set(key, []);
      byRuleId.get(key).push(row);
    }
    const byRule = quality.rankRules(
      [...byRuleId.entries()].map(([ruleId, rows]) => quality.summarize(rows, { rule_id: ruleId })),
      QUALITY_RULE_LIMIT
    );

    res.json({
      success: true,
      window: days,
      repository_id: repositoryId || null,
      overall: quality.summarize(overallRows),
      by_rule: byRule,
    });
  } catch (error) {
    console.error('Error fetching quality metrics:', error);
    res.status(500).json({ error: 'Failed to fetch quality metrics' });
  }
});

router.post('/pr-analyses/:analysisId/retry', authenticateToken, async (req, res) => {
  try {
    const { analysisId } = req.params;
    const analysis = await analysisDb.getAnalysisById(analysisId, req.user.user_id);

    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }
    if (analysis.status !== 'failed') {
      return res.status(400).json({ error: 'Only failed analyses can be retried' });
    }

    const runData = await pool.query(
      `SELECT ar.*, r.full_name AS repository_full_name, r.installation_id, r.baseline_set, r.is_active
       FROM analysis_runs ar
       JOIN repositories r ON r.id = ar.repository_id
       WHERE ar.id = $1`,
      [analysisId]
    );
    const run = runData.rows[0];
    if (!run) {
      return res.status(404).json({ error: 'Analysis run not found' });
    }

    if (!run.is_active) {
      return res.status(400).json({ error: 'Reconnect the repository before retrying analysis' });
    }
    // A retry is a new attempt; preserve the failed run and its historical evidence.
    const retry = await pool.query(
      `INSERT INTO analysis_runs (repository_id, pull_request_id, pr_number, commit_sha, status, triggered_by)
       VALUES ($1, $2, $3, $4, 'pending', 'retry') RETURNING id`,
      [run.repository_id, run.pull_request_id, run.pr_number, run.commit_sha]
    );

    notifyAnalysisQueued();

    res.json({ success: true, message: 'Analysis retry triggered', analysis_run_id: retry.rows[0].id });
  } catch (error) {
    console.error('Error retrying analysis:', error);
    res.status(500).json({ error: 'Failed to retry analysis' });
  }
});

module.exports = router;
