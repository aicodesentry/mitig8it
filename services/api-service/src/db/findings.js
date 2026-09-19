const { pool, transaction } = require('../config/database');

async function listByPullRequest(pullRequestId, userId, { status = 'open', minConfidence = 0 }) {
  await restoreExpiredSuppressions(null, userId);
  const result = await pool.query(
    `SELECT f.*
     FROM findings f
     JOIN pull_requests pr ON pr.id = f.pull_request_id
     JOIN repositories r ON r.id = pr.repository_id
     JOIN repository_access ra ON ra.repository_id = r.id
     WHERE pr.id = $1
       AND ra.user_id = $2
       AND ($3::text = 'all' OR f.status = $3)
       AND f.confidence >= $4::numeric
     ORDER BY
       CASE f.severity
         WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4
       END,
       f.confidence DESC,
       f.created_at DESC`,
    [pullRequestId, userId, status, Number(minConfidence)]
  );
  return result.rows;
}

// The pull request the findings belong to, scoped by the same repository access the
// findings query uses. The client needs the exact revision the findings describe.
async function getPullRequestForUser(pullRequestId, userId) {
  const result = await pool.query(
    `SELECT pr.id, pr.pr_number, pr.head_sha, pr.base_sha
       FROM pull_requests pr
       JOIN repository_access ra ON ra.repository_id = pr.repository_id
      WHERE pr.id = $1 AND ra.user_id = $2
      LIMIT 1`,
    [pullRequestId, userId]
  );
  return result.rows[0] || null;
}

async function listAll(userId, { repositoryId, status = 'open', severity, category }) {
  await restoreExpiredSuppressions(null, userId);
  const params = [userId];
  const clauses = ['ra.user_id = $1'];

  if (repositoryId) {
    params.push(repositoryId);
    clauses.push(`f.repository_id = $${params.length}`);
  }
  if (status !== 'all') {
    params.push(status);
    clauses.push(`f.status = $${params.length}`);
  }
  if (severity) {
    params.push(severity);
    clauses.push(`f.severity = $${params.length}`);
  }
  if (category) {
    params.push(category);
    clauses.push(`f.category = $${params.length}`);
  }

  const result = await pool.query(
     `SELECT f.*
     FROM findings f
     JOIN repositories r ON r.id = f.repository_id
     JOIN repository_access ra ON ra.repository_id = r.id
     WHERE ${clauses.join(' AND ')}
     ORDER BY f.updated_at DESC
     LIMIT 200`,
    params
  );
  return result.rows;
}

async function getById(findingId, userId) {
  await restoreExpiredSuppressions(null, userId);
  const result = await pool.query(
     `SELECT f.*, r.full_name AS repository_full_name, pr.pr_number
     FROM findings f
     JOIN repositories r ON r.id = f.repository_id
     JOIN repository_access ra ON ra.repository_id = r.id
     LEFT JOIN pull_requests pr ON pr.id = f.pull_request_id
     WHERE f.id = $1 AND ra.user_id = $2`,
    [findingId, userId]
  );
  return result.rowCount > 0 ? result.rows[0] : null;
}

async function updateStatus(findingId, userId, { status, dismissalReason }) {
  return transaction(async (client) => {
    const finding = await client.query(
      `SELECT f.id, f.repository_id
       FROM findings f
       JOIN repositories r ON r.id = f.repository_id
       JOIN repository_access ra ON ra.repository_id = r.id
       WHERE f.id = $1 AND ra.user_id = $2`,
      [findingId, userId]
    );

    if (finding.rowCount === 0) return null;

    const statusResult = await client.query(
      `UPDATE findings
       SET status = $1, dismissal_reason = $2, suppression_applied = FALSE, updated_at = NOW(), last_seen_at = NOW()
       WHERE id = $3
       RETURNING *`,
      [status, dismissalReason || null, findingId]
    );

    await client.query(
      `INSERT INTO audit_logs (user_id, repository_id, action, resource_type, resource_id, details)
       VALUES ($1, $2, 'finding.status.updated', 'finding', $3, $4)`,
      [userId, finding.rows[0].repository_id, findingId,
       JSON.stringify({ status, dismissal_reason: dismissalReason || null })]
    );

    return statusResult.rows[0];
  });
}

async function listByAnalysisRun(analysisRunId) {
  const result = await pool.query(
    `SELECT snapshot FROM analysis_run_findings
     WHERE analysis_run_id = $1
     ORDER BY
       CASE snapshot->>'severity' WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
       (snapshot->>'confidence')::numeric DESC`,
    [analysisRunId]
  );
  return result.rows.map(row => row.snapshot);
}

// --- Internal (used by orchestrator, no user-scoped auth) ---

async function findByFingerprint({ repositoryId, pullRequestId, fingerprint }) {
  const result = await pool.query(
    `SELECT id FROM findings
     WHERE repository_id = $1
       AND pull_request_id = $2
       AND fingerprint = $3`,
    [repositoryId, pullRequestId, fingerprint]
  );
  return result.rowCount > 0 ? result.rows[0] : null;
}

async function upsert(params) {
  const {
    id, runId, pullRequestId, prNumber, commitSha, repositoryId, installationId,
    fingerprint, ruleId, internalType, title, description, category, cweId, owaspCategory,
    taxonomyMappings, taxonomyVersions,
    severity, confidence, exploitability, filePath, lineStart, lineEnd,
    codeSnippet, analysisScope, evidenceDetails, evidence, exploitScenario, remediation, remediationPatch, isBaseline,
  } = params;

  if (id) {
    const updated = await pool.query(
      `UPDATE findings
       SET analysis_run_id = $1, pull_request_id = $2, pull_request_number = $3,
           commit_sha = $4, internal_type = $5, title = $6, description = $7, category = $8,
           cwe_id = $9, owasp_category = $10, taxonomy_mappings = $11, taxonomy_versions = $12,
           severity = $13, confidence = $14, exploitability = $15, file_path = $16, line_start = $17, line_end = $18,
           code_snippet = $19, evidence_details = $20, evidence = $21, exploit_scenario = $22,
           remediation = $23, remediation_patch = $24, is_baseline = $25,
           last_seen_at = NOW(), updated_at = NOW(),
           status = CASE WHEN status = 'fixed' OR suppression_applied THEN 'open' ELSE status END,
           dismissal_reason = CASE WHEN suppression_applied THEN NULL ELSE dismissal_reason END,
           suppression_applied = FALSE
       WHERE id = $26
       RETURNING *`,
      [runId, pullRequestId, prNumber, commitSha, internalType, title, description, category,
       cweId, owaspCategory, JSON.stringify(taxonomyMappings || {}), JSON.stringify(taxonomyVersions || {}),
       severity, confidence, exploitability,
       filePath, lineStart, lineEnd, codeSnippet, JSON.stringify({
         analysis_scope: analysisScope || 'pattern',
         ...(evidenceDetails || {}),
       }), evidence, exploitScenario,
       remediation, remediationPatch, isBaseline, id]
    );
    return updated.rows[0];
  }

  const inserted = await pool.query(
    `INSERT INTO findings (
       repository_id, installation_id, pull_request_number, pull_request_id,
       analysis_run_id, commit_sha, fingerprint, rule_id, internal_type, title, description,
       category, cwe_id, owasp_category, taxonomy_mappings, taxonomy_versions, severity, confidence, exploitability,
       file_path, line_start, line_end, code_snippet, evidence_details, evidence, exploit_scenario,
       remediation, remediation_patch, status, is_baseline, first_seen_at, last_seen_at
     ) VALUES (
       $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,
       'open',$29,NOW(),NOW()
     ) RETURNING *`,
    [repositoryId, installationId, prNumber, pullRequestId, runId, commitSha,
     fingerprint, ruleId, internalType, title, description, category, cweId, owaspCategory,
     JSON.stringify(taxonomyMappings || {}), JSON.stringify(taxonomyVersions || {}), severity, confidence, exploitability,
     filePath, lineStart, lineEnd, codeSnippet, JSON.stringify({
       analysis_scope: analysisScope || 'pattern',
       ...(evidenceDetails || {}),
     }), evidence, exploitScenario, remediation, remediationPatch, isBaseline]
  );
  return inserted.rows[0];
}

async function dismiss(findingId, reason) {
  await pool.query(
    `UPDATE findings SET status = 'dismissed', suppression_applied = TRUE, dismissal_reason = $1, updated_at = NOW() WHERE id = $2`,
    [reason, findingId]
  );
}

async function markFixed({ repositoryId, pullRequestId, activeFingerprints }) {
  if (activeFingerprints.length === 0) {
    await pool.query(
      `UPDATE findings SET status = 'fixed', suppression_applied = FALSE, dismissal_reason = NULL, updated_at = NOW()
       WHERE repository_id = $1 AND pull_request_id = $2 AND (status = 'open' OR suppression_applied)`,
      [repositoryId, pullRequestId]
    );
    return;
  }
  await pool.query(
    `UPDATE findings SET status = 'fixed', suppression_applied = FALSE, dismissal_reason = NULL, updated_at = NOW()
     WHERE repository_id = $1 AND pull_request_id = $2 AND (status = 'open' OR suppression_applied)
       AND fingerprint <> ALL($3::text[])`,
    [repositoryId, pullRequestId, activeFingerprints]
  );
}

async function mergeEvidenceDetails(findingId, metadata) {
  await pool.query(
    `UPDATE findings
     SET evidence_details = COALESCE(evidence_details, '{}'::jsonb) || $1::jsonb,
         updated_at = NOW()
     WHERE id = $2`,
    [JSON.stringify(metadata || {}), findingId]
  );
}

async function getActiveSuppressions(repositoryId) {
  const result = await pool.query(
    `SELECT fingerprint, reason FROM suppressions
     WHERE repository_id = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
    [repositoryId]
  );
  return result.rows;
}

async function restoreExpiredSuppressions(repositoryId = null, userId = null) {
  await pool.query(
    `UPDATE findings f SET status = 'open', suppression_applied = FALSE,
       dismissal_reason = NULL, updated_at = NOW()
     WHERE f.suppression_applied AND f.status = 'dismissed'
       AND ($1::uuid IS NULL OR f.repository_id = $1)
       AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM repository_access ra
         WHERE ra.repository_id = f.repository_id AND ra.user_id = $2))
       AND NOT EXISTS (SELECT 1 FROM suppressions s
         WHERE s.repository_id = f.repository_id AND s.fingerprint = f.fingerprint
           AND (s.expires_at IS NULL OR s.expires_at > NOW()))`,
    [repositoryId, userId]
  );
}

async function snapshotRun(runId, findingRows) {
  return transaction(async (client) => {
    // Reclaimed workers may replace partial evidence only while an attempt is
    // running. Locking the run also serializes this with terminal state changes.
    const run = await client.query('SELECT status FROM analysis_runs WHERE id = $1 FOR UPDATE', [runId]);
    if (!run.rows[0]) throw new Error('Analysis run not found while snapshotting evidence');
    if (run.rows[0].status !== 'running') return;
    await client.query('DELETE FROM analysis_run_findings WHERE analysis_run_id = $1', [runId]);
    await client.query(
      `INSERT INTO analysis_run_findings (analysis_run_id, finding_id, snapshot)
       SELECT $1, (item->>'id')::uuid, item FROM jsonb_array_elements($2::jsonb) item`,
      [runId, JSON.stringify(findingRows)]
    );
  });
}

module.exports = {
  getPullRequestForUser,
  restoreExpiredSuppressions, snapshotRun,
  listByPullRequest, listAll, getById, updateStatus, listByAnalysisRun,
  findByFingerprint, upsert, dismiss, markFixed, mergeEvidenceDetails, getActiveSuppressions,
};
