const express = require('express');
const { pool } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const findingsDb = require('../db/findings');

const router = express.Router();

router.get('/suppressions', authenticateToken, async (req, res) => {
  const { repository_id } = req.query;
  const params = [req.user.user_id];
  const clauses = ['ra.user_id = $1'];

  if (repository_id) {
    params.push(repository_id);
    clauses.push(`s.repository_id = $${params.length}`);
  }

  const result = await pool.query(
    `SELECT s.*, f.title, f.category, f.severity
     FROM suppressions s
     JOIN repositories r ON r.id = s.repository_id
     JOIN repository_access ra ON ra.repository_id = r.id
     LEFT JOIN findings f ON f.id = s.finding_id AND f.repository_id = s.repository_id
     WHERE ${clauses.join(' AND ')}
     ORDER BY s.created_at DESC`,
    params
  );

  res.json({ suppressions: result.rows });
});

router.post('/suppressions', authenticateToken, async (req, res) => {
  const { finding_id, repository_id, fingerprint, reason, notes, expires_at } = req.body;
  if ((!finding_id && !fingerprint) || !repository_id || !reason) {
    return res.status(400).json({ error: 'finding_id or fingerprint, repository_id, and reason are required' });
  }

  const repo = await pool.query(
    `SELECT r.id
     FROM repositories r
     JOIN repository_access ra ON ra.repository_id = r.id
     WHERE r.id = $1 AND ra.user_id = $2`,
    [repository_id, req.user.user_id]
  );

  if (repo.rowCount === 0) {
    return res.status(404).json({ error: 'Repository not found' });
  }

  let resolvedFindingId = finding_id || null;
  let resolvedFingerprint = fingerprint || null;

  if (resolvedFindingId) {
    const finding = await pool.query(
      'SELECT fingerprint FROM findings WHERE id = $1 AND repository_id = $2',
      [resolvedFindingId, repository_id]
    );
    if (finding.rowCount === 0) {
      return res.status(404).json({ error: 'Finding not found' });
    }
    if (resolvedFingerprint && resolvedFingerprint !== finding.rows[0]?.fingerprint) {
      return res.status(400).json({ error: 'Fingerprint does not match finding' });
    }
    resolvedFingerprint = finding.rows[0]?.fingerprint;
  }

  if (!resolvedFingerprint) {
    return res.status(400).json({ error: 'Fingerprint could not be resolved' });
  }

  const suppression = await pool.query(
    `INSERT INTO suppressions (finding_id, repository_id, fingerprint, reason, notes, suppressed_by, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [
      resolvedFindingId,
      repository_id,
      resolvedFingerprint,
      reason,
      notes || null,
      req.user.user_id,
      expires_at || null,
    ]
  );

  await pool.query(
    `INSERT INTO audit_logs (user_id, repository_id, action, resource_type, resource_id, details)
     VALUES ($1, $2, 'suppression.created', 'suppression', $3, $4)`,
    [
      req.user.user_id,
      repository_id,
      suppression.rows[0].id,
      JSON.stringify({ reason, fingerprint: resolvedFingerprint, notes: notes || null }),
    ]
  );

  res.status(201).json({ suppression: suppression.rows[0] });
});

router.delete('/suppressions/:id', authenticateToken, async (req, res) => {
  const suppression = await pool.query(
    `DELETE FROM suppressions s
     USING repositories r, repository_access ra
     WHERE s.id = $1
       AND s.repository_id = r.id
       AND ra.repository_id = r.id
       AND ra.user_id = $2
     RETURNING s.*`,
    [req.params.id, req.user.user_id]
  );

  if (suppression.rowCount === 0) {
    return res.status(404).json({ error: 'Suppression not found' });
  }

  await findingsDb.restoreExpiredSuppressions(suppression.rows[0].repository_id);

  await pool.query(
    `INSERT INTO audit_logs (user_id, repository_id, action, resource_type, resource_id, details)
     VALUES ($1, $2, 'suppression.deleted', 'suppression', $3, $4)`,
    [
      req.user.user_id,
      suppression.rows[0].repository_id,
      suppression.rows[0].id,
      JSON.stringify({ fingerprint: suppression.rows[0].fingerprint }),
    ]
  );

  res.json({ success: true });
});

module.exports = router;
