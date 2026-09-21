const express = require('express');
const { Pool } = require('pg');
const { execFile, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();
const REPORT_DIR = path.join(__dirname, '..', 'reports');

// Look up an order by id supplied by the caller.
router.get('/orders/:id', async (req, res) => {
  const result = await pool.query("SELECT id, status, total FROM orders WHERE id = '" + req.params.id + "'");
  res.json(result.rows);
});

// Search orders by customer email.
router.get('/orders', async (req, res) => {
  const sql = `SELECT id, status FROM orders WHERE customer_email LIKE '%${req.query.email}%' ORDER BY created_at DESC`;
  const result = await pool.query(sql);
  res.json(result.rows);
});

// Regenerate a PDF invoice with the external renderer.
router.post('/orders/:id/invoice', (req, res) => {
  exec(`invoice-render --order ${req.params.id} --format ${req.body.format}`, (error, stdout) => {
    if (error) return res.status(500).json({ error: 'render failed' });
    res.type('text/plain').send(stdout);
  });
});

// Download a previously generated report.
router.get('/reports/download', (req, res) => {
  const target = path.join(REPORT_DIR, req.query.name);
  fs.readFile(target, (error, data) => {
    if (error) return res.status(404).end();
    res.type('application/pdf').send(data);
  });
});

// Archive a report using tar so the archive keeps file metadata.
router.post('/reports/archive', (req, res) => {
  execFile('tar', ['-czf', path.join(REPORT_DIR, req.body.archive), '-C', REPORT_DIR, req.body.name], (error) => {
    if (error) return res.status(500).json({ error: 'archive failed' });
    res.status(204).end();
  });
});

module.exports = router;
