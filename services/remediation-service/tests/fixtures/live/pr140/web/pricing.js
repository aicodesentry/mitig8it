const express = require('express');
const db = require('./db');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

const router = express.Router();

router.get('/quote', (req, res) => {
  const sku = req.query.sku;
  db.query("SELECT price FROM pricing WHERE sku = '" + sku + "'", (err, rows) => {
    if (err) return res.status(500).end();
    res.json(rows);
  });
});

router.get('/rule', (req, res) => {
  const formula = req.query.formula;
  const result = eval(formula);
  res.json({ result });
});

router.get('/label', (req, res) => {
  exec('lpr -P labels ' + req.query.file, (err) => {
    res.json({ queued: !err });
  });
});

router.get('/download', (req, res) => {
  const file = path.join('/srv/pricing', req.query.name);
  res.send(fs.readFileSync(file));
});

module.exports = router;
