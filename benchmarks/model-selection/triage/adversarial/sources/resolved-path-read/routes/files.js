const fs = require('fs');
const path = require('path');
const express = require('express');

const router = express.Router();
const BASE_DIR = path.resolve(__dirname, '..', 'public', 'downloads');

router.get('/downloads/:name', (req, res) => {
  // basename drops every directory part, so the read stays inside BASE_DIR.
  fs.readFile(path.join(BASE_DIR, path.basename(req.params.name)), (err, data) => {
    if (err) return res.status(404).end();
    res.type('application/octet-stream').send(data);
  });
});

module.exports = router;
