const express = require('express');
const crypto = require('crypto');

const app = express();

app.post('/login', (req, res) => {
  const token = crypto.randomBytes(16).toString('hex');
  res.cookie('auth_token', token, { httpOnly: false, maxAge: 900000 });
  res.json({ ok: true, user: req.body.user });
});

module.exports = app;
