const express = require('express');

const router = express.Router();

router.get('/preferences/:theme', (req, res) => {
  res.cookie('theme', req.params.theme, {
    maxAge: 30 * 24 * 3600 * 1000,
    secure: true,
    httpOnly: true,
    sameSite: 'lax'
  });
  res.send('saved');
});

module.exports = router;
