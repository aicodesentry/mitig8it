const express = require('express');

const router = express.Router();

router.get('/logout', (req, res) => {
  req.session = null;
  res.redirect('/login');
});

router.get('/account', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login?next=account');
  }
  return res.render('account', { userId: req.session.userId });
});

module.exports = router;
