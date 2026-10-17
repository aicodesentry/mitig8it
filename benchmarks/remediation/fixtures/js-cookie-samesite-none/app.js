const express = require('express');

const app = express();

app.get('/widget', (req, res) => {
  res.cookie('widget_session', req.query.session, { secure: false, sameSite: 'none' });
  res.send('<div id="widget"></div>');
});

module.exports = app;
