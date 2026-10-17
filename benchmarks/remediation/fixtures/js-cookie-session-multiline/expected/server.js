const express = require('express');
const cookieSession = require('cookie-session');

const app = express();

app.use(
  cookieSession({
    name: 'session',
    keys: [process.env.COOKIE_KEY_1, process.env.COOKIE_KEY_2],
    maxAge: 24 * 60 * 60 * 1000,
    secure: true,
    httpOnly: true,
    sameSite: 'lax'
  })
);

module.exports = app;
