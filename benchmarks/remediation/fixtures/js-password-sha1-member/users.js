const crypto = require('node:crypto');

const users = new Map();

function digestPassword(password) {
  const digest = crypto.createHash('sha1').update(password, 'utf8').digest('hex');
  return digest;
}

function register(name, password) {
  users.set(name, { name, passwordHash: digestPassword(password) });
  return users.get(name);
}

function login(user, attempt) {
  if (user.passwordHash !== digestPassword(attempt)) {
    return false;
  }
  return true;
}

module.exports = { digestPassword, register, login, users };
