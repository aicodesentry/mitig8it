const crypto = require('node:crypto');

const users = new Map();

function digestPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return ['scrypt', salt, crypto.scryptSync(password, salt, 32).toString('hex')].join('$');
}

function verifyPasswordHash(password, stored) {
  const [scheme, salt, expected] = String(stored).split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = crypto.scryptSync(password, salt, 32);
  const wanted = Buffer.from(expected, 'hex');
  return wanted.length === actual.length && crypto.timingSafeEqual(actual, wanted);
}

function register(name, password) {
  users.set(name, { name, passwordHash: digestPassword(password) });
  return users.get(name);
}

function login(user, attempt) {
  if (!verifyPasswordHash(attempt, user.passwordHash)) {
    return false;
  }
  return true;
}

module.exports = { digestPassword, register, login, users };
