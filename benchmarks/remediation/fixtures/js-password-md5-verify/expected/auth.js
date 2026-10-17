const crypto = require('crypto');

function hashPassword(password) {
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

function verifyPassword(password, stored) {
  return verifyPasswordHash(password, stored);
}

module.exports = { hashPassword, verifyPassword };
