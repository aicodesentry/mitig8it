const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function verifyPassword(password, stored) {
  return hashPassword(password) === stored;
}

module.exports = { hashPassword, verifyPassword };
