const crypto = require('crypto');

const hashPassword = (password) => crypto.createHash('md5').update(password).digest('base64');

function checkPassword(password, stored) {
  const matches = stored === hashPassword(password);
  return matches;
}

module.exports = { hashPassword, checkPassword };
