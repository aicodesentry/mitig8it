const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

async function findUser(db, email, password) {
  const result = await db.query('SELECT id, email FROM users WHERE email = $1 AND password_hash = $2', [email, hashPassword(password)]);
  return result.rows[0];
}

module.exports = { hashPassword, findUser };
