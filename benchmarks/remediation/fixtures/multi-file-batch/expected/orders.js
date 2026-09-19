const { normalizeEmail } = require('./customers');

function buildOrderLookup(email) {
  return { text: 'SELECT id, total FROM orders WHERE email = $1', values: [normalizeEmail(email)] };
}

module.exports = { buildOrderLookup };
