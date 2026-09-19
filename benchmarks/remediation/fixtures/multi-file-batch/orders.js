const { normalizeEmail } = require('./customers');

function buildOrderLookup(email) {
  return { text: `SELECT id, total FROM orders WHERE email = '${normalizeEmail(email)}'`, values: [] };
}

module.exports = { buildOrderLookup };
