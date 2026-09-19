function buildUserLookup(email) {
  return { text: `SELECT id, email FROM users WHERE email = '${email}'`, values: [] };
}

module.exports = { buildUserLookup };
