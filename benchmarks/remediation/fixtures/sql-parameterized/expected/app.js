function buildUserLookup(email) {
  return { text: 'SELECT id, email FROM users WHERE email = $1', values: [email] };
}

module.exports = { buildUserLookup };
