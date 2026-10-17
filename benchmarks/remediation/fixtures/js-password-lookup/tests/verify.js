// Abstention fixture: the digest is used as a lookup key in a query, so no repair of the
// hashing function alone can keep logins working. The engine skips the finding as
// password_hash_used_for_lookup, and no candidate should reach these checks.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function localPath() {
  return path.resolve(__dirname, '..', 'users.js');
}

function exploit() {
  if (/createHash\('md5'\)/.test(fs.readFileSync(localPath(), 'utf8'))) {
    process.stderr.write('vulnerability present: the password is stored as an unsalted md5 digest\n');
    process.exit(1);
  }
  process.exit(0);
}

async function behavior() {
  const m = require(localPath());
  const seen = [];
  const db = { query: async (text, values) => { seen.push({ text, values }); return { rows: [{ id: 1, email: values[0] }] }; } };
  const user = await m.findUser(db, 'a@example.com', 'secret');
  assert.equal(user.email, 'a@example.com');
  assert.equal(seen.length, 1);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
