// Abstention fixture: the cookie is cross-site on purpose (SameSite=None), so no flag rewrite
// can be chosen without a design decision. The engine skips the finding as
// cookie_samesite_none_is_deliberate, and no candidate should reach these checks.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function exploit() {
  if (/secure:\s*false/.test(fs.readFileSync(localPath(), 'utf8'))) {
    process.stderr.write('vulnerability present: the cookie is sent over plain HTTP\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  assert.match(fs.readFileSync(localPath(), 'utf8'), /sameSite: 'none'/);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
