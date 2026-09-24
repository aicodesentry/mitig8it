// Abstention fixture: the credential really is hardcoded, but the Node toolchain records no
// environment reads, so no regression test can prove a hardcoded_credential repair for a
// JavaScript source. The engine skips the finding rather than hand the agent an unprovable
// task, and no candidate should reach these checks.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const LITERAL = 'sk-live-3f9ab2c1d4e5f6a7';

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function exploit() {
  const source = fs.readFileSync(localPath(), 'utf8');
  if (source.includes(LITERAL)) {
    process.stderr.write('vulnerability present: the API key is a literal in the source\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const headers = require(localPath()).vendorHeaders('req-1');
  assert.match(headers.Authorization, /^Bearer /);
  assert.equal(headers['X-Request-Id'], 'req-1');
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
