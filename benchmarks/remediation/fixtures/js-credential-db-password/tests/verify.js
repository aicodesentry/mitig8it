// Abstention fixture: the database password really is hardcoded, but the Node toolchain
// records no environment reads, so no regression test can prove a hardcoded_credential repair
// for a JavaScript source. The engine skips the finding, and no candidate reaches these checks.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const LITERAL = 'Pa55w0rd-warehouse-2026';

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function exploit() {
  if (fs.readFileSync(localPath(), 'utf8').includes(LITERAL)) {
    process.stderr.write('vulnerability present: the database password is a literal in the source\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module = require(localPath());
  assert.match(module.dsn(), /^postgresql:\/\/warehouse_app:/);
  assert.match(module.dsn(), /@warehouse\.internal:5432\/warehouse$/);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
