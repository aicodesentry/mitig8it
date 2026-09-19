// Abstention fixture: the checks exist so the verification profile is complete, but the
// query adapter's placeholder syntax is undocumented, so no candidate should reach them.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "x' OR '1'='1";

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  let observed = '';
  const db = { execute: (statement) => { observed = statement; return []; } };
  loadLocal().runUnknownAdapter(db, ATTACK);
  if (observed.includes(ATTACK)) {
    process.stderr.write('vulnerability present: untrusted input is interpolated into the statement\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  let observed = '';
  const db = { execute: (statement) => { observed = statement; return []; } };
  loadLocal().runUnknownAdapter(db, 'person@example.com');
  assert.match(observed, /from users/i);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('unsupported invocation\n'); process.exit(64); }
