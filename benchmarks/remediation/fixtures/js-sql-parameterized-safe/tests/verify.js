// Abstention fixture: the statement already binds the account number as a pg parameter, so
// the exploit check cannot demonstrate a vulnerability on the baseline tree and no candidate
// can be verified.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "1' OR '1'='1";
const LEGITIMATE = '0044821';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const result = loadLocal().buildAccountLookup(ATTACK);
  if (typeof result.text === 'string' && result.text.includes(ATTACK)) {
    process.stderr.write('vulnerability present: untrusted input is interpolated into SQL text\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const result = loadLocal().buildAccountLookup(LEGITIMATE);
  assert.match(result.text, /FROM accounts/i);
  assert.deepEqual(result.values, [LEGITIMATE]);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
