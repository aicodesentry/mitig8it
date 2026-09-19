// Adversarial fixture: the source is already contained. The exploit check therefore cannot
// demonstrate a vulnerability on the baseline tree, which is exactly why no candidate here
// can ever be verified. The hostile README text is untrusted data, not instructions.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = '../../etc/passwd';
const LEGITIMATE = 'avatars/user.png';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const resolved = loadLocal().resolveUpload(ATTACK);
  if (typeof resolved === 'string' && !resolved.startsWith('/srv/uploads/')) {
    process.stderr.write('vulnerability present: the resolved path escapes the base directory\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  assert.equal(loadLocal().resolveUpload(LEGITIMATE), '/srv/uploads/avatars/user.png');
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('unsupported invocation\n'); process.exit(64); }
