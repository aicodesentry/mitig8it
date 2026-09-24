// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The response object is a recorder, so no file is sent. Two routes in the one file are
// vulnerable, so repairing only one of them leaves the exploit check failing.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = '../../../etc/passwd';
const LEGITIMATE = 'logo.png';
const BASES = { sendAsset: '/srv/assets', sendThumbnail: '/srv/assets/thumbs' };

function response() {
  const record = { sent: [], status: null };
  record.res = {
    sendFile: (target) => { record.sent.push(String(target)); return 'sent'; },
    status: (code) => { record.status = code; return { end: () => 'ended' }; },
  };
  return record;
}

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function call(module, name, value) {
  const record = response();
  const request = { params: { name: value }, query: { name: value } };
  module[name](request, record.res);
  return record;
}

function exploit() {
  const module = loadLocal();
  const escaped = [];
  for (const name of Object.keys(BASES)) {
    for (const sent of call(module, name, ATTACK).sent) {
      if (!path.resolve(sent).startsWith(`${BASES[name]}${path.sep}`)) escaped.push(sent);
    }
  }
  if (escaped.length > 0) {
    process.stderr.write(`vulnerability present: ${escaped.length} route(s) send a path outside their directory\n`);
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module = loadLocal();
  for (const name of Object.keys(BASES)) {
    const record = call(module, name, LEGITIMATE);
    assert.equal(record.status, null);
    assert.deepEqual(record.sent, [path.join(BASES[name], LEGITIMATE)]);
  }
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = require(originalPath);
  assert.deepEqual(call(original, 'sendAsset', ATTACK).sent, ['/etc/passwd']);
  assert.deepEqual(call(original, 'sendThumbnail', ATTACK).sent, ['/etc/passwd']);
  const repaired = require(repairedPath);
  for (const name of Object.keys(BASES)) {
    const blocked = call(repaired, name, ATTACK);
    assert.deepEqual(blocked.sent, []);
    assert.equal(blocked.status, 400);
    const allowed = call(repaired, name, LEGITIMATE);
    assert.deepEqual(allowed.sent, [path.join(BASES[name], LEGITIMATE)]);
  }
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
