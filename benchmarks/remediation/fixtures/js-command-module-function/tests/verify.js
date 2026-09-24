// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const ATTACK = 'page.html; touch /tmp/owned';
const LEGITIMATE = 'page.html';

// Stands in for child_process so the test sees how the command was started without starting it.
// `shell` is the command line a shell would interpret: a string for exec, null for an argv call.
function withFakeChildProcess(modulePath, run) {
  const calls = [];
  const fake = {
    exec: (command, ...rest) => (calls.push({ shell: String(command), args: null }), rest.find((v) => typeof v === 'function')),
    execFile: (file, ...rest) => {
      const args = Array.isArray(rest[0]) ? rest[0] : [];
      calls.push({ shell: null, command: String(file), args: args.map(String) });
      return rest.find((v) => typeof v === 'function');
    },
  };
  fake.spawn = fake.execFile;
  const original = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'child_process' || request === 'node:child_process') return fake;
    return original.call(this, request, parent, isMain);
  };
  try {
    delete require.cache[require.resolve(modulePath)];
    run(require(modulePath));
  } finally {
    Module._load = original;
  }
  return calls[0];
}

const local = () => path.resolve(__dirname, '..', 'app.js');
const render = (target, name) => withFakeChildProcess(target, (m) => m.renderReport(name, () => {}));

function exploit() {
  const call = render(local(), ATTACK);
  if (typeof call.shell === 'string') {
    process.stderr.write('vulnerability present: the file name reaches a shell command string\n');
    process.exit(1);
  }
  assert.ok(call.args.includes(ATTACK), 'the payload must survive as its own argument');
  process.exit(0);
}

function behavior() {
  const call = render(local(), LEGITIMATE);
  const rendered = JSON.stringify(call);
  assert.ok(rendered.includes('wkhtmltopdf'));
  assert.ok(rendered.includes(LEGITIMATE));
  assert.ok(rendered.includes('report.pdf'));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = render(originalPath, ATTACK);
  const repaired = render(repairedPath, ATTACK);
  const legitimate = render(repairedPath, LEGITIMATE);
  assert.match(original.shell, /touch \/tmp\/owned/);
  assert.equal(repaired.shell, null, 'the repair must not build a shell command string');
  assert.equal(repaired.command, 'wkhtmltopdf');
  assert.ok(repaired.args.includes(ATTACK));
  assert.ok(legitimate.args.includes(LEGITIMATE));
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
