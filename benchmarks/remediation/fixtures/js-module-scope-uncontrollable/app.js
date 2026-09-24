// The archive is named after the account the job runs as, read once when this module is
// required. There is no function to call and no input a test can set: the account comes from a
// call that happens on import, so nothing a generated proof does changes what reaches the
// command. The service refuses rather than writing a test that would pass on this code.
const { execSync } = require('child_process');
const os = require('node:os');

const account = os.userInfo().username;
const archive = execSync(`tar -czf /backup/${account}.tgz /srv/${account}`).toString();

module.exports = { archive, account };
