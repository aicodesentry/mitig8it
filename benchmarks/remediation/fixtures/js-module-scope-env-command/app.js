// A release note generator. Everything here runs once, when the module is required: there is
// no function enclosing the sink, so a test can only drive it by setting the environment the
// module reads and then importing it.
const { execSync } = require('child_process');

const branch = process.env.BUILD_BRANCH;
const log = execSync(`git log --oneline ${branch}`).toString();

module.exports = { log, branch };
