// The deadline on every HTTP call this service makes to GitHub. Without one a hung
// connection holds the operation until the caller's gRPC deadline expires, and the work
// keeps running after the caller has given up on it.
const GITHUB_TIMEOUT_MS = 25000;

module.exports = { GITHUB_TIMEOUT_MS };
