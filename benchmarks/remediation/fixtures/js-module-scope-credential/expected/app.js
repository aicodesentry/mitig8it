// The webhook signer is built when this module is required, so the secret is read at import
// time and there is no function a test could call instead.
const crypto = require('node:crypto');

const signingSecret = process.env.SIGNING_SECRET;
const algorithm = 'sha256';

function sign(payload) {
  return crypto.createHmac(algorithm, signingSecret).update(payload).digest('hex');
}

module.exports = { sign, signingSecret };
