// The webhook signer is built when this module is required, so the secret is read at import
// time and there is no function a test could call instead.
const crypto = require('node:crypto');

const signingSecret = 'whsec_2f8c11ad93be40f7';
const algorithm = 'sha256';

function sign(payload) {
  return crypto.createHmac(algorithm, signingSecret).update(payload).digest('hex');
}

module.exports = { sign, signingSecret };
