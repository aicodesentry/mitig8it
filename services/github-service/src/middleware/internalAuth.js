const crypto = require('crypto');

// Every route that acts on behalf of the control plane requires the shared internal
// secret. The comparison is constant time so response latency cannot leak how much of
// the secret a caller has guessed, and an unconfigured secret fails closed.
function ensureInternalAuth(req, res, next) {
  const expected = process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  if (!expected) {
    return res.status(500).json({ error: 'Internal secret is not configured' });
  }
  const provided = req.headers['x-internal-secret'] || '';
  const expectedBuf = Buffer.from(expected);
  const providedBuf = Buffer.from(provided);
  if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

module.exports = { ensureInternalAuth };
