const requestContext = require('./requestContext');

// Cloud Logging parses a stdout line that is a single JSON object and promotes
// `severity` and `message` to the entry itself. `level` is kept alongside for the
// local pipelines that already read it.
const SEVERITY = { info: 'INFO', warn: 'WARNING', error: 'ERROR' };

// Call sites that came from `console.error(message, error.message)` pass a string as
// the second argument. Spreading that would scatter one character per key, so anything
// that is not a plain object is recorded under a single field instead.
function toMeta(meta) {
  if (meta == null) return {};
  if (typeof meta === 'object' && !Array.isArray(meta)) return meta;
  return { detail: meta instanceof Error ? meta.message : String(meta) };
}

function log(level, message, meta) {
  const payload = {
    ts: new Date().toISOString(),
    severity: SEVERITY[level] || 'DEFAULT',
    level,
    message: typeof message === 'string' ? message : String(message),
    // The context comes first so an explicit field at the call site still wins.
    ...requestContext.current(),
    ...toMeta(meta),
  };
  console.log(JSON.stringify(payload));
}

module.exports = {
  info: (message, meta) => log('info', message, meta),
  warn: (message, meta) => log('warn', message, meta),
  error: (message, meta) => log('error', message, meta),
};
