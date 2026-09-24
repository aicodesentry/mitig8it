const requestContext = require('./requestContext');

// Cloud Logging parses a stdout line that is a single JSON object and promotes
// `severity` and `message` to the entry itself. `level` is kept alongside for the
// local pipelines and log parsers that already read it.
const SEVERITY = { info: 'INFO', warn: 'WARNING', error: 'ERROR' };

function log(level, message, meta = {}) {
  const payload = {
    ts: new Date().toISOString(),
    severity: SEVERITY[level] || 'DEFAULT',
    level,
    message,
    // The context comes first so an explicit field at the call site still wins: a
    // helper logging about another run's id must be able to say so.
    ...requestContext.current(),
    ...meta,
  };
  // Keep logs machine-parsable for ingestion by log pipelines.
  console.log(JSON.stringify(payload));
}

module.exports = {
  info: (message, meta) => log('info', message, meta),
  warn: (message, meta) => log('warn', message, meta),
  error: (message, meta) => log('error', message, meta),
};
