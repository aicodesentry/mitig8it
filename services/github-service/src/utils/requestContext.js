const { AsyncLocalStorage } = require('async_hooks');

// The same contract the API service uses: one identifier set travels with the work,
// not with the call signature, so every log line here joins the API's lines for the
// same webhook delivery without a call site passing anything by hand.
const storage = new AsyncLocalStorage();

const FIELD_HEADERS = Object.freeze({
  delivery_id: 'x-github-delivery',
  analysis_run_id: 'x-analysis-run-id',
  job_id: 'x-job-id',
  correlation_id: 'x-correlation-id',
});

const FIELDS = Object.freeze(Object.keys(FIELD_HEADERS));

// Identifiers arrive from GitHub and from peer services. A newline in one of them
// would forge a second log line, and an unbounded one would bloat every record.
function sanitize(value) {
  if (value == null) return null;
  const text = String(value).replace(/[\r\n\u0000]/g, '').trim();
  if (!text) return null;
  return text.slice(0, 200);
}

function clean(fields = {}) {
  const result = {};
  for (const field of FIELDS) {
    const value = sanitize(fields[field]);
    if (value) result[field] = value;
  }
  return result;
}

function current() {
  return storage.getStore() || {};
}

function runWith(fields, fn) {
  return storage.run({ ...current(), ...clean(fields) }, fn);
}

function assign(fields = {}) {
  const store = storage.getStore();
  if (!store) return current();
  Object.assign(store, clean(fields));
  return store;
}

function fromHeaders(headers = {}) {
  const lookup = (name) => (typeof headers.get === 'function' ? headers.get(name) : headers[name]);
  const fields = {};
  for (const [field, header] of Object.entries(FIELD_HEADERS)) {
    fields[field] = lookup(header) || lookup(header.toUpperCase());
  }
  return clean(fields);
}

function toHeaders(extra = {}) {
  const fields = { ...current(), ...clean(extra) };
  const headers = {};
  for (const [field, header] of Object.entries(FIELD_HEADERS)) {
    if (fields[field]) headers[header] = fields[field];
  }
  return headers;
}

function toGrpcMetadata(Metadata, extra = {}) {
  const metadata = new Metadata();
  for (const [header, value] of Object.entries(toHeaders(extra))) {
    metadata.set(header, value);
  }
  return metadata;
}

function fromGrpcMetadata(metadata) {
  if (!metadata || typeof metadata.get !== 'function') return {};
  const fields = {};
  for (const [field, header] of Object.entries(FIELD_HEADERS)) {
    const values = metadata.get(header);
    fields[field] = Array.isArray(values) ? values[0] : values;
  }
  return clean(fields);
}

function requestContextMiddleware(req, _res, next) {
  runWith(fromHeaders(req.headers || {}), () => next());
}

module.exports = {
  FIELDS,
  FIELD_HEADERS,
  assign,
  current,
  fromGrpcMetadata,
  fromHeaders,
  requestContextMiddleware,
  runWith,
  sanitize,
  toGrpcMetadata,
  toHeaders,
};
