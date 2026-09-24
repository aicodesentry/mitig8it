const { AsyncLocalStorage } = require('async_hooks');

// One identifier set travels with the work, not with the call signature. Every log
// line picks it up from here, so a correlated log is the default rather than something
// a call site has to remember to pass down through six layers of helpers.
const storage = new AsyncLocalStorage();

// The full set of correlation fields and the wire header each one travels on. HTTP
// headers and gRPC metadata keys are the same strings: gRPC metadata keys are
// lowercase ASCII, which these already are.
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

// Runs `fn` with the given identifiers added to whatever is already in scope. Fields
// already known are never overwritten by an empty value.
function runWith(fields, fn) {
  return storage.run({ ...current(), ...clean(fields) }, fn);
}

// Adds identifiers to the context already in scope, for the case where the value is
// only learned partway through the work, such as a run id assigned after the claim.
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

// Outbound headers for an HTTP call to a peer service. Only fields that are actually
// known are sent, so an empty header never claims a correlation that does not exist.
function toHeaders(extra = {}) {
  const fields = { ...current(), ...clean(extra) };
  const headers = {};
  for (const [field, header] of Object.entries(FIELD_HEADERS)) {
    if (fields[field]) headers[header] = fields[field];
  }
  return headers;
}

// gRPC metadata carrying the same fields. `Metadata` is passed in rather than required
// so this module stays usable in processes that do not speak gRPC.
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

// Express middleware: adopts whatever the caller sent and holds it for the request.
function requestContextMiddleware(req, res, next) {
  const fields = fromHeaders(req.headers || {});
  if (req.correlationId) fields.correlation_id = req.correlationId;
  runWith(fields, () => next());
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
