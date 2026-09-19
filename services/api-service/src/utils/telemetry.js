const { context, propagation, trace, SpanStatusCode } = require('@opentelemetry/api');
const { NodeSDK } = require('@opentelemetry/sdk-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-proto');

const attributes = new Set(['stage', 'attempt', 'outcome', 'model', 'provider', 'policy_version', 'prompt_version',
  'tool_version', 'input_tokens', 'output_tokens', 'cost_usd', 'error_category', 'http.request.method',
  'http.route', 'http.response.status_code', 'job_id', 'action_id']);
let sdk;

function safeAttributes(values = {}) {
  return Object.fromEntries(Object.entries(values).filter(([key, value]) =>
    attributes.has(key) && ['string', 'number', 'boolean'].includes(typeof value))
    .map(([key, value]) => [key, typeof value === 'string' ? value.replace(/[\r\n\x00]/g, '').slice(0, 200) : value]));
}

function startTelemetry(serviceName) {
  if (sdk || process.env.OTEL_SDK_DISABLED === 'true' || !process.env.OTEL_EXPORTER_OTLP_ENDPOINT) return;
  // Manual instrumentation intentionally avoids collecting SQL, headers, URLs or source.
  sdk = new NodeSDK({
    serviceName,
    traceExporter: new OTLPTraceExporter({ timeoutMillis: 5000 }),
  });
  sdk.start();
}

function injectTrace() {
  const carrier = {};
  propagation.inject(context.active(), carrier);
  // Baggage can contain customer information. Only propagate W3C trace identifiers.
  return Object.fromEntries(Object.entries(carrier).filter(([key]) => ['traceparent', 'tracestate'].includes(key)));
}

async function withSpan(name, values, operation, carrier = {}) {
  const parent = propagation.extract(context.active(), {
    traceparent: carrier.traceparent, tracestate: carrier.tracestate,
  });
  return context.with(parent, () => trace.getTracer('mitig8it-remediation', '1.0.0')
    .startActiveSpan(name, { attributes: safeAttributes(values) }, async span => {
      try {
        const result = await operation();
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (error) {
        // Error messages and stacks can contain source or tokens; record only classification.
        span.setAttribute('error_category', Number.isInteger(error.statusCode) ? 'http_' + error.statusCode : 'operation_failed');
        span.setStatus({ code: SpanStatusCode.ERROR });
        throw error;
      } finally { span.end(); }
    }));
}

function requestTracing(req, res, next) {
  const parent = propagation.extract(context.active(), { traceparent: req.get('traceparent'), tracestate: req.get('tracestate') });
  context.with(parent, () => trace.getTracer('mitig8it-remediation', '1.0.0').startActiveSpan('http.request', span => {
    span.setAttribute('http.request.method', req.method);
    let ended = false;
    const finish = () => {
      if (ended) return;
      ended = true;
      span.setAttributes(safeAttributes({ 'http.route': req.route?.path || 'unmatched', 'http.response.status_code': res.statusCode }));
      if (res.statusCode >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
      span.end();
    };
    res.once('finish', finish);
    res.once('close', finish);
    next();
  }));
}

async function shutdownTelemetry() {
  if (sdk) await sdk.shutdown();
  sdk = undefined;
}
module.exports = { startTelemetry, shutdownTelemetry, withSpan, injectTrace, requestTracing, safeAttributes };

