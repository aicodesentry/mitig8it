const client = require('prom-client');

// Two registries are in play: this one holds the process and HTTP metrics, and
// prom-client's default registry holds the product counters that the service modules
// declare. A scrape must show both, so every reader goes through `renderMetrics`.
const metricsRegister = new client.Registry();
client.collectDefaultMetrics({ register: metricsRegister });

const httpDuration = new client.Histogram({
  name: 'codesentry_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5],
  registers: [metricsRegister],
});

// A prom-client metric exists only once its module has been required, so a counter
// that has not been touched yet is simply absent from the scrape. An alert cannot
// tell that apart from a service that stopped reporting, so the product metric
// modules are loaded here: every series is present, at zero, from the first scrape.
require('../services/analysisMetrics');
require('../services/remediationMetrics');

const contentType = metricsRegister.contentType;

async function renderMetrics() {
  return client.Registry.merge([metricsRegister, client.register]).metrics();
}

module.exports = { metricsRegister, httpDuration, renderMetrics, contentType };
