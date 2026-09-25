const http = require('http');
const { renderMetrics, contentType } = require('./utils/metricsRegistry');
const logger = require('./utils/logger');

const DEFAULT_PORT = 9091;

// The managed Prometheus sidecar runs in the same Cloud Run instance and reaches this
// service over the loopback interface. It cannot hold the internal secret that gates
// the public /metrics route, so the scrape gets its own listener bound to 127.0.0.1.
// Nothing outside the instance can open a connection to it: the ingress only ever
// forwards to the ingress container's port, and the loopback address is not routable
// from outside the network namespace. The public route stays gated exactly as it was.
function loopbackPort() {
  const parsed = Number(process.env.METRICS_LOOPBACK_PORT || DEFAULT_PORT);
  return Number.isInteger(parsed) && parsed > 0 && parsed < 65536 ? parsed : DEFAULT_PORT;
}

function createMetricsServer() {
  return http.createServer(async (req, res) => {
    // A request that arrived here from anything but the loopback interface would mean
    // the bind failed open. Refuse rather than serve, and say so once.
    const remote = req.socket.remoteAddress || '';
    if (remote !== '127.0.0.1' && remote !== '::1' && remote !== '::ffff:127.0.0.1') {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('forbidden\n');
      logger.warn('Loopback metrics listener refused a non-loopback request', { remote });
      return;
    }
    if (req.method !== 'GET' || (req.url || '').split('?')[0] !== '/metrics') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found\n');
      return;
    }
    try {
      const body = await renderMetrics();
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(body);
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('metrics render failed\n');
      logger.error('Loopback metrics render failed', { error: error.message });
    }
  });
}

// Off unless asked for, so local development and the test suite do not bind a port.
function metricsLoopbackEnabled() {
  return process.env.METRICS_LOOPBACK_ENABLED === 'true';
}

function startMetricsServer() {
  if (!metricsLoopbackEnabled()) return null;
  const port = loopbackPort();
  const server = createMetricsServer();
  // A failed metrics bind must never take the API down with it.
  server.on('error', (error) => {
    logger.error('Loopback metrics listener failed', { port, error: error.message });
  });
  server.listen(port, '127.0.0.1', () => {
    logger.info('Loopback metrics listener started', { port });
  });
  return server;
}

module.exports = { createMetricsServer, startMetricsServer, metricsLoopbackEnabled, loopbackPort, DEFAULT_PORT };
