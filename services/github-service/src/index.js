const express = require('express');
const { startTelemetry, requestTracing } = require('./utils/telemetry');
const cors = require('cors');
const helmet = require('helmet');
const client = require('prom-client');
const webhookRoutes = require('./routes/webhooks');
const internalRoutes = require('./routes/internal');
const githubAppAuth = require('./services/githubAppAuth');
const { startServer: startGrpcServer } = require('./github_grpc_server');
const path = require('path');
require('dotenv').config();
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), override: false });
// Alias: root .env uses GITHUB_WEBHOOK_SECRET; this service expects WEBHOOK_SECRET
process.env.WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || process.env.GITHUB_WEBHOOK_SECRET;

if (process.env.SERVICE_MODE === 'grpc') {
  startGrpcServer();
  return;
}

// Validate required environment variables
const requiredEnvVars = [
  'WEBHOOK_SECRET'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:');
  missingEnvVars.forEach(varName => console.error(`  - ${varName}`));
  process.exit(1);
}

console.log('✓ All required environment variables are set');

const app = express();
startTelemetry('mitig8it-github');
app.use(requestTracing);
const PORT = process.env.PORT || 3002;
const metricsRegister = new client.Registry();

// Prometheus metrics: default system metrics + HTTP duration histogram
client.collectDefaultMetrics({ register: metricsRegister });
const httpRequestDurationSeconds = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'path', 'status'],
  buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5],
});
metricsRegister.registerMetric(httpRequestDurationSeconds);

app.use(helmet());
app.use(cors());

// Don't use express.json() globally - webhook route needs raw body
// The webhook route handles its own body parsing
app.use((req, res, next) => {
  if (req.path === '/webhooks/github') {
    next(); // Let webhook route handle raw body
  } else {
    express.json({ limit: '2mb' })(req, res, next);
  }
});

// Record HTTP durations for RED metrics
app.use((req, res, next) => {
  const start = process.hrtime();
  res.on('finish', () => {
    const [s, ns] = process.hrtime(start);
    const durationSeconds = s + ns / 1e9;
    const path = req.route?.path || req.path || 'unknown';
    httpRequestDurationSeconds
      .labels(req.method, path, res.statusCode)
      .observe(durationSeconds);
  });
  next();
});

// Metrics endpoint (kept open for internal scrapes only)
app.get('/metrics', async (req, res) => {
  const metricsSecret = process.env.METRICS_AUTH_TOKEN || process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  if (process.env.NODE_ENV === 'production') {
    if (!metricsSecret || req.get('x-internal-secret') !== metricsSecret) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  try {
    res.set('Content-Type', metricsRegister.contentType);
    res.end(await metricsRegister.metrics());
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// Mount routes
app.use('/webhooks', webhookRoutes);
app.use('/internal', internalRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'github-service',
    timestamp: new Date().toISOString()
  });
});

// GitHub App health check to validate installation token works
app.get('/health/github-app', async (_req, res) => {
  const result = await githubAppAuth.healthCheck();
  const status = result.ok ? 200 : 500;
  res.status(status).json({
    status: result.ok ? 'ok' : 'error',
    service: 'github-service',
    github_app: result,
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`GitHub Service running on port ${PORT}`);
});

if (process.env.ENABLE_GRPC_SERVER === 'true') {
  startGrpcServer();
}
