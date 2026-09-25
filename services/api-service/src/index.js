const path = require('path');
require('dotenv').config();
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), override: false });

const { pool } = require('./config/database');
const logger = require('./utils/logger');
const { startTelemetry, shutdownTelemetry } = require('./utils/telemetry');
const { createApp } = require('./app');
const { ensureDatabaseSchema } = require('./services/schemaBootstrap');
const { startMetricsServer } = require('./metricsServer');
const { warmUp } = require('./services/warmup');

const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET'];
if (process.env.NODE_ENV === 'production') {
  requiredEnvVars.push('GITHUB_WEBHOOK_SECRET', 'GITHUB_SERVICE_INTERNAL_SECRET');
}
if (process.env.GITHUB_CLIENT_ID || process.env.GITHUB_CLIENT_SECRET) {
  requiredEnvVars.push('ENCRYPTION_KEY');
}
const missing = requiredEnvVars.filter((v) => !process.env[v]);
if (missing.length > 0) {
  console.error(`Missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

const PORT = Number(process.env.PORT || 3000);

async function start() {
  startTelemetry('mitig8it-api');
  await ensureDatabaseSchema();
  const app = createApp();
  const server = app.listen(PORT, () => {
    logger.info('API service started', { port: PORT });
  });

  // The managed Prometheus sidecar scrapes this loopback listener; the public
  // /metrics route stays gated by the internal secret.
  const metricsServer = startMetricsServer();

  // Deliberately not awaited: readiness must not wait on a peer service, and the
  // warm-up is an optimisation, not a precondition for serving.
  if (process.env.NODE_ENV !== 'test') {
    warmUp().catch((error) => logger.warn('Warm-up failed', { error: error.message }));
  }

  // Start background profile worker (processes one repo per minute)
  let stopPurgeLoop = null;
  if (process.env.NODE_ENV !== 'test') {
    const { startWorkerLoop } = require('./services/profileWorker');
    const { startAnalysisQueueWorker } = require('./services/prAnalysisOrchestrator');
    const { startPurgeLoop } = require('./services/installationPurge');
    startWorkerLoop(60000);
    startAnalysisQueueWorker();
    // Deleting the data of an uninstalled installation must not depend on the
    // remediation control plane being enabled, so this runs whether or not the
    // reconciler does. Both call the same locked, idempotent purge.
    stopPurgeLoop = startPurgeLoop();
  }

  // Single-instance deployments run the remediation control-plane loop inside the API
  // process instead of a separate worker Deployment. Off unless explicitly enabled.
  let stopRemediationWorker = null;
  if (process.env.REMEDIATION_WORKER_INPROCESS === 'true') {
    const { startRemediationWorker } = require('./workers');
    stopRemediationWorker = startRemediationWorker();
    logger.info('Remediation worker started in-process');
  }

  const shutdown = async () => {
    logger.info('API service shutting down');
    if (stopPurgeLoop) {
      try { stopPurgeLoop(); } catch (error) {
        logger.error('Installation purge loop stop failed', { error: error.message });
      }
      stopPurgeLoop = null;
    }
    if (stopRemediationWorker) {
      try {
        stopRemediationWorker();
      } catch (error) {
        logger.error('Remediation worker stop failed', { error: error.message });
      }
      stopRemediationWorker = null;
    }
    if (metricsServer) metricsServer.close();
    server.close(async () => {
      await shutdownTelemetry();
      await pool.end();
      process.exit(0);
    });
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

start().catch((err) => {
  logger.error('Failed to start API service', { error: err.message });
  process.exit(1);
});
