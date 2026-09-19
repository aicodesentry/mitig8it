const path = require('path');
require('dotenv').config();
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), override: false });

const { pool } = require('./config/database');
const logger = require('./utils/logger');
const { startTelemetry, shutdownTelemetry } = require('./utils/telemetry');
const { createApp } = require('./app');
const { ensureDatabaseSchema } = require('./services/schemaBootstrap');

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

  // Start background profile worker (processes one repo per minute)
  if (process.env.NODE_ENV !== 'test') {
    const { startWorkerLoop } = require('./services/profileWorker');
    const { startAnalysisQueueWorker } = require('./services/prAnalysisOrchestrator');
    startWorkerLoop(60000);
    startAnalysisQueueWorker();
  }

  const shutdown = async () => {
    logger.info('API service shutting down');
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
