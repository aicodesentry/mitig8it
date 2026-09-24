const axios = require('axios');
const { pool } = require('../config/database');
const { getIdentityToken, normalizeAudience } = require('../clients/grpcConnection');
const logger = require('../utils/logger');

// The first webhook after an idle period used to pay for every cold start in the chain
// one after another: connect the database pool, mint an identity token, wake the github
// service, wake the analysis service. Doing that work at startup, in parallel, moves it
// off the critical path of the first review.
//
// Nothing here is allowed to fail the process. A warm-up that cannot reach a peer has
// lost an optimisation, not correctness: the orchestrator still retries a cold
// downstream on 429 exactly as it did before.
const WARMUP_TIMEOUT_MS = Number(process.env.WARMUP_TIMEOUT_MS || 5000);

function useGrpcTransport() {
  return String(process.env.INTERNAL_SERVICE_TRANSPORT || '').toLowerCase() === 'grpc';
}

async function warmDatabase() {
  // Opens a real connection and runs a real statement: a pool that has never been used
  // has no connection, and the first webhook would pay the TLS handshake itself.
  await pool.query('SELECT 1');
  return 'database';
}

// Any response at all means the instance is awake, which is the whole objective. A 401
// from an authenticated health route warms the container just as well as a 200.
async function warmHttpService(name, url) {
  if (!url) return null;
  try {
    await axios.get(`${url.replace(/\/+$/, '')}/health`, {
      timeout: WARMUP_TIMEOUT_MS,
      validateStatus: () => true,
    });
  } catch (error) {
    logger.warn('Warm-up ping failed', { service: name, error: error.message });
    return null;
  }
  return name;
}

// On Cloud Run the identity token, not the TCP connect, is the slow part of the first
// internal call, and a failed mint is the failure the orchestrator retries around.
async function warmIdentityToken(name, rawAudience, rawTarget) {
  const audience = normalizeAudience(rawAudience, rawTarget);
  if (!audience) return null;
  try {
    await getIdentityToken(audience);
  } catch (error) {
    logger.warn('Warm-up identity token mint failed', { service: name, error: error.message });
    return null;
  }
  return `${name}_identity`;
}

function warmupTasks() {
  const tasks = [
    warmDatabase(),
    warmHttpService('github', process.env.GITHUB_SERVICE_URL),
    warmHttpService('analysis', process.env.ANALYSIS_SERVICE_URL),
  ];
  if (useGrpcTransport()) {
    tasks.push(
      warmIdentityToken('github', process.env.GITHUB_GRPC_AUDIENCE, process.env.GITHUB_GRPC_URL),
      warmIdentityToken('analysis', process.env.ANALYSIS_GRPC_AUDIENCE, process.env.ANALYSIS_GRPC_URL)
    );
  }
  return tasks;
}

async function warmUp() {
  const started = Date.now();
  const results = await Promise.allSettled(warmupTasks());
  const warmed = results
    .filter((result) => result.status === 'fulfilled' && result.value)
    .map((result) => result.value);
  const failed = results.filter((result) => result.status === 'rejected').length;
  logger.info('Warm-up finished', { warmed, failed, durationMs: Date.now() - started });
  return { warmed, failed };
}

module.exports = { warmUp, warmDatabase, warmHttpService, warmIdentityToken, WARMUP_TIMEOUT_MS };
