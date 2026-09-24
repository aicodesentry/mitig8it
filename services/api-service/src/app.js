const express = require('express');
const { requestTracing } = require('./utils/telemetry');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { randomUUID } = require('crypto');
const { httpDuration, renderMetrics, contentType: metricsContentType } = require('./utils/metricsRegistry');

const authRoutes = require('./routes/auth');
const installationRoutes = require('./routes/installations');
const repositoryRoutes = require('./routes/repositories');
const prRoutes = require('./routes/prs');
const findingRoutes = require('./routes/findings');
const suppressionRoutes = require('./routes/suppressions');
const reportsRoutes = require('./routes/reports');
const webhookRoutes = require('./routes/webhooks');
const webhookEventsRoutes = require('./routes/webhookEvents');
const healthRoutes = require('./routes/health');
const internalRoutes = require('./routes/internal');
const remediationRoutes = require('./routes/remediation');
const logger = require('./utils/logger');
const requestContext = require('./utils/requestContext');

function createApp() {
  const app = express();
  app.use(requestTracing);
  const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
  app.set('trust proxy', 1);

  const CORS_ORIGINS = [
    FRONTEND_URL,
    'https://codesentry-260311-9f2b.web.app',
    'http://localhost:5173',
    'http://localhost:3001',
    ...(process.env.FIREBASE_HOSTING_URL ? [process.env.FIREBASE_HOSTING_URL] : []),
  ].filter(Boolean);

  const isAllowedOrigin = (origin) =>
    Boolean(
      origin &&
      (
        CORS_ORIGINS.includes(origin) ||
        origin === 'https://mitig8it.com' ||
        origin === 'https://www.mitig8it.com'
      )
    );

  app.use(
    helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'none'"],
          baseUri: ["'none'"],
          frameAncestors: ["'none'"],
          formAction: ["'self'"],
        },
      },
    })
  );

  app.use(
    cors({
      origin(origin, callback) {
        // Allow requests with no origin (server-to-server, curl, etc.)
        if (!origin) return callback(null, true);
        if (isAllowedOrigin(origin)) {
          return callback(null, true);
        }
        callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
    })
  );

  app.use((req, res, next) => {
    const correlationId = req.headers['x-correlation-id'] || randomUUID();
    req.correlationId = correlationId;
    res.setHeader('X-Correlation-ID', correlationId);
    next();
  });

  // Everything downstream of this point logs the delivery and run identifiers the
  // caller sent without being handed them.
  app.use(requestContext.requestContextMiddleware);

  app.use((req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      const durationSeconds = Number(process.hrtime.bigint() - start) / 1e9;
      const route = req.route?.path || req.path || 'unknown';
      httpDuration.labels(req.method, route, String(res.statusCode)).observe(durationSeconds);
    });
    next();
  });

  app.use('/webhooks', express.raw({ type: 'application/json', limit: '10mb' }));
  app.use('/webhooks', webhookRoutes);

  app.use(express.json({ limit: '2mb' }));
  app.use(cookieParser());

  app.use((req, res, next) => {
    const unsafeMethod = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
    if (!unsafeMethod || !req.cookies?.__session || req.path.startsWith('/webhooks')) {
      return next();
    }

    const origin = req.get('origin');
    if (origin && !isAllowedOrigin(origin)) {
      return res.status(403).json({ error: 'Invalid request origin' });
    }

    if (req.get('x-csrf-protection') !== '1') {
      return res.status(403).json({ error: 'Missing CSRF protection header' });
    }

    return next();
  });

  app.use(
    '/api',
    rateLimit({
      windowMs: 10 * 60 * 1000,
      max: 400,
      standardHeaders: true,
      legacyHeaders: false,
    })
  );

  app.use(
    '/auth',
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 20,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Too many auth attempts. Try again in 15 minutes.' },
    }),
    authRoutes
  );
  app.use('/api/analysis', require('./routes/playground'));
  app.use('/api/installations', installationRoutes);
  app.use('/api/repositories', repositoryRoutes);
  app.use('/api', prRoutes);
  app.use('/api', findingRoutes);
  app.use('/api', remediationRoutes);
  app.use('/api', suppressionRoutes);
  app.use('/api/reports', reportsRoutes);
  app.use('/api/webhooks', webhookEventsRoutes);
  app.use('/internal', internalRoutes);
  app.use('/health', healthRoutes);

  app.get('/metrics', async (req, res) => {
    const metricsSecret = process.env.METRICS_AUTH_TOKEN || process.env.GITHUB_SERVICE_INTERNAL_SECRET;
    if (process.env.NODE_ENV === 'production') {
      if (!metricsSecret || req.get('x-internal-secret') !== metricsSecret) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
    }

    res.set('Content-Type', metricsContentType);
    res.end(await renderMetrics());
  });

  app.get('/', (_req, res) => {
    res.json({ service: 'mitig8it-api', status: 'ok', version: '1.0.0' });
  });

  app.use((err, req, res, _next) => {
    logger.error('Unhandled API error', {
      correlationId: req.correlationId,
      error: err.message,
      stack: err.stack,
    });
    res.status(err.status || 500).json({ error: err.message || 'Internal error' });
  });

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  return app;
}

module.exports = { createApp };
