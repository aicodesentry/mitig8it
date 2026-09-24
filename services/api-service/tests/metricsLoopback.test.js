const http = require('http');

jest.mock('../src/utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn() }));

const { createMetricsServer, metricsLoopbackEnabled, loopbackPort, DEFAULT_PORT } = require('../src/metricsServer');

function get(port, path) {
  return new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port, path }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body, headers: response.headers }));
    });
    request.on('error', reject);
  });
}

describe('loopback metrics listener', () => {
  let server;
  let port;

  beforeAll(async () => {
    server = createMetricsServer();
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  // The whole point of the second listener: the sidecar has no internal secret.
  test('serves the exposition format without any secret header', async () => {
    const response = await get(port, '/metrics');
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('text/plain');
    expect(response.body).toContain('mitig8it_analysis_runs_started_total');
  });

  test('exposes the product counters and the process metrics in one scrape', async () => {
    const response = await get(port, '/metrics');
    expect(response.body).toContain('mitig8it_analysis_runs_failed_total');
    expect(response.body).toContain('mitig8it_analysis_runs_stalled');
    expect(response.body).toContain('codesentry_http_request_duration_seconds');
    expect(response.body).toContain('process_cpu_user_seconds_total');
  });

  test('serves nothing but the metrics path', async () => {
    expect((await get(port, '/')).status).toBe(404);
    expect((await get(port, '/health')).status).toBe(404);
  });

  test('is off unless explicitly enabled, so a local run binds no extra port', () => {
    delete process.env.METRICS_LOOPBACK_ENABLED;
    expect(metricsLoopbackEnabled()).toBe(false);
    process.env.METRICS_LOOPBACK_ENABLED = 'true';
    expect(metricsLoopbackEnabled()).toBe(true);
    delete process.env.METRICS_LOOPBACK_ENABLED;
  });

  test('an unusable port configuration falls back rather than binding something arbitrary', () => {
    process.env.METRICS_LOOPBACK_PORT = 'not-a-port';
    expect(loopbackPort()).toBe(DEFAULT_PORT);
    process.env.METRICS_LOOPBACK_PORT = '9123';
    expect(loopbackPort()).toBe(9123);
    delete process.env.METRICS_LOOPBACK_PORT;
  });
});
