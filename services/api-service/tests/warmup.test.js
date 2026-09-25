const axios = require('axios');

jest.mock('axios');
jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));
jest.mock('../src/clients/grpcConnection', () => ({
  getIdentityToken: jest.fn(),
  normalizeAudience: jest.requireActual('../src/clients/grpcConnection').normalizeAudience,
}));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn() }));

const { pool } = require('../src/config/database');
const { getIdentityToken } = require('../src/clients/grpcConnection');
const logger = require('../src/utils/logger');
const { warmUp } = require('../src/services/warmup');

beforeEach(() => {
  jest.clearAllMocks();
  pool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] });
  axios.get.mockResolvedValue({ status: 200, data: {} });
  getIdentityToken.mockResolvedValue('token');
  process.env.GITHUB_SERVICE_URL = 'https://github-service.example';
  process.env.ANALYSIS_SERVICE_URL = 'https://analysis-service.example';
  delete process.env.INTERNAL_SERVICE_TRANSPORT;
  delete process.env.GITHUB_GRPC_AUDIENCE;
  delete process.env.ANALYSIS_GRPC_AUDIENCE;
});

describe('warm-up', () => {
  test('opens the database pool with a real statement', async () => {
    await warmUp();
    expect(pool.query).toHaveBeenCalledWith('SELECT 1');
  });

  test('pings both downstream services in parallel', async () => {
    await warmUp();
    expect(axios.get).toHaveBeenCalledWith('https://github-service.example/health', expect.any(Object));
    expect(axios.get).toHaveBeenCalledWith('https://analysis-service.example/health', expect.any(Object));
  });

  // A cold service answering 401 or 503 is still a woken service, which is the point.
  test('any response counts as warm', async () => {
    axios.get.mockResolvedValue({ status: 401 });
    const result = await warmUp();
    expect(result.warmed).toContain('github');
    expect(result.warmed).toContain('analysis');
  });

  test('pre-mints the identity tokens the first internal gRPC call would wait for', async () => {
    process.env.INTERNAL_SERVICE_TRANSPORT = 'grpc';
    process.env.GITHUB_GRPC_AUDIENCE = 'https://github-service.example';
    process.env.ANALYSIS_GRPC_AUDIENCE = 'https://analysis-service.example';

    const result = await warmUp();

    expect(getIdentityToken).toHaveBeenCalledWith('https://github-service.example');
    expect(getIdentityToken).toHaveBeenCalledWith('https://analysis-service.example');
    expect(result.warmed).toContain('github_identity');
  });

  test('does not mint identity tokens when the transport is HTTP', async () => {
    await warmUp();
    expect(getIdentityToken).not.toHaveBeenCalled();
  });

  // The warm-up is an optimisation. Losing it must never stop the service serving.
  test('an unreachable downstream is logged and never thrown', async () => {
    axios.get.mockRejectedValue(new Error('connect ECONNREFUSED'));
    await expect(warmUp()).resolves.toMatchObject({ failed: 0 });
    expect(logger.warn).toHaveBeenCalledWith('Warm-up ping failed', expect.objectContaining({ service: 'github' }));
  });

  test('a database that refuses the connection is reported, not thrown', async () => {
    pool.query.mockRejectedValue(new Error('no pg_hba.conf entry'));
    await expect(warmUp()).resolves.toMatchObject({ failed: 1 });
  });

  test('a service with no configured URL is skipped rather than guessed at', async () => {
    delete process.env.ANALYSIS_SERVICE_URL;
    const result = await warmUp();
    expect(result.warmed).not.toContain('analysis');
    expect(axios.get).toHaveBeenCalledTimes(1);
  });
});
