const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));

jest.mock('axios');
jest.mock('../src/services/githubUserAuth', () => ({
  persistGithubTokens: jest.fn(),
}));
const axios = require('axios');
const { pool } = require('../src/config/database');
const { createApp } = require('../src/app');
const { persistGithubTokens } = require('../src/services/githubUserAuth');

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  jest.resetAllMocks();
  process.env = { ...ORIGINAL_ENV };
  process.env.GITHUB_CLIENT_ID = 'test-client-id';
  process.env.GITHUB_CLIENT_SECRET = 'test-client-secret';
  process.env.JWT_SECRET = 'test-jwt-secret';
  process.env.ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  process.env.FRONTEND_URL = 'http://localhost:5173';
  process.env.GITHUB_CALLBACK_URL = 'http://localhost:3000/auth/github/callback';
});

afterAll(() => {
  process.env = ORIGINAL_ENV;
});

describe('GET /auth/github', () => {
  test('redirects to GitHub OAuth with correct params', async () => {
    const app = createApp();
    const res = await request(app).get('/auth/github');

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('github.com/login/oauth/authorize');
    expect(res.headers.location).toContain('client_id=test-client-id');
    expect(res.headers.location).toContain('redirect_uri=');
    expect(res.headers.location).toContain('scope=read:user');
    expect(res.headers.location).toContain('state=');
    expect(res.headers.location).not.toContain('read:org');
  });

  test('returns 500 if GITHUB_CLIENT_ID not set', async () => {
    delete process.env.GITHUB_CLIENT_ID;
    const app = createApp();
    const res = await request(app).get('/auth/github');

    expect(res.status).toBe(500);
    expect(res.body.error).toContain('not configured');
  });

  test('returns 500 if GITHUB_CLIENT_SECRET not set', async () => {
    delete process.env.GITHUB_CLIENT_SECRET;
    const app = createApp();
    const res = await request(app).get('/auth/github');

    expect(res.status).toBe(500);
    expect(res.body.error).toContain('not configured');
  });

  test('uses GITHUB_CALLBACK_URL env var in redirect', async () => {
    process.env.GITHUB_CALLBACK_URL = 'https://api.example.com/auth/github/callback';
    const app = createApp();
    const res = await request(app).get('/auth/github');

    expect(res.headers.location).toContain(
      encodeURIComponent('https://api.example.com/auth/github/callback')
    );
  });

  test('forwards prompt=select_account to GitHub when requested', async () => {
    const app = createApp();
    const res = await request(app).get('/auth/github?prompt=select_account');

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('prompt=select_account');
  });
});

describe('GET /auth/github/callback', () => {
  const mockGitHubUser = {
    id: 12345,
    login: 'testuser',
    email: 'test@example.com',
    avatar_url: 'https://avatars.githubusercontent.com/u/12345',
    name: 'Test User',
  };

  const mockDbUser = {
    id: 'uuid-123',
    github_id: 12345,
    github_username: 'testuser',
    github_email: 'test@example.com',
    avatar_url: 'https://avatars.githubusercontent.com/u/12345',
    name: 'Test User',
  };

  function setupSuccessfulOAuth() {
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'gho_test_token_123' },
    });
    axios.get.mockResolvedValueOnce({
      data: mockGitHubUser,
    });
    pool.query.mockResolvedValueOnce({
      rows: [mockDbUser],
    });
    persistGithubTokens.mockResolvedValue({});
  }

  let oauthCookie;
  async function getValidState(app) {
    const res = await request(app).get('/auth/github');
    oauthCookie = res.headers['set-cookie']?.[0]?.split(';')[0] || '';
    const location = res.headers.location || '';
    const redirectUrl = new URL(location);
    return redirectUrl.searchParams.get('state');
  }

  test('redirects with error if no code provided', async () => {
    const app = createApp();
    const res = await request(app).get('/auth/github/callback');

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=no_oauth_code');
  });

  test('rejects callback with missing state', async () => {
    const app = createApp();
    const res = await request(app).get('/auth/github/callback?code=test-code');

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=invalid_state');
  });

  test('rejects callback with tampered state', async () => {
    const app = createApp();
    const state = await getValidState(app);
    const tamperedState = `${state}tampered`;
    const res = await request(app).get(`/auth/github/callback?code=test-code&state=${encodeURIComponent(tamperedState)}`);

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=invalid_state');
  });

  test('rejects state transferred to a browser without the initiating cookie', async () => {
    setupSuccessfulOAuth();
    const app = createApp();
    const state = await getValidState(app);
    const res = await request(app).get(`/auth/github/callback?code=test-code&state=${state}`);
    expect(res.headers.location).toContain('error=invalid_state');
    expect(axios.post).not.toHaveBeenCalled();
  });

  test('rejects unrelated Firebase origins', async () => {
    const res = await request(createApp()).get('/').set('Origin', 'https://codesentry-attacker-owned.web.app');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('sets cookie-backed session and redirects straight to dashboard', async () => {
    setupSuccessfulOAuth();
    const app = createApp();
    const state = await getValidState(app);
    const res = await request(app).get(`/auth/github/callback?code=test-code&state=${state}`).set('Cookie', oauthCookie);

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('http://localhost:5173/dashboard');
    const authCookie = res.headers['set-cookie']?.findLast((cookie) => cookie.startsWith('__session='));
    expect(authCookie).toBeDefined();
    const cookieToken = decodeURIComponent(authCookie.split(';')[0].split('=')[1]);
    const decoded = jwt.verify(cookieToken, 'test-jwt-secret');
    expect(decoded.github_username).toBe('testuser');

    // Verify GitHub token exchange
    expect(axios.post).toHaveBeenCalledWith(
      'https://github.com/login/oauth/access_token',
      { client_id: 'test-client-id', client_secret: 'test-client-secret', code: 'test-code' },
      expect.objectContaining({ headers: { Accept: 'application/json' } })
    );

    // Verify user was fetched
    expect(axios.get).toHaveBeenCalledWith(
      'https://api.github.com/user',
      expect.objectContaining({ headers: { Authorization: 'Bearer gho_test_token_123' } })
    );

    // Verify DB upsert
    expect(pool.query).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO users'),
      expect.arrayContaining([12345, 'testuser', 'test@example.com'])
    );
  });

  test('fetches email from /user/emails if not in profile', async () => {
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'gho_test_token_123' },
    });
    axios.get
      .mockResolvedValueOnce({
        data: { ...mockGitHubUser, email: null },
      })
      .mockResolvedValueOnce({
        data: [
          { email: 'secondary@example.com', primary: false },
          { email: 'primary@example.com', primary: true },
        ],
      });
    pool.query.mockResolvedValueOnce({ rows: [mockDbUser] });
    persistGithubTokens.mockResolvedValue({});

    const app = createApp();
    const state = await getValidState(app);
    await request(app).get(`/auth/github/callback?code=test-code&state=${state}`).set('Cookie', oauthCookie);

    expect(axios.get).toHaveBeenCalledWith(
      'https://api.github.com/user/emails',
      expect.any(Object)
    );
    expect(pool.query).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO users'),
      expect.arrayContaining(['primary@example.com'])
    );
  });

  test('redirects with error if token exchange fails', async () => {
    axios.post.mockResolvedValueOnce({
      data: { error: 'bad_verification_code' },
    });

    const app = createApp();
    const state = await getValidState(app);
    const res = await request(app).get(`/auth/github/callback?code=bad-code&state=${state}`).set('Cookie', oauthCookie);

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=oauth_exchange_failed');
  });

  test('redirects with error if GitHub API returns error', async () => {
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'gho_test_token_123' },
    });
    axios.get.mockRejectedValueOnce(new Error('GitHub API error'));

    const app = createApp();
    const state = await getValidState(app);
    const res = await request(app).get(`/auth/github/callback?code=test-code&state=${state}`).set('Cookie', oauthCookie);

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=oauth_callback_failed');
  });

  test('redirects with error if DB upsert fails', async () => {
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'gho_test_token_123' },
    });
    axios.get.mockResolvedValueOnce({ data: mockGitHubUser });
    pool.query.mockRejectedValueOnce(new Error('DB connection refused'));

    const app = createApp();
    const state = await getValidState(app);
    const res = await request(app).get(`/auth/github/callback?code=test-code&state=${state}`).set('Cookie', oauthCookie);

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('error=oauth_callback_failed');
  });

  test('stores GitHub refresh-token metadata when GitHub returns expiring user tokens', async () => {
    axios.post.mockResolvedValueOnce({
      data: {
        access_token: 'gho_test_token_123',
        refresh_token: 'ghr_refresh_123',
        expires_in: 28800,
        refresh_token_expires_in: 15811200,
      },
    });
    axios.get.mockResolvedValueOnce({
      data: mockGitHubUser,
    });
    pool.query.mockResolvedValueOnce({
      rows: [mockDbUser],
    });
    persistGithubTokens.mockResolvedValue({});

    const app = createApp();
    const state = await getValidState(app);
    const res = await request(app).get(`/auth/github/callback?code=test-code&state=${state}`).set('Cookie', oauthCookie);

    expect(res.status).toBe(302);
    expect(pool.query).toHaveBeenCalledWith(
      expect.stringContaining('github_refresh_token'),
      expect.arrayContaining([12345, 'testuser', 'test@example.com'])
    );
    expect(persistGithubTokens).toHaveBeenCalledWith(
      'uuid-123',
      expect.objectContaining({
        access_token: 'gho_test_token_123',
        refresh_token: 'ghr_refresh_123',
        expires_in: 28800,
        refresh_token_expires_in: 15811200,
      })
    );
  });
});

describe('POST /auth/exchange', () => {
  test('returns 410 for legacy auth-code exchange flow', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/auth/exchange')
      .send({ code: 'legacy-code' });

    expect(res.status).toBe(410);
    expect(res.body.error).toContain('Legacy auth exchange');
  });
});

describe('GET /auth/me', () => {
  test('returns user with valid JWT', async () => {
    const token = jwt.sign(
      { user_id: 'uuid-123', github_id: 12345, github_username: 'testuser' },
      'test-jwt-secret',
      { expiresIn: '7d' }
    );

    pool.query.mockResolvedValueOnce({
      rowCount: 1,
      rows: [{
        id: 'uuid-123',
        github_id: 12345,
        github_username: 'testuser',
        github_email: 'test@example.com',
        avatar_url: 'https://avatars.githubusercontent.com/u/12345',
        name: 'Test User',
        created_at: '2026-01-01T00:00:00Z',
      }],
    });

    const app = createApp();
    const res = await request(app)
      .get('/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.user.github_username).toBe('testuser');
    expect(res.body.github_app_install_url).toContain('github.com/apps/');
  });

  test('returns user with valid auth cookie', async () => {
    const token = jwt.sign(
      { user_id: 'uuid-123', github_id: 12345, github_username: 'testuser' },
      'test-jwt-secret',
      { expiresIn: '7d' }
    );

    pool.query.mockResolvedValueOnce({
      rowCount: 1,
      rows: [{
        id: 'uuid-123',
        github_id: 12345,
        github_username: 'testuser',
        github_email: 'test@example.com',
        avatar_url: 'https://avatars.githubusercontent.com/u/12345',
        name: 'Test User',
        created_at: '2026-01-01T00:00:00Z',
      }],
    });

    const app = createApp();
    const res = await request(app)
      .get('/auth/me')
      .set('Cookie', [`__session=${token}`]);

    expect(res.status).toBe(200);
    expect(res.body.user.github_username).toBe('testuser');
  });

  test('returns 401 with no token', async () => {
    const app = createApp();
    const res = await request(app).get('/auth/me');

    expect(res.status).toBe(401);
  });

  test('returns 401 with invalid token', async () => {
    const app = createApp();
    const res = await request(app)
      .get('/auth/me')
      .set('Authorization', 'Bearer invalid-token');

    expect(res.status).toBe(401);
  });

  test('returns 401 with expired token', async () => {
    const token = jwt.sign(
      { user_id: 'uuid-123', github_id: 12345, github_username: 'testuser' },
      'test-jwt-secret',
      { expiresIn: '0s' }
    );

    const app = createApp();
    const res = await request(app)
      .get('/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(401);
  });

  test('returns 404 if user not found in DB', async () => {
    const token = jwt.sign(
      { user_id: 'uuid-deleted', github_id: 99999, github_username: 'ghost' },
      'test-jwt-secret',
      { expiresIn: '7d' }
    );

    pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });

    const app = createApp();
    const res = await request(app)
      .get('/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });
});

describe('POST /auth/logout', () => {
  test('returns success', async () => {
    const app = createApp();
    const res = await request(app).post('/auth/logout');

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('clears the auth cookie with local-development attributes', async () => {
    const app = createApp();
    const res = await request(app).post('/auth/logout');

    const authCookie = res.headers['set-cookie']?.findLast((cookie) => cookie.startsWith('__session='));
    expect(authCookie).toBeDefined();
    expect(authCookie).toContain('__session=;');
    expect(authCookie).toContain('Path=/');
    expect(authCookie).toContain('HttpOnly');
    expect(authCookie).toContain('SameSite=Lax');
    expect(authCookie).not.toContain('Secure');
  });

  test('clears the auth cookie with secure attributes behind HTTPS proxy', async () => {
    process.env.NODE_ENV = 'production';
    const app = createApp();
    const res = await request(app)
      .post('/auth/logout')
      .set('X-Forwarded-Proto', 'https');

    const authCookie = res.headers['set-cookie']?.findLast((cookie) => cookie.startsWith('__session='));
    expect(authCookie).toBeDefined();
    expect(authCookie).toContain('__session=;');
    expect(authCookie).toContain('Path=/');
    expect(authCookie).toContain('HttpOnly');
    expect(authCookie).toContain('SameSite=None');
    expect(authCookie).toContain('Secure');
  });
});
