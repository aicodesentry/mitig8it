import { beforeEach, describe, expect, it, vi } from 'vitest'

const setLocationHref = (value) => {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: {
      ...window.location,
      href: value,
      hostname: 'localhost',
      pathname: '/',
    },
  })
}

describe('authAPI GitHub login/logout helpers', () => {
  beforeEach(() => {
    vi.resetModules()
    window.localStorage.clear()
    setLocationHref('http://localhost:5173/')
  })

  it('marks the next login for GitHub reauthentication after logout', async () => {
    const post = vi.fn().mockResolvedValue({ data: { success: true } })
    vi.doMock('axios', () => {
      const create = () => ({
        post,
        get: vi.fn(),
        interceptors: {
          request: { use: vi.fn() },
          response: { use: vi.fn() },
        },
      })
      return { default: { create } }
    })

    const { authAPI, consumeGithubReauthRequired } = await import('../api')

    await authAPI.logout()

    expect(consumeGithubReauthRequired()).toBe(true)
    expect(consumeGithubReauthRequired()).toBe(false)
  })

  it('adds prompt=select_account on the first login after logout', async () => {
    vi.doMock('axios', () => {
      const create = () => ({
        post: vi.fn(),
        get: vi.fn(),
        interceptors: {
          request: { use: vi.fn() },
          response: { use: vi.fn() },
        },
      })
      return { default: { create } }
    })

    const { authAPI, markGithubReauthRequired } = await import('../api')

    markGithubReauthRequired()
    authAPI.loginWithGitHub()
    expect(window.location.href).toBe('http://localhost:3000/auth/github?prompt=select_account')

    authAPI.loginWithGitHub()
    expect(window.location.href).toBe('http://localhost:3000/auth/github')
  })
})

it('clears legacy and account report caches on logout, preserving preferences', async () => {
  vi.resetModules()
  const post = vi.fn().mockResolvedValue({ data: {} })
  vi.doMock('axios', () => ({ default: { create: () => ({ post, interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } }) } }))
  localStorage.setItem('reports_cache_main', 'private')
  localStorage.setItem('reports_cache_user_A_main', 'private')
  localStorage.setItem('theme', 'dark')
  const { authAPI } = await import('../api')
  await authAPI.logout()
  expect(localStorage.getItem('reports_cache_main')).toBeNull()
  expect(localStorage.getItem('reports_cache_user_A_main')).toBeNull()
  expect(localStorage.getItem('theme')).toBe('dark')
})

it('routes playground requests through the credentialed CSRF-protected API client', async () => {
  vi.resetModules()
  const get = vi.fn().mockResolvedValue({ data: { status: 'ok' } })
  const post = vi.fn().mockResolvedValue({ data: { vulnerabilities: [] } })
  const requestUse = vi.fn()
  const create = vi.fn(() => ({ get, post, interceptors: { request: { use: requestUse }, response: { use: vi.fn() } } }))
  vi.doMock('axios', () => ({ default: { create } }))
  const { analysisAPI } = await import('../api')
  await analysisAPI.healthCheck()
  await analysisAPI.getHistory(5)
  await analysisAPI.analyzeCode({ code: 'eval(input())', language: 'python' })
  expect(create).toHaveBeenCalledWith(expect.objectContaining({ withCredentials: true }))
  expect(get).toHaveBeenCalledWith('/api/analysis/health')
  expect(get).toHaveBeenCalledWith('/api/analysis/history?limit=5')
  expect(post).toHaveBeenCalledWith('/api/analysis/analyze', { code: 'eval(input())', language: 'python' })
  expect(requestUse.mock.calls[0][0]({}).headers['X-CSRF-Protection']).toBe('1')
})
