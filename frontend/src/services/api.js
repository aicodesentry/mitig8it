import axios from 'axios'
import { clearPrivateCaches } from './privateCache'

const DEFAULT_LOCAL_API_URL = 'http://localhost:3000'
const isBrowser = typeof window !== 'undefined'
const isLocalHost =
  isBrowser && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
const API_BASE_URL =
  import.meta.env.VITE_API_URL || (isLocalHost ? DEFAULT_LOCAL_API_URL : '')
const FORCE_REAUTH_KEY = 'codesentry_force_github_reauth'

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json'
  }
})

export const setAuthToken = (token) => {
  if (typeof window === 'undefined') return
  if (!token) return
  window.localStorage.removeItem('codesentry_auth_token')
}

export const clearAuthToken = () => {
  if (typeof window === 'undefined') return
  window.localStorage.removeItem('codesentry_auth_token')
}

export const markGithubReauthRequired = () => {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(FORCE_REAUTH_KEY, '1')
}

export const consumeGithubReauthRequired = () => {
  if (typeof window === 'undefined') return false
  const required = window.localStorage.getItem(FORCE_REAUTH_KEY) === '1'
  if (required) {
    window.localStorage.removeItem(FORCE_REAUTH_KEY)
  }
  return required
}

api.interceptors.request.use((config) => {
  config.headers = config.headers || {}
  config.headers['X-CSRF-Protection'] = '1'
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const errorCode = error?.response?.data?.code
    const requestUrl = error?.config?.url || ''
    if (
      error?.response?.status === 401 &&
      errorCode !== 'GITHUB_TOKEN_INVALID' &&
      !requestUrl.includes('/api/installations/sync') &&
      (window.location.pathname.startsWith('/app') || window.location.pathname.startsWith('/dashboard'))
    ) {
      clearPrivateCaches()
      clearAuthToken()
      window.location.href = '/'
    }
    return Promise.reject(error)
  }
)

export const authAPI = {
  loginWithGitHub: () => {
    const params = new URLSearchParams()
    if (consumeGithubReauthRequired()) {
      params.set('prompt', 'select_account')
    }
    const query = params.toString()
    window.location.href = `${API_BASE_URL}/auth/github${query ? `?${query}` : ''}`
  },
  getMe: async () => {
    const { data } = await api.get('/auth/me', {
      headers: {
        'Cache-Control': 'no-cache',
        Pragma: 'no-cache'
      }
    })
    return data
  },
  logout: async () => {
    await api.post('/auth/logout')
    clearPrivateCaches()
    markGithubReauthRequired()
  }
}

export const installationAPI = {
  list: async () => {
    const { data } = await api.get('/api/installations')
    return data
  },
  sync: async () => {
    const { data } = await api.post('/api/installations/sync')
    return data
  }
}

export const repositoryAPI = {
  list: async () => {
    const { data } = await api.get('/api/repositories')
    return data
  },
  get: async (repositoryId) => {
    const { data } = await api.get(`/api/repositories/${repositoryId}`)
    return data
  },
  listPRs: async (repositoryId) => {
    const { data } = await api.get(`/api/repositories/${repositoryId}/pull-requests`)
    return data
  },
  setBaseline: async (repositoryId, enabled) => {
    const { data } = await api.patch(`/api/repositories/${repositoryId}/baseline`, { enabled })
    return data
  },
  connect: async (repositoryId) => {
    const { data } = await api.post(`/api/repositories/${repositoryId}/connect`)
    return data
  },
  disconnect: async (repositoryId) => {
    const { data } = await api.post(`/api/repositories/${repositoryId}/disconnect`)
    return data
  },
  getRepositories: async () => {
    const { data } = await api.get('/api/repositories')
    return data
  },
  getConnectedCount: async () => {
    const { data } = await api.get('/api/repositories')
    const active = (data.repositories || []).filter(r => r.is_active)
    return { count: active.length }
  },
  getSummary: async () => {
    const { data } = await api.get('/api/reports/summary')
    return data
  }
}

export const remediationAPI = {
  latest: async (pullRequestId) => (await api.get(`/api/pull-requests/${pullRequestId}/remediations`)).data,
  generate: async (pullRequestId, payload) => (await api.post(`/api/pull-requests/${pullRequestId}/remediations`, payload)).data,
  get: async (id) => (await api.get(`/api/remediations/${id}`)).data,
  preview: async (id) => (await api.get(`/api/remediations/${id}/preview`)).data,
  apply: async (id, payload) => (await api.post(`/api/remediations/${id}/apply`, payload)).data,
  cancel: async (id) => (await api.post(`/api/remediations/${id}/cancel`, {})).data,
  action: async (id) => (await api.get(`/api/remediation-actions/${id}`)).data,
  cancelMerge: async (id) => (await api.post(`/api/remediation-actions/${id}/cancel-merge`, {})).data,
  feedback: async (id, payload) => (await api.post(`/api/remediations/${id}/feedback`, payload)).data,
}

// The four reasons the API accepts for a dismissal or a suppression. They are the same
// list the outcome log validates against, so the workspace never sends free text.
export const DISMISSAL_REASONS = [
  { value: 'not_exploitable', label: 'Not exploitable here' },
  { value: 'test_or_sample_code', label: 'Test or sample code' },
  { value: 'wrong_rule_match', label: 'Wrong rule match' },
  { value: 'other', label: 'Other' },
]

export const findingAPI = {
  listByPR: async (pullRequestId, params = {}) => {
    const q = new URLSearchParams(params).toString()
    const { data } = await api.get(`/api/pull-requests/${pullRequestId}/findings${q ? `?${q}` : ''}`)
    return data
  },
  list: async (params = {}) => {
    const q = new URLSearchParams(params).toString()
    const { data } = await api.get(`/api/findings${q ? `?${q}` : ''}`)
    return data
  },
  get: async (findingId) => {
    const { data } = await api.get(`/api/findings/${findingId}`)
    return data
  },
  updateStatus: async (findingId, status, dismissalReason = null) => {
    const { data } = await api.patch(`/api/findings/${findingId}/status`, {
      status,
      dismissal_reason: dismissalReason
    })
    return data
  }
}

export const suppressionAPI = {
  list: async (repositoryId) => {
    const q = repositoryId ? `?repository_id=${repositoryId}` : ''
    const { data } = await api.get(`/api/suppressions${q}`)
    return data
  },
  create: async (payload) => {
    const { data } = await api.post('/api/suppressions', payload)
    return data
  },
  remove: async (suppressionId) => {
    const { data } = await api.delete(`/api/suppressions/${suppressionId}`)
    return data
  }
}

export const reportsAPI = {
  getPRAnalyses: async (params = {}) => {
    const q = new URLSearchParams(params).toString()
    const { data } = await api.get(`/api/reports/pr-analyses${q ? `?${q}` : ''}`)
    return data
  },
  getPRAnalysisDetails: async (analysisId) => {
    const { data } = await api.get(`/api/reports/pr-analyses/${analysisId}`)
    return data
  },
  getSummary: async () => {
    const { data } = await api.get('/api/reports/summary')
    return data
  }
}

export const analysisAPI = {
  healthCheck: async () => {
    const { data } = await api.get('/api/analysis/health')
    return data
  },
  getHistory: async (limit = 10) => {
    try {
      const { data } = await api.get(`/api/analysis/history?limit=${limit}`)
      return data
    } catch (_error) {
      return { analyses: [], total: 0 }
    }
  },
  analyzeCode: async (payload) => {
    try {
      const { data } = await api.post('/api/analysis/analyze', payload)
      return data
    } catch (error) {
      if (error?.response?.status === 404) {
        throw new Error('Interactive analysis endpoint is not available', { cause: error })
      }
      throw error
    }
  }
}

export const webhookAPI = {
  getEvents: async (limit = 50, offset = 0) => {
    const q = new URLSearchParams({ limit: String(limit), offset: String(offset) }).toString()
    const { data } = await api.get(`/api/webhooks/events?${q}`)
    return data
  }
}

export default api
