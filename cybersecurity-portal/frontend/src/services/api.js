import axios from 'axios'

export const API_URL = import.meta.env.VITE_API_URL || 'https://secure-eye.up.railway.app/api'

const api = axios.create({
  baseURL: API_URL,
  timeout: 45000,
})

// Set default retry settings
api.defaults.retry = 3;
api.defaults.retryDelay = 1500;

// Attach token to every request
api.interceptors.request.use(config => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Auto-refresh on 401 & Auto-Retry logic
api.interceptors.response.use(
  res => res,
  async err => {
    const { config, response } = err
    
    // 1. Auto-refresh logic (401)
    if (response?.status === 401 && !config._retry) {
      config._retry = true
      const refreshToken = localStorage.getItem('refresh_token')
      if (refreshToken) {
        try {
          const res = await axios.post(`${API_URL}/auth/refresh`, { refresh_token: refreshToken })
          localStorage.setItem('access_token', res.data.access_token)
          localStorage.setItem('refresh_token', res.data.refresh_token)
          config.headers.Authorization = `Bearer ${res.data.access_token}`
          return api(config)
        } catch {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          window.location.href = '/login'
        }
      }
    }

    // 2. Resilience Layer: Auto-Retry on server errors (5xx) or network failures
    if (!config || !config.retry || (response && response.status < 500)) {
        return Promise.reject(err)
    }

    config.__retryCount = config.__retryCount || 0
    if (config.__retryCount >= config.retry) {
        return Promise.reject(err)
    }

    config.__retryCount += 1
    const backoff = new Promise((resolve) => {
        setTimeout(() => resolve(), config.retryDelay * config.__retryCount)
    })

    await backoff
    console.warn(`[Self-Healing] Connection issue detected. Retrying request (${config.__retryCount}/${config.retry})...`)
    return api(config)
  }
)

export default api
