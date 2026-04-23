import axios from 'axios'

import api, { API_URL } from './api'

const HEALTH_PATH = '/health'
const KEEP_ALIVE_INTERVAL_MS = 4 * 60 * 1000
const WAKE_RETRIES = 5

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms))

export async function wakeBackend() {
  let lastError

  for (let attempt = 0; attempt <= WAKE_RETRIES; attempt += 1) {
    try {
      await axios.get(`${API_URL}${HEALTH_PATH}`, {
        timeout: attempt === 0 ? 12000 : 20000,
      })
      return true
    } catch (error) {
      lastError = error
      const delay = Math.min(1000 * 2 ** attempt, 8000)
      await wait(delay)
    }
  }

  throw lastError
}

export function startBackendKeepAlive() {
  let stopped = false

  const pulse = async () => {
    if (stopped || document.hidden) return
    try {
      await api.get(HEALTH_PATH, { timeout: 10000, retry: 1 })
    } catch {
      // The next scheduled pulse or user request will retry with normal backoff.
    }
  }

  pulse()
  const intervalId = window.setInterval(pulse, KEEP_ALIVE_INTERVAL_MS)
  const onVisible = () => {
    if (!document.hidden) pulse()
  }
  document.addEventListener('visibilitychange', onVisible)

  return () => {
    stopped = true
    window.clearInterval(intervalId)
    document.removeEventListener('visibilitychange', onVisible)
  }
}
