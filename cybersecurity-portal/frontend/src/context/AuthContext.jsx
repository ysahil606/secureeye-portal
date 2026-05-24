import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import api from '../services/api'
import { wakeBackend } from '../services/resilience'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [permissions, setPermissions] = useState([])
  const [loading, setLoading] = useState(true)

  const loadUser = useCallback(async () => {
    const token = localStorage.getItem('access_token')
    if (!token) { setLoading(false); return }
    try {
      const res = await api.get('/auth/me')
      setUser(res.data)
      try {
        const pRes = await api.get('/auth/me/permissions')
        setPermissions(pRes.data)
      } catch (e) {
        setPermissions([])
      }
    } catch {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadUser() }, [loadUser])

  const login = async (username, password) => {
    await wakeBackend()
    const res = await api.post('/auth/login', { username, password })
    const { access_token, refresh_token, user: userData } = res.data
    localStorage.setItem('access_token', access_token)
    localStorage.setItem('refresh_token', refresh_token)
    setUser(userData)
    try {
      const pRes = await api.get('/auth/me/permissions')
      setPermissions(pRes.data)
    } catch (e) {
      setPermissions([])
    }
    return userData
  }

  const logout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    setUser(null)
    setPermissions([])
  }

  const isAdmin = user?.role === 'admin'
  const isAnalyst = user?.role === 'analyst' || user?.role === 'admin'
  const isViewer = !!user

  const hasFeatureAccess = (feature) => {
    if (!user) return false
    if (user.role === 'admin' || permissions.includes('*')) return true
    return permissions.includes(feature)
  }

  return (
    <AuthContext.Provider value={{ user, permissions, loading, login, logout, isAdmin, isAnalyst, isViewer, loadUser, hasFeatureAccess }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
