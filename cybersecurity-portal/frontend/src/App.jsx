import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { StatusBar, Style } from '@capacitor/status-bar'
import { SplashScreen } from '@capacitor/splash-screen'
import { AuthProvider, useAuth } from './context/AuthContext'
import { startBackendKeepAlive } from './services/resilience'
import Layout from './components/Layout'
import AppLock from './components/AppLock'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Advisories from './pages/Advisories'
import AdvisoryDetail from './pages/AdvisoryDetail'
import AdvisoryForm from './pages/AdvisoryForm'
import SmartSearch from './pages/SmartSearch'
import ThreatTimeline from './pages/ThreatTimeline'
import ZeroDayTracker from './pages/ZeroDayTracker'
import IOCManagement from './pages/IOCManagement'
import AlertLogs from './pages/AlertLogs'
import UserManagement from './pages/UserManagement'
import ManageSectors from './pages/ManageSectors'
import FeedLogs from './pages/FeedLogs'
import MISPIntegration from './pages/MISPIntegration'
import AdvancedSecurityCenter from './pages/AdvancedSecurityCenter'
import DeepScan from './pages/DeepScan'
import DarkWebMonitor from './pages/DarkWebMonitor'
import SecuritySettings from './pages/SecuritySettings'
import MobileToolkit from './pages/MobileToolkit'
import AdvancedOpsSuite from './pages/AdvancedOpsSuite'

function PrivateRoute({ children, adminOnly, analystOnly }) {
  const { user, loading } = useAuth()
  if (loading) return (
    <div className="min-h-screen bg-dark-900 flex items-center justify-center">
      <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
    </div>
  )
  if (!user) return <Navigate to="/login" replace />
  if (adminOnly && user.role !== 'admin') return <Navigate to="/dashboard" replace />
  if (analystOnly && !['admin', 'analyst'].includes(user.role)) return <Navigate to="/dashboard" replace />
  return children
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />

      <Route element={<PrivateRoute><Layout /></PrivateRoute>}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/advisories" element={<Advisories />} />
        <Route path="/advisories/new" element={<PrivateRoute analystOnly><AdvisoryForm /></PrivateRoute>} />
        <Route path="/advisories/:id" element={<AdvisoryDetail />} />
        <Route path="/advisories/:id/edit" element={<PrivateRoute analystOnly><AdvisoryForm /></PrivateRoute>} />
        <Route path="/search" element={<SmartSearch />} />
        <Route path="/timeline" element={<ThreatTimeline />} />
        <Route path="/zero-days" element={<ZeroDayTracker />} />
        <Route path="/iocs" element={<IOCManagement />} />
        <Route path="/misp" element={<MISPIntegration />} />
        <Route path="/alerts" element={<PrivateRoute analystOnly><AlertLogs /></PrivateRoute>} />
        <Route path="/admin/users" element={<PrivateRoute adminOnly><UserManagement /></PrivateRoute>} />
        <Route path="/admin/sectors" element={<PrivateRoute adminOnly><ManageSectors /></PrivateRoute>} />
        <Route path="/admin/feeds" element={<FeedLogs />} />
        <Route path="/advanced" element={<AdvancedSecurityCenter />} />
        <Route path="/advanced-ops" element={<AdvancedOpsSuite />} />
        <Route path="/deepscan" element={<DeepScan />} />
        <Route path="/darkweb" element={<DarkWebMonitor />} />
        <Route path="/mobile-toolkit" element={<MobileToolkit />} />
        <Route path="/security" element={<SecuritySettings />} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <ResilienceWrapper>
        <AppRoutes />
      </ResilienceWrapper>
    </AuthProvider>
  )
}

function ResilienceWrapper({ children }) {
  const [isLocked, setIsLocked] = useState(true)
  const [hasPin, setHasPin] = useState(null)

  useEffect(() => {
    const checkPinConfig = async () => {
      const { Preferences } = await import('@capacitor/preferences')
      const { value } = await Preferences.get({ key: 'app_pin' })
      if (!value) {
        setIsLocked(false)
        setHasPin(false)
      } else {
        setHasPin(true)
      }
    }
    checkPinConfig()

    // Initialize Capacitor native features
    const initNative = async () => {
      try {
        await StatusBar.setStyle({ style: Style.Dark })
        await StatusBar.setBackgroundColor({ color: '#0a0e1a' })
        await SplashScreen.hide()
      } catch (e) {
        console.log('Native platform features not available')
      }
    }
    initNative()

    const enforceAutoLock = () => {
      const minutes = Number(localStorage.getItem('secureeye_auto_lock') || 0)
      if (!minutes || document.visibilityState !== 'visible') return
      const lastUnlock = Number(localStorage.getItem('secureeye_last_unlock') || Date.now())
      if (Date.now() - lastUnlock > minutes * 60 * 1000) {
        setIsLocked(true)
        setHasPin(true)
      }
    }
    document.addEventListener('visibilitychange', enforceAutoLock)
    const stopKeepAlive = startBackendKeepAlive()

    return () => {
      document.removeEventListener('visibilitychange', enforceAutoLock)
      stopKeepAlive?.()
    }
  }, [])

  if (isLocked && hasPin === true) {
    return <AppLock onSuccess={() => {
      localStorage.setItem('secureeye_last_unlock', String(Date.now()))
      setIsLocked(false)
    }} />
  }

  return children
}
