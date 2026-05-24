import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { StatusBar, Style } from '@capacitor/status-bar'
import { SplashScreen } from '@capacitor/splash-screen'
import { AuthProvider, useAuth } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
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
import AdvancedOpsSuite from './pages/AdvancedOpsSuite'
import Settings from './pages/Settings'
import RolePermissions from './pages/RolePermissions'

function PrivateRoute({ children, adminOnly, analystOnly, feature }) {
  const { user, loading, hasFeatureAccess } = useAuth()
  if (loading) return (
    <div className="min-h-screen bg-dark-900 flex items-center justify-center">
      <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
    </div>
  )
  if (!user) return <Navigate to="/login" replace />
  if (adminOnly && user.role !== 'admin') return <Navigate to="/dashboard" replace />
  if (analystOnly && !['admin', 'analyst'].includes(user.role)) return <Navigate to="/dashboard" replace />
  if (feature && !hasFeatureAccess(feature)) return <Navigate to="/dashboard" replace />
  return children
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />

      <Route element={<PrivateRoute><Layout /></PrivateRoute>}>
        <Route path="/dashboard" element={<PrivateRoute feature="dashboard"><Dashboard /></PrivateRoute>} />
        <Route path="/advisories" element={<PrivateRoute feature="advisories"><Advisories /></PrivateRoute>} />
        <Route path="/advisories/new" element={<PrivateRoute analystOnly feature="advisories"><AdvisoryForm /></PrivateRoute>} />
        <Route path="/advisories/:id" element={<PrivateRoute feature="advisories"><AdvisoryDetail /></PrivateRoute>} />
        <Route path="/advisories/:id/edit" element={<PrivateRoute analystOnly feature="advisories"><AdvisoryForm /></PrivateRoute>} />
        <Route path="/search" element={<PrivateRoute feature="search"><SmartSearch /></PrivateRoute>} />
        <Route path="/timeline" element={<PrivateRoute feature="timeline"><ThreatTimeline /></PrivateRoute>} />
        <Route path="/zero-days" element={<PrivateRoute feature="zero-days"><ZeroDayTracker /></PrivateRoute>} />
        <Route path="/iocs" element={<PrivateRoute feature="iocs"><IOCManagement /></PrivateRoute>} />
        <Route path="/misp" element={<PrivateRoute feature="misp"><MISPIntegration /></PrivateRoute>} />
        <Route path="/alerts" element={<PrivateRoute analystOnly feature="advisories"><AlertLogs /></PrivateRoute>} />
        <Route path="/admin/users" element={<PrivateRoute adminOnly><UserManagement /></PrivateRoute>} />
        <Route path="/admin/sectors" element={<PrivateRoute adminOnly><ManageSectors /></PrivateRoute>} />
        <Route path="/admin/feeds" element={<PrivateRoute adminOnly><FeedLogs /></PrivateRoute>} />
        <Route path="/admin/permissions" element={<PrivateRoute adminOnly><RolePermissions /></PrivateRoute>} />
        <Route path="/advanced" element={<PrivateRoute feature="advanced"><AdvancedSecurityCenter /></PrivateRoute>} />
        <Route path="/advanced-ops" element={<PrivateRoute feature="advanced"><AdvancedOpsSuite /></PrivateRoute>} />
        <Route path="/deepscan" element={<PrivateRoute feature="deepscan"><DeepScan /></PrivateRoute>} />
        <Route path="/darkweb" element={<PrivateRoute feature="darkweb"><DarkWebMonitor /></PrivateRoute>} />
        <Route path="/security" element={<PrivateRoute feature="security"><SecuritySettings /></PrivateRoute>} />
        <Route path="/settings" element={<PrivateRoute feature="settings"><Settings /></PrivateRoute>} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ResilienceWrapper>
          <AppRoutes />
        </ResilienceWrapper>
      </AuthProvider>
    </ThemeProvider>
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
