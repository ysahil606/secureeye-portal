import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/Layout'
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
        <Route path="/alerts" element={<PrivateRoute analystOnly><AlertLogs /></PrivateRoute>} />
        <Route path="/admin/users" element={<PrivateRoute adminOnly><UserManagement /></PrivateRoute>} />
        <Route path="/admin/sectors" element={<PrivateRoute adminOnly><ManageSectors /></PrivateRoute>} />
        <Route path="/admin/feeds" element={<FeedLogs />} />
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  )
}
