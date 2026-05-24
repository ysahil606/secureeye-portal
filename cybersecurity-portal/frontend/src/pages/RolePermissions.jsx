import React, { useState, useEffect } from 'react'
import api from '../services/api'
import { Shield, Save, Loader2, AlertTriangle, CheckCircle } from 'lucide-react'
import clsx from 'clsx'

const ROLES = [
  { id: 'analyst', label: 'Analyst Role', color: 'blue' },
  { id: 'viewer', label: 'Viewer Role', color: 'purple' }
]

const FEATURES = [
  { id: 'dashboard', label: 'Dashboard', desc: 'Main overview page' },
  { id: 'advisories', label: 'Advisories', desc: 'View threat advisories' },
  { id: 'search', label: 'Smart Search', desc: 'AI-powered global search' },
  { id: 'timeline', label: 'Threat Timeline', desc: 'Visual chronological threat tracker' },
  { id: 'zero-days', label: 'Zero-Day Tracker', desc: 'Track unpatched exploits' },
  { id: 'misp', label: 'MISP Integration', desc: 'Sync with MISP servers' },
  { id: 'iocs', label: 'IOC Management', desc: 'Indicators of Compromise DB' },
  { id: 'deepscan', label: 'DeepScan Lab', desc: 'Advanced sandbox analysis' },
  { id: 'darkweb', label: 'Dark Web Monitor', desc: 'Track leak sites and forums' },
  { id: 'advanced', label: 'Advanced Center', desc: 'Advanced tools & settings' },
  { id: 'security', label: 'Security Settings', desc: 'Personal app security' },
  { id: 'settings', label: 'App Settings', desc: 'Theme & appearance' }
]

export default function RolePermissions() {
  const [permissions, setPermissions] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    fetchPermissions()
  }, [])

  const fetchPermissions = async () => {
    try {
      const res = await api.get('/admin/permissions')
      // If DB is empty, initialize default state
      if (res.data.length === 0) {
        const defaults = []
        ROLES.forEach(r => {
          FEATURES.forEach(f => {
            defaults.push({ role: r.id, feature: f.id, is_allowed: true })
          })
        })
        setPermissions(defaults)
      } else {
        setPermissions(res.data)
      }
    } catch (err) {
      setError('Failed to load permissions. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleToggle = (roleId, featureId) => {
    setPermissions(prev => {
      // Find existing
      const existingIdx = prev.findIndex(p => p.role === roleId && p.feature === featureId)
      if (existingIdx >= 0) {
        const next = [...prev]
        next[existingIdx] = { ...next[existingIdx], is_allowed: !next[existingIdx].is_allowed }
        return next
      } else {
        return [...prev, { role: roleId, feature: featureId, is_allowed: true }]
      }
    })
  }

  const isAllowed = (roleId, featureId) => {
    const p = permissions.find(p => p.role === roleId && p.feature === featureId)
    return p ? p.is_allowed : false
  }

  const handleSave = async () => {
    setSaving(true)
    setError('')
    setSuccess('')
    try {
      await api.put('/admin/permissions', { permissions })
      setSuccess('Permissions successfully updated!')
      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setError('Failed to save permissions.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-full text-text-muted">
      <Loader2 className="w-8 h-8 animate-spin text-accent-primary" />
    </div>
  )

  return (
    <div className="max-w-6xl mx-auto pb-12 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-text-primary flex items-center gap-3">
            <Shield className="w-8 h-8 text-accent-primary" />
            Role & Feature Permissions
          </h1>
          <p className="text-text-muted mt-2">
            Control which features are accessible by Analysts and Viewers. Admins always have full access.
          </p>
        </div>
        <button
          onClick={handleSave}
          disabled={saving}
          className={clsx(
            "flex items-center gap-2 px-6 py-2.5 rounded-xl font-medium transition-all shadow-lg",
            "bg-accent-primary hover:bg-accent-primary/90 text-dark-950",
            saving && "opacity-70 cursor-not-allowed"
          )}
        >
          {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
          {saving ? 'Saving...' : 'Save Permissions'}
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-500/10 border border-green-500/20 text-green-400 p-4 rounded-xl flex items-center gap-3">
          <CheckCircle className="w-5 h-5 shrink-0" />
          {success}
        </div>
      )}

      <div className="bg-bg-card border border-border-light rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-bg-panel border-b border-border-light">
                <th className="p-4 font-semibold text-text-primary">Feature Module</th>
                {ROLES.map(role => (
                  <th key={role.id} className="p-4 text-center">
                    <span className={clsx(
                      "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide",
                      role.color === 'blue' ? "bg-blue-500/20 text-blue-400 border border-blue-500/30" :
                      "bg-purple-500/20 text-purple-400 border border-purple-500/30"
                    )}>
                      {role.label}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light/50">
              {FEATURES.map(feature => (
                <tr key={feature.id} className="hover:bg-bg-panel/30 transition-colors">
                  <td className="p-4">
                    <div className="font-medium text-text-primary">{feature.label}</div>
                    <div className="text-sm text-text-muted mt-1">{feature.desc}</div>
                  </td>
                  {ROLES.map(role => (
                    <td key={role.id} className="p-4 text-center align-middle">
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          className="sr-only peer"
                          checked={isAllowed(role.id, feature.id)}
                          onChange={() => handleToggle(role.id, feature.id)}
                        />
                        <div className={clsx(
                          "w-11 h-6 bg-dark-600 peer-focus:outline-none rounded-full peer",
                          "peer-checked:after:translate-x-full peer-checked:after:border-white",
                          "after:content-[''] after:absolute after:top-[2px] after:left-[2px]",
                          "after:bg-white after:border-gray-300 after:border after:rounded-full",
                          "after:h-5 after:w-5 after:transition-all",
                          role.color === 'blue' ? "peer-checked:bg-blue-500" : "peer-checked:bg-purple-500"
                        )}></div>
                      </label>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
