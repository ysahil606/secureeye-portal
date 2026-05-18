import { useEffect, useState } from 'react'
import { Activity, Download, Fingerprint, Lock, RotateCcw, Shield, ShieldCheck, Trash2 } from 'lucide-react'
import { Preferences } from '@capacitor/preferences'
import api from '../services/api'
import toast from 'react-hot-toast'
import AppLock from '../components/AppLock'

export default function SecuritySettings() {
  const [hasPin, setHasPin] = useState(false)
  const [showSetup, setShowSetup] = useState(false)
  const [autoLock, setAutoLock] = useState(() => localStorage.getItem('secureeye_auto_lock') || 'off')
  const [apiHealth, setApiHealth] = useState('unknown')

  useEffect(() => {
    checkStatus()
    checkApiHealth()
  }, [])

  const checkStatus = async () => {
    const { value } = await Preferences.get({ key: 'app_pin' })
    setHasPin(!!value)
  }

  const checkApiHealth = async () => {
    setApiHealth('checking')
    try {
      await api.get('/health')
      setApiHealth('online')
    } catch {
      setApiHealth('offline')
    }
  }

  const updateAutoLock = (value) => {
    setAutoLock(value)
    localStorage.setItem('secureeye_auto_lock', value)
    toast.success('Auto-lock preference saved')
  }

  const removePin = async () => {
    if (confirm('Are you sure you want to disable App Lock?')) {
      await Preferences.remove({ key: 'app_pin' })
      setHasPin(false)
      toast.success('App Lock disabled')
    }
  }

  const clearLocalSecurityData = () => {
    if (!confirm('Clear saved searches, scan history, dark web watchlist, and resolved leak marks?')) return
    ;['secureeye_saved_searches', 'secureeye_recent_searches', 'deepscan_history', 'darkweb_watchlist', 'darkweb_resolved'].forEach(key => localStorage.removeItem(key))
    toast.success('Local security workspace cleared')
  }

  const exportSettings = () => {
    const payload = {
      appLockEnabled: hasPin,
      autoLock,
      apiHealth,
      exportedAt: new Date().toISOString(),
      savedSearches: JSON.parse(localStorage.getItem('secureeye_saved_searches') || '[]'),
      darkwebWatchlist: JSON.parse(localStorage.getItem('darkweb_watchlist') || '[]'),
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'secureeye-security-settings.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  if (showSetup) {
    return (
      <div className="fixed inset-0 z-50 bg-dark-900">
        <div className="p-4">
          <button onClick={() => setShowSetup(false)} className="text-slate-400 hover:text-white">Back</button>
        </div>
        <AppLock onSuccess={() => {
          setHasPin(true)
          setShowSetup(false)
          toast.success('PIN set successfully')
        }} />
      </div>
    )
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <Shield className="w-6 h-6 text-blue-400" />
          Security Center
        </h1>
        <p className="text-slate-400 mt-1">Manage app access, local security data, and backend status.</p>
      </div>

      <div className="grid grid-cols-1 gap-4">
        <div className="card p-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${hasPin ? 'bg-green-500/20 text-green-400' : 'bg-dark-700 text-slate-500'}`}>
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-white">4-Digit PIN Lock</h3>
              <p className="text-xs text-slate-500">{hasPin ? 'App is protected by a PIN' : 'Add an extra layer of security'}</p>
            </div>
          </div>
          {hasPin ? (
            <button onClick={removePin} className="text-red-400 hover:bg-red-500/10 p-2 rounded-lg transition-colors" title="Disable PIN">
              <Trash2 className="w-5 h-5" />
            </button>
          ) : (
            <button onClick={() => setShowSetup(true)} className="btn-primary py-2 px-4 text-xs font-bold">Set PIN</button>
          )}
        </div>

        <div className="card p-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center text-blue-400">
              <RotateCcw className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-white">Auto-Lock Timer</h3>
              <p className="text-xs text-slate-500">Choose when SecureEye should request the app PIN again.</p>
            </div>
          </div>
          <select className="input w-full sm:w-44" value={autoLock} onChange={e => updateAutoLock(e.target.value)}>
            <option value="off">Off</option>
            <option value="5">5 minutes</option>
            <option value="15">15 minutes</option>
            <option value="30">30 minutes</option>
          </select>
        </div>

        <div className="card p-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${apiHealth === 'online' ? 'bg-green-500/20 text-green-400' : apiHealth === 'offline' ? 'bg-red-500/20 text-red-400' : 'bg-dark-700 text-slate-500'}`}>
              <Activity className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-white">Backend Health</h3>
              <p className="text-xs text-slate-500 capitalize">API status: {apiHealth}</p>
            </div>
          </div>
          <button onClick={checkApiHealth} className="btn-ghost text-sm">Recheck</button>
        </div>

        <div className="card p-6 flex items-center justify-between gap-4 opacity-70">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-dark-700 rounded-xl flex items-center justify-center text-slate-500">
              <Fingerprint className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-white">Biometric Auth</h3>
              <p className="text-xs text-slate-500">Prepared for native fingerprint or Face ID support.</p>
            </div>
          </div>
          <div className="w-10 h-6 bg-dark-600 rounded-full relative"><div className="absolute left-1 top-1 w-4 h-4 bg-dark-400 rounded-full" /></div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <button onClick={exportSettings} className="card p-4 flex items-center gap-3 text-left hover:border-blue-500/40 transition-colors">
            <Download className="w-5 h-5 text-blue-400" />
            <span><span className="block text-sm font-bold text-white">Export Security Settings</span><span className="text-xs text-slate-500">Download local preferences and watchlists.</span></span>
          </button>
          <button onClick={clearLocalSecurityData} className="card p-4 flex items-center gap-3 text-left hover:border-red-500/40 transition-colors">
            <Trash2 className="w-5 h-5 text-red-400" />
            <span><span className="block text-sm font-bold text-white">Clear Local Workspace</span><span className="text-xs text-slate-500">Remove saved searches and scan caches.</span></span>
          </button>
        </div>

        <div className="bg-blue-600/10 border border-blue-500/20 rounded-2xl p-5 flex items-start gap-4">
          <ShieldCheck className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <p className="text-xs text-slate-400 leading-relaxed">
            Your App PIN is stored on-device. SecureEye does not send the PIN to the server.
          </p>
        </div>
      </div>
    </div>
  )
}
