import { useState, useEffect } from 'react'
import { Shield, ExternalLink, RefreshCw, Database, Terminal, Network } from 'lucide-react'
import api from '../services/api'

export default function MISPIntegration() {
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [stats, setStats] = useState({ CIRCL: 0, OTX: 0 })
  const [logs, setLogs] = useState([])

  const fetchStatus = async () => {
    try {
      const res = await api.get('/advanced/misp/status')
      setStats(res.data.stats || { CIRCL: 0, OTX: 0 })
      setLogs(res.data.logs || [])
    } catch (err) {
      console.error("Failed to fetch MISP status:", err)
    }
  }

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30000) // refresh every 30s
    return () => clearInterval(interval)
  }, [])

  const handleSync = async () => {
    setSyncing(true)
    try {
      await api.post('/advanced/misp/sync')
      await fetchStatus()
    } catch (err) {
      console.error("Failed to sync MISP:", err)
    } finally {
      setSyncing(false)
    }
  }

  const formatLogTime = (isoString) => {
    if (!isoString) return ''
    const d = new Date(isoString)
    return `[${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}]`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">MISP Integration</h1>
          <p className="text-slate-400 mt-1">Malware Information Sharing Platform & Open Threat Exchange</p>
        </div>
        <button onClick={handleSync} disabled={syncing} className="btn-primary flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
          {syncing ? 'Syncing...' : 'Sync All Instances'}
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card p-6 border-l-4 border-blue-500">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-blue-500" />
            </div>
            <div>
              <h3 className="font-bold text-white">CIRCL MISP OSINT</h3>
              <p className="text-xs text-slate-500">Public OSINT Feed</p>
            </div>
            <span className="ml-auto px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/10 text-green-500 uppercase">Connected</span>
          </div>
          <p className="text-sm text-slate-400 mb-6">
            Pulls high-fidelity IOCs including malicious IPs, domains, and file hashes from the Computer Incident Response Center Luxembourg.
          </p>
          <div className="flex items-center justify-between text-xs">
            <div className="flex gap-4">
              <span className="text-slate-500"><Database className="w-3 h-3 inline mr-1" /> {stats.CIRCL.toLocaleString()} IOCs</span>
              <span className="text-slate-500"><RefreshCw className="w-3 h-3 inline mr-1" /> 15m interval</span>
            </div>
            <a href="https://www.circl.lu/" target="_blank" rel="noreferrer" className="text-blue-400 hover:underline flex items-center gap-1">
              Source <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>

        <div className="card p-6 border-l-4 border-purple-500">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 bg-purple-500/10 rounded-lg flex items-center justify-center">
              <Network className="w-5 h-5 text-purple-500" />
            </div>
            <div>
              <h3 className="font-bold text-white">AlienVault OTX</h3>
              <p className="text-xs text-slate-500">Open Threat Exchange</p>
            </div>
            <span className="ml-auto px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/10 text-green-500 uppercase">Connected</span>
          </div>
          <p className="text-sm text-slate-400 mb-6">
            Synchronizes with AlienVault OTX pulses to ingest community-sourced indicators of compromise and threat actor patterns.
          </p>
          <div className="flex items-center justify-between text-xs">
            <div className="flex gap-4">
              <span className="text-slate-500"><Database className="w-3 h-3 inline mr-1" /> {stats.OTX.toLocaleString()} IOCs</span>
              <span className="text-slate-500"><RefreshCw className="w-3 h-3 inline mr-1" /> 15m interval</span>
            </div>
            <a href="https://otx.alienvault.com/" target="_blank" rel="noreferrer" className="text-blue-400 hover:underline flex items-center gap-1">
              Portal <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="bg-dark-700/50 px-6 py-4 border-b border-dark-600 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-bold text-white uppercase tracking-wider">Live MISP Log Stream</span>
        </div>
        <div className="p-6 font-mono text-xs space-y-2 bg-black/20 max-h-96 overflow-y-auto">
          {logs.length === 0 ? (
            <div className="text-slate-500 italic">No recent sync logs found.</div>
          ) : (
            logs.map(log => (
              <div key={log.id} className="flex gap-3 items-start">
                <span className="text-slate-600 whitespace-nowrap">{formatLogTime(log.timestamp)}</span>
                <span className={log.status === 'success' ? 'text-green-400' : log.status === 'running' ? 'text-blue-400' : 'text-red-400'}>
                  {log.status.toUpperCase()}
                </span>
                <span className="text-slate-300">
                  [{log.source}] {log.status === 'success' ? `Ingested ${log.items_new} new indicators. Duplicates skipped: ${log.items_duplicate}` : log.status === 'error' ? log.error_msg : 'Synchronization in progress...'}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
