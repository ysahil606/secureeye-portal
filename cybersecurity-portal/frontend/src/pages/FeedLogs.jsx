import { useEffect, useState } from 'react'
import { Cpu, Play, CheckCircle, XCircle, RefreshCw } from 'lucide-react'
import api from '../services/api'
import { formatDateTime } from '../utils/helpers'
import { useAuth } from '../context/AuthContext'
import toast from 'react-hot-toast'

export default function FeedLogs() {
  const { isAnalyst } = useAuth()
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)

  const load = () => {
    setLoading(true)
    api.get('/admin/feeds/logs', { params: { limit: 200 } })
      .then(r => setLogs(r.data))
      .catch(() => toast.error('Failed to load logs'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const runNow = async () => {
    setRunning(true)
    try {
      await api.post('/admin/feeds/run')
      toast.success('Feed ingestion triggered! Refresh in ~30s to see results.')
      setTimeout(load, 5000)
    } catch { toast.error('Failed to trigger feeds') }
    finally { setRunning(false) }
  }

  const grouped = logs.reduce((acc, log) => {
    const key = log.feed_source
    if (!acc[key]) acc[key] = []
    acc[key].push(log)
    return acc
  }, {})

  const sources = Object.keys(grouped)
  const lastRuns = sources.map(s => ({ source: s, last: grouped[s][0] }))

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Cpu className="w-6 h-6 text-blue-400" /> Feed Management
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">Automated threat feed ingestion status</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="btn-ghost flex items-center gap-2 text-sm">
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
          {isAnalyst && (
            <button onClick={runNow} disabled={running} className="btn-primary flex items-center gap-2 text-sm">
              <Play className="w-4 h-4" /> {running ? 'Running…' : 'Run All Feeds Now'}
            </button>
          )}
        </div>
      </div>

      {/* Source summary */}
      {lastRuns.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {lastRuns.map(({ source, last }) => (
            <div key={source} className="card p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-sm text-slate-300 font-semibold">{source}</span>
                {last.status === 'success'
                  ? <CheckCircle className="w-4 h-4 text-green-400" />
                  : <XCircle className="w-4 h-4 text-red-400" />}
              </div>
              <div className="grid grid-cols-3 gap-2 text-center text-xs">
                <div><div className="text-slate-300 font-bold">{last.items_fetched ?? '—'}</div><div className="text-slate-500">Fetched</div></div>
                <div><div className="text-green-400 font-bold">{last.items_new ?? '—'}</div><div className="text-slate-500">New</div></div>
                <div><div className="text-slate-500 font-bold">{last.items_duplicate ?? '—'}</div><div className="text-slate-500">Dupes</div></div>
              </div>
              <div className="text-xs text-slate-500 mt-2 text-center">{formatDateTime(last.run_at)}</div>
            </div>
          ))}
        </div>
      )}

      {/* Full log table */}
      <div>
        <h2 className="text-base font-semibold text-white mb-3">Full Run History</h2>
        {loading ? (
          <div className="flex justify-center py-8"><div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" /></div>
        ) : logs.length === 0 ? (
          <div className="card p-8 text-center text-slate-500">No feed runs recorded yet.</div>
        ) : (
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-dark-800 border-b border-dark-600">
                  <tr>
                    {['#', 'Source', 'Status', 'Fetched', 'New', 'Dupes', 'Run At', 'Error'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs uppercase tracking-wider text-slate-500">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-600">
                  {logs.map(log => (
                    <tr key={log.id} className="hover:bg-dark-700/50 transition-colors">
                      <td className="px-4 py-2.5 text-slate-600 text-xs">{log.id}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-slate-300">{log.feed_source}</td>
                      <td className="px-4 py-2.5">
                        {log.status === 'success'
                          ? <span className="text-green-400 text-xs flex items-center gap-1"><CheckCircle className="w-3 h-3" /> OK</span>
                          : <span className="text-red-400 text-xs flex items-center gap-1"><XCircle className="w-3 h-3" /> Error</span>}
                      </td>
                      <td className="px-4 py-2.5 text-slate-400">{log.items_fetched ?? '—'}</td>
                      <td className="px-4 py-2.5 text-green-400 font-semibold">{log.items_new ?? '—'}</td>
                      <td className="px-4 py-2.5 text-slate-500">{log.items_duplicate ?? '—'}</td>
                      <td className="px-4 py-2.5 text-slate-400 text-xs whitespace-nowrap">{formatDateTime(log.run_at)}</td>
                      <td className="px-4 py-2.5 text-red-400 text-xs max-w-[180px] truncate">{log.error_msg || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
