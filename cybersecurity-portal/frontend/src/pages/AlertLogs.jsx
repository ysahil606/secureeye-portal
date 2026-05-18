import { useEffect, useState } from 'react'
import { Bell, CheckCircle, XCircle, Mail, Hash } from 'lucide-react'
import api from '../services/api'
import { formatDateTime } from '../utils/helpers'

const CHANNEL_ICONS = { email: Mail, slack: Hash, teams: Hash }
const CHANNEL_COLORS = { email: 'text-blue-400', slack: 'text-purple-400', teams: 'text-cyan-400' }

export default function AlertLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/admin/feeds/logs', { params: { limit: 100 } })
      .then(r => setLogs(r.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  // Also load alert logs from advisories
  const [alertLogs, setAlertLogs] = useState([])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Bell className="w-6 h-6 text-yellow-400" /> Alert & Feed Logs
        </h1>
        <p className="text-slate-400 text-sm mt-0.5">History of automated threat feed runs and alert dispatches</p>
      </div>

      {/* Feed Logs */}
      <div>
        <h2 className="text-base font-semibold text-white mb-3 px-1 md:px-0">Feed Ingestion Logs</h2>
        {loading ? (
          <div className="flex justify-center py-8">
            <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
          </div>
        ) : logs.length === 0 ? (
          <div className="card p-8 text-center text-slate-500">No feed runs yet. Click "Run Feeds Now" on the Dashboard.</div>
        ) : (
          <>
            {/* Mobile View: Cards */}
            <div className="space-y-3 md:hidden">
              {logs.map(log => (
                <div key={log.id} className="card p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-blue-400 font-bold uppercase tracking-tight">{log.feed_source}</span>
                    <span className="text-[10px] text-slate-500">{formatDateTime(log.run_at)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {log.status === 'success' ? (
                        <div className="flex items-center gap-1 text-green-400 text-xs font-semibold">
                          <CheckCircle className="w-3.5 h-3.5" /> Success
                        </div>
                      ) : (
                        <div className="flex items-center gap-1 text-red-400 text-xs font-semibold">
                          <XCircle className="w-3.5 h-3.5" /> Error
                        </div>
                      )}
                    </div>
                    <div className="flex gap-4">
                      <div className="text-center">
                        <div className="text-xs text-slate-300 font-bold">{log.items_fetched ?? 0}</div>
                        <div className="text-[9px] text-slate-500 uppercase">Fetched</div>
                      </div>
                      <div className="text-center">
                        <div className="text-xs text-green-400 font-bold">{log.items_new ?? 0}</div>
                        <div className="text-[9px] text-slate-500 uppercase">New</div>
                      </div>
                    </div>
                  </div>
                  {log.error_msg && (
                    <div className="text-[10px] text-red-400 bg-red-400/5 p-2 rounded border border-red-400/20 italic">
                      {log.error_msg}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Desktop View: Table */}
            <div className="card hidden md:block overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-dark-800 border-b border-dark-600">
                    <tr>
                      {['Source', 'Status', 'Fetched', 'New', 'Duplicates', 'Run At', 'Error'].map(h => (
                        <th key={h} className="text-left px-4 py-3 text-xs uppercase tracking-wider text-slate-500">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-600">
                    {logs.map(log => (
                      <tr key={log.id} className="hover:bg-dark-700/50 transition-colors">
                        <td className="px-4 py-3 font-mono text-xs text-slate-300 font-semibold">{log.feed_source}</td>
                        <td className="px-4 py-3">
                          {log.status === 'success'
                            ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" /> Success</span>
                            : log.status === 'error'
                            ? <span className="flex items-center gap-1 text-red-400 text-xs"><XCircle className="w-3.5 h-3.5" /> Error</span>
                            : <span className="text-yellow-400 text-xs">{log.status}</span>
                          }
                        </td>
                        <td className="px-4 py-3 text-slate-300">{log.items_fetched ?? '—'}</td>
                        <td className="px-4 py-3 text-green-400 font-semibold">{log.items_new ?? '—'}</td>
                        <td className="px-4 py-3 text-slate-500">{log.items_duplicate ?? '—'}</td>
                        <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{formatDateTime(log.run_at)}</td>
                        <td className="px-4 py-3 text-red-400 text-xs max-w-[200px] truncate">{log.error_msg || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
