// ThreatTimeline.jsx
import { useEffect, useState } from 'react'
import { Clock, AlertTriangle } from 'lucide-react'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import { formatDateTime, cvssColor } from '../utils/helpers'
import { Link } from 'react-router-dom'

import toast from 'react-hot-toast'

export function ThreatTimeline() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({ source: '', is_critical: '' })

  useEffect(() => {
    setLoading(true)
    const params = {}
    if (filters.source) params.source = filters.source
    if (filters.is_critical) params.is_critical = filters.is_critical

    api.get('/advisories/timeline', { params })
      .then(r => setItems(r.data.items || []))
      .catch((err) => {
        console.error('Timeline error:', err.response?.data || err.message)
        toast.error('Failed to load timeline')
      })
      .finally(() => setLoading(false))
  }, [filters])

  if (loading) return <div className="flex justify-center py-20"><div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" /></div>

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Timeline</h1>
          <p className="text-slate-400 text-sm mt-0.5">Chronological view of all published advisories</p>
        </div>
        <div className="flex gap-3">
          <select 
            className="input w-auto text-sm" 
            value={filters.source} 
            onChange={e => setFilters(f => ({ ...f, source: e.target.value }))}
          >
            <option value="">All Sources</option>
            <option value="manual">Secure</option>
            <option value="external">Open Source</option>
          </select>
          <select 
            className="input w-auto text-sm" 
            value={filters.is_critical} 
            onChange={e => setFilters(f => ({ ...f, is_critical: e.target.value }))}
          >
            <option value="">All Severities</option>
            <option value="true">Critical Only</option>
          </select>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="card p-12 text-center text-slate-500">No published advisories yet. Publish advisories to see them here.</div>
      ) : (
        <div className="relative">
          <div className="absolute left-6 top-0 bottom-0 w-px bg-dark-600" />
          <div className="space-y-4">
            {items.map((adv, i) => (
              <div key={adv.id} className="relative flex gap-5 pl-14">
                <div className={`absolute left-4 top-4 w-4 h-4 rounded-full border-2 flex-shrink-0 ${adv.is_critical_alert ? 'bg-red-500 border-red-400' : 'bg-dark-700 border-dark-500'}`} />
                <Link to={`/advisories/${adv.id}`} className="card flex-1 p-4 hover:border-blue-500/50 transition-all">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={adv.severity} />
                        {adv.is_critical_alert && <span className="text-xs text-red-400 font-semibold flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Critical</span>}
                      </div>
                      <h3 className="font-medium text-white text-sm">{adv.title}</h3>
                      {adv.cve_ids?.length > 0 && (
                        <div className="flex gap-1 mt-1">
                          {adv.cve_ids.slice(0, 2).map(c => (
                            <span key={c} className="text-xs font-mono text-blue-400">{c}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="text-right flex-shrink-0">
                      {adv.cvss_score && <div className={`text-lg font-bold ${cvssColor(adv.cvss_score)}`}>{adv.cvss_score}</div>}
                      <div className="text-xs text-slate-500 flex items-center gap-1 mt-1">
                        <Clock className="w-3 h-3" /> {formatDateTime(adv.published_at)}
                      </div>
                    </div>
                  </div>
                </Link>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default ThreatTimeline
