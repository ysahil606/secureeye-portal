import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bug, ExternalLink } from 'lucide-react'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import { cvssColor, formatDateTime } from '../utils/helpers'

const STATUS_COLORS = {
  'Exploited in the Wild': 'text-red-400 bg-red-900/30 border-red-700/40',
  'Patch Available': 'text-yellow-400 bg-yellow-900/30 border-yellow-700/40',
  'Mitigated': 'text-green-400 bg-green-900/30 border-green-700/40',
  'Under Investigation': 'text-blue-400 bg-blue-900/30 border-blue-700/40',
}

export default function ZeroDayTracker() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/advisories', { params: { is_zero_day: true, per_page: 100 } })
      .then(r => setItems(r.data.items || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="flex justify-center py-20"><div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" /></div>

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Bug className="w-6 h-6 text-red-400" /> Zero-Day Tracker
        </h1>
        <p className="text-slate-400 text-sm mt-0.5">{items.length} unpatched zero-days tracked</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {['Exploited in the Wild', 'Patch Available', 'Mitigated', 'Under Investigation'].map(status => {
          const count = items.filter(i => i.zero_day_status === status).length
          const cls = STATUS_COLORS[status] || 'text-slate-400 bg-dark-800 border-dark-600'
          return (
            <div key={status} className={`card p-4 border ${cls.split(' ').slice(2).join(' ')}`}>
              <div className={`text-2xl font-bold ${cls.split(' ')[0]}`}>{count}</div>
              <div className="text-xs text-slate-400 mt-0.5">{status}</div>
            </div>
          )
        })}
      </div>

      {items.length === 0 ? (
        <div className="card p-12 text-center text-slate-500">No zero-day vulnerabilities tracked yet. Tag advisories as Zero-Day when creating them.</div>
      ) : (
        <div className="space-y-3">
          {items.map(adv => (
            <Link key={adv.id} to={`/advisories/${adv.id}`}
              className="card block p-4 hover:border-red-500/50 transition-all">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <SeverityBadge severity={adv.severity} />
                    {adv.zero_day_status && (
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${STATUS_COLORS[adv.zero_day_status] || 'text-slate-400 border-dark-600'}`}>
                        {adv.zero_day_status}
                      </span>
                    )}
                    {adv.is_kev && <span className="badge-critical text-xs">CISA KEV</span>}
                  </div>
                  <h3 className="font-semibold text-white">{adv.title}</h3>
                  {adv.cve_ids?.length > 0 && (
                    <div className="flex gap-1 mt-1">
                      {adv.cve_ids.map(c => <span key={c} className="text-xs font-mono text-blue-400">{c}</span>)}
                    </div>
                  )}
                  {adv.affected_vendors?.length > 0 && (
                    <div className="text-xs text-slate-500 mt-1">
                      Affected: {adv.affected_vendors.join(', ')}
                    </div>
                  )}
                </div>
                <div className="text-right flex-shrink-0">
                  {adv.cvss_score && <div className={`text-2xl font-bold ${cvssColor(adv.cvss_score)}`}>{adv.cvss_score}</div>}
                  <div className="text-xs text-slate-500 mt-1">{formatDateTime(adv.created_at)}</div>
                  {adv.source_url && (
                    <a href={adv.source_url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                      className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 mt-1 justify-end">
                      <ExternalLink className="w-3 h-3" /> Source
                    </a>
                  )}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
