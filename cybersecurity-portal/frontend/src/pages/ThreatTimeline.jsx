// ThreatTimeline.jsx
import { useEffect, useState } from 'react'
import { Clock, AlertTriangle, Activity, Filter, Radar, Globe, FileText, ChevronRight, ExternalLink } from 'lucide-react'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import { formatDateTime, cvssColor } from '../utils/helpers'
import { Link } from 'react-router-dom'
import toast from 'react-hot-toast'
import clsx from 'clsx'

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

  const truncate = (str, n) => (str?.length > n ? str.slice(0, n - 1) + '...' : str);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-32 space-y-4">
        <div className="relative w-16 h-16">
          <div className="absolute inset-0 rounded-full border-2 border-blue-500/20" />
          <div className="absolute inset-0 rounded-full border-t-2 border-blue-500 animate-spin" />
          <div className="absolute inset-0 rounded-full border-r-2 border-purple-500 animate-spin" style={{ animationDuration: '1.5s', animationDirection: 'reverse' }} />
          <Activity className="absolute inset-0 m-auto w-6 h-6 text-cyan-400 animate-pulse" />
        </div>
        <div className="text-cyan-500/80 font-mono text-sm tracking-widest uppercase animate-pulse">Syncing Timeline</div>
      </div>
    )
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-700">
      
      {/* Premium Header */}
      <div className="relative flex flex-col md:flex-row md:items-center justify-between gap-6 bg-dark-900/60 backdrop-blur-2xl p-6 rounded-3xl border border-white/5 shadow-2xl overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-bl from-blue-500/10 to-purple-500/10 blur-3xl rounded-full pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-gradient-to-tr from-cyan-500/10 to-emerald-500/10 blur-3xl rounded-full pointer-events-none" />
        
        <div className="relative z-10 flex items-center gap-5">
          <div className="relative flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-900/40 to-purple-900/40 border border-white/10 shadow-[0_0_30px_rgba(59,130,246,0.15)] group">
            <Radar className="w-7 h-7 text-blue-400 group-hover:text-cyan-300 transition-colors" />
            <div className="absolute inset-0 bg-blue-400/20 blur-xl rounded-2xl opacity-50 group-hover:opacity-100 transition-opacity animate-pulse" />
          </div>
          <div>
            <h1 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-blue-100 to-cyan-300 tracking-tight">
              Threat Timeline
            </h1>
          </div>
        </div>

        <div className="relative z-10 flex items-center gap-3">
          <div className="relative group">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-cyan-400 transition-colors" />
            <select 
              className="appearance-none bg-dark-950/80 border border-white/10 text-slate-300 text-sm rounded-xl pl-10 pr-10 py-2.5 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all cursor-pointer hover:bg-dark-900 shadow-inner" 
              value={filters.source} 
              onChange={e => setFilters(f => ({ ...f, source: e.target.value }))}
            >
              <option value="">All Sources</option>
              <option value="manual">Secure</option>
              <option value="external">Open Source</option>
            </select>
          </div>
          <div className="relative group">
            <AlertTriangle className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-red-400 transition-colors" />
            <select 
              className="appearance-none bg-dark-950/80 border border-white/10 text-slate-300 text-sm rounded-xl pl-10 pr-10 py-2.5 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/50 transition-all cursor-pointer hover:bg-dark-900 shadow-inner" 
              value={filters.is_critical} 
              onChange={e => setFilters(f => ({ ...f, is_critical: e.target.value }))}
            >
              <option value="">All Severities</option>
              <option value="true">Critical Only</option>
            </select>
          </div>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="relative overflow-hidden bg-dark-900/40 border border-white/5 rounded-3xl p-16 text-center shadow-inner animate-in slide-in-from-bottom-8">
          <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-10" />
          <Radar className="w-12 h-12 text-slate-600 mx-auto mb-4 animate-[spin_4s_linear_infinite]" />
          <h3 className="text-lg font-bold text-slate-300 mb-1">No Active Threats</h3>
          <p className="text-slate-500">The chronological stream is currently clear.</p>
        </div>
      ) : (
        <div className="relative pl-4 md:pl-10 pb-10">
          {/* Glowing Vertical Timeline Path */}
          <div className="absolute left-[1.65rem] md:left-[3.15rem] top-8 bottom-0 w-[2px] bg-gradient-to-b from-cyan-500 via-purple-500/50 to-transparent shadow-[0_0_15px_rgba(6,182,212,0.8)]" />
          
          <div className="space-y-8">
            {items.map((adv, i) => (
              <div 
                key={adv.id} 
                className="relative flex gap-6 md:gap-10 items-start group animate-in slide-in-from-right-12 fade-in duration-700 fill-mode-both"
                style={{ animationDelay: `${i * 100}ms` }}
              >
                {/* Horizontal Tracking Line (Hover Effect) */}
                <div className="absolute left-[1.65rem] md:left-[3.15rem] top-[1.3rem] w-0 h-px bg-cyan-400/50 group-hover:w-8 md:group-hover:w-10 transition-all duration-500 z-0" />

                {/* Animated Node */}
                <div className="relative flex-shrink-0 z-10 mt-3">
                  <div className={clsx(
                    "w-5 h-5 rounded-full border-[3px] flex items-center justify-center transition-all duration-300 group-hover:scale-125 shadow-xl",
                    adv.is_critical_alert 
                      ? "bg-dark-950 border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.6)]" 
                      : "bg-dark-950 border-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.4)]"
                  )}>
                    <div className={clsx(
                      "w-1.5 h-1.5 rounded-full animate-ping",
                      adv.is_critical_alert ? "bg-red-400" : "bg-cyan-300"
                    )} />
                  </div>
                </div>

                {/* Premium Card */}
                <Link 
                  to={`/advisories/${adv.id}`} 
                  className="relative flex-1 block group/card"
                >
                  <div className={clsx(
                    "absolute -inset-[1px] rounded-3xl blur-md opacity-0 group-hover/card:opacity-100 transition-opacity duration-700",
                    adv.is_critical_alert ? "bg-gradient-to-r from-red-600/50 to-orange-600/50" : "bg-gradient-to-r from-cyan-600/50 to-blue-600/50"
                  )} />
                  
                  <div className="relative bg-dark-900/80 backdrop-blur-xl border border-white/10 rounded-[1.4rem] p-5 md:p-6 shadow-xl transition-all duration-500 group-hover/card:-translate-y-1 group-hover/card:bg-dark-900/95 overflow-hidden">
                    {/* Left Accent Bar */}
                    <div className={clsx(
                      "absolute left-0 top-0 bottom-0 w-1.5 transition-all duration-500",
                      adv.is_critical_alert ? "bg-red-500 shadow-[0_0_20px_rgba(239,68,68,1)]" : "bg-blue-500 opacity-50 group-hover/card:opacity-100 group-hover/card:shadow-[0_0_20px_rgba(59,130,246,1)]"
                    )} />

                    <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                      <div className="space-y-4 flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <SeverityBadge severity={adv.severity} />
                          {adv.source === 'external' ? (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-[0.2em] bg-white/5 text-slate-300 border border-white/10 shadow-sm">
                              <Globe className="w-3 h-3 text-blue-400" /> Open Source Intel
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-[0.2em] bg-purple-500/10 text-purple-300 border border-purple-500/30 shadow-sm">
                              <FileText className="w-3 h-3" /> Internal Advisory
                            </span>
                          )}
                          
                          {adv.is_critical_alert && (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest bg-red-500/10 text-red-400 border border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.2)] animate-pulse ml-1">
                              <AlertTriangle className="w-3 h-3" /> Critical Alert
                            </span>
                          )}
                        </div>
                        
                        <div>
                          <h3 className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-300 group-hover/card:from-white group-hover/card:to-cyan-200 transition-all leading-snug">
                            {adv.title}
                          </h3>
                          {(adv.summary || adv.description) && (
                            <p className="text-[13px] text-slate-400 mt-2 font-medium leading-relaxed max-w-4xl text-justify hyphens-auto">
                              {truncate((adv.summary || adv.description).replace(/<[^>]+>/g, ' '), 200)}
                            </p>
                          )}
                        </div>

                        <div className="flex flex-wrap items-center gap-4 mt-2">
                          {adv.cve_ids?.length > 0 && (
                            <div className="flex gap-1.5">
                              {adv.cve_ids.slice(0, 3).map(c => (
                                <span key={c} className="text-[10px] font-black tracking-widest text-cyan-300 bg-cyan-950/40 px-2 py-1 rounded border border-cyan-800/50 shadow-inner flex items-center gap-1">
                                  <ExternalLink className="w-3 h-3 text-cyan-500/50" /> {c}
                                </span>
                              ))}
                            </div>
                          )}
                          
                          {adv.source_url && (
                            <span className="text-[11px] font-mono text-blue-400/80 truncate max-w-[200px] flex items-center gap-1.5">
                              <div className="w-1 h-1 rounded-full bg-blue-500 animate-pulse" />
                              {new URL(adv.source_url).hostname.replace('www.', '')}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex flex-row md:flex-col items-center md:items-end justify-between md:justify-between h-full flex-shrink-0 pt-1 md:pt-0 border-t border-white/5 md:border-t-0 mt-3 md:mt-0 min-w-[120px]">
                        {adv.cvss_score ? (
                          <div className="flex flex-col items-start md:items-end bg-dark-950/40 p-3 rounded-2xl border border-white/5 w-full text-right">
                            <div className={`text-2xl font-black drop-shadow-md ${cvssColor(adv.cvss_score)}`}>{adv.cvss_score}</div>
                            <div className="text-[9px] font-black uppercase tracking-widest text-slate-500">Threat Score</div>
                          </div>
                        ) : (
                          <div className="flex flex-col items-start md:items-end bg-dark-950/40 p-3 rounded-2xl border border-white/5 w-full text-right">
                            <div className="text-xl font-black text-slate-600">--</div>
                            <div className="text-[9px] font-black uppercase tracking-widest text-slate-500">Unscored</div>
                          </div>
                        )}
                        
                        <div className="flex flex-col items-end gap-3 mt-4 w-full">
                          <div className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-widest text-slate-400 bg-dark-950/50 px-3 py-1.5 rounded-lg border border-white/5 whitespace-nowrap">
                            <Clock className="w-3.5 h-3.5 text-cyan-500/70" /> 
                            {formatDateTime(adv.published_at)}
                          </div>
                          
                          <div className="text-xs font-black uppercase tracking-widest text-blue-400 group-hover/card:text-cyan-300 transition-colors flex items-center gap-1 mt-2">
                            View Advisory <ChevronRight className="w-4 h-4 group-hover/card:translate-x-1 transition-transform" />
                          </div>
                        </div>
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
