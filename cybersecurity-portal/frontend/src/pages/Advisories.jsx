import { useEffect, useState, useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Plus, Filter, RefreshCw, ChevronLeft, ChevronRight, ShieldAlert, Activity, Crosshair, AlertTriangle } from 'lucide-react'
import api from '../services/api'
import AdvisoryCard from '../components/AdvisoryCard'
import CyberBriefingPlayer from '../components/CyberBriefingPlayer'
import { useAuth } from '../context/AuthContext'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'informational']
const STATUSES = ['', 'pending', 'published', 'archived', 'rejected']

export default function Advisories() {
  const { isAnalyst } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [data, setData] = useState({ items: [], total: 0, page: 1, total_pages: 1 })
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(parseInt(searchParams.get('page')) || 1)
  const [sectors, setSectors] = useState([])
  
  const [filters, setFilters] = useState({
    status: searchParams.get('status') || '',
    severity: searchParams.get('severity') || '',
    sector_id: searchParams.get('sector_id') || '',
    source: searchParams.get('source') || '',
    is_kev: searchParams.get('is_kev') || '',
    is_zero_day: searchParams.get('is_zero_day') || '',
    is_critical: searchParams.get('is_critical') || '',
    mitre_ttp: searchParams.get('mitre_ttp') || ''
  })

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const activeFilters = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== ''))
      const params = { page, per_page: 20, ...activeFilters }
      const r = await api.get('/advisories', { params })
      setData(r.data)
      
      const newParams = { ...activeFilters }
      if (page > 1) newParams.page = page
      setSearchParams(newParams, { replace: true })
    } catch { toast.error('Failed to load advisories') }
    finally { setLoading(false) }
  }, [page, filters, setSearchParams])

  useEffect(() => { fetchData() }, [fetchData])
  useEffect(() => {
    api.get('/admin/sectors').then(r => setSectors(r.data)).catch(() => {})
  }, [])

  const setFilter = (k, v) => { setFilters(f => ({ ...f, [k]: v })); setPage(1) }
  const visibleStatuses = isAnalyst ? STATUSES : ['', 'published', 'archived']

  return (
    <div className="space-y-8 pb-10">
      <CyberBriefingPlayer />
      
      {/* Hero Header */}
      <div className="relative p-[1px] rounded-3xl overflow-hidden group">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/30 via-cyan-500/20 to-purple-600/30 blur-xl opacity-50 group-hover:opacity-70 transition-opacity duration-700" />
        <div className="relative bg-dark-900/90 backdrop-blur-2xl rounded-[23px] p-8 md:p-10 border border-white/5 shadow-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 overflow-hidden">
          {/* Background Decorative Rings */}
          <div className="absolute -right-20 -top-20 w-64 h-64 border-[40px] border-blue-500/10 rounded-full blur-2xl" />
          <div className="absolute -left-20 -bottom-20 w-64 h-64 border-[40px] border-cyan-500/10 rounded-full blur-2xl" />
          
          <div className="relative z-10">
            <div className="inline-flex items-center gap-2 px-3 py-1 mb-4 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-bold uppercase tracking-widest">
              <Crosshair className="w-3.5 h-3.5" /> Threat Intelligence Feed
            </div>
            <h1 className="text-4xl md:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white to-slate-400 tracking-tight">
              Advisories
            </h1>
            <p className="text-slate-400 font-medium mt-3 text-lg flex items-center gap-2">
              Tracking <span className="text-white font-bold bg-dark-800 px-2.5 py-1 rounded-md border border-dark-600">{data.total}</span> active threats & vulnerabilities.
            </p>
          </div>
          
          <div className="relative z-10 flex flex-wrap gap-3">
            <button onClick={fetchData} className="bg-dark-800 hover:bg-dark-700 text-white border border-dark-600 hover:border-dark-500 font-bold px-5 py-3 rounded-xl transition-all shadow-lg flex items-center gap-2 text-sm uppercase tracking-wider">
              <RefreshCw className={clsx("w-4 h-4", loading && "animate-spin text-blue-400")} /> Sync
            </button>
            {isAnalyst && (
              <Link to="/advisories/new" className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-black px-6 py-3 rounded-xl transition-all shadow-neon-blue flex items-center gap-2 text-sm uppercase tracking-wider hover:scale-105">
                <Plus className="w-4 h-4" /> New Advisory
              </Link>
            )}
          </div>
        </div>
      </div>

      {/* Futuristic Filters */}
      <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 p-5 rounded-2xl shadow-lg sticky top-2 z-20">
        <div className="flex flex-col xl:flex-row gap-5 items-start xl:items-center">
          
          {/* Toggles (Zero Day, KEV, Critical) */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 px-3">
              <Filter className="w-4 h-4 text-slate-500" />
              <span className="text-xs font-bold text-slate-500 uppercase tracking-widest">Filters</span>
            </div>
            
            <button
              onClick={() => setFilter('is_critical', filters.is_critical === 'true' ? '' : 'true')}
              className={clsx(
                "flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all border",
                filters.is_critical === 'true' 
                  ? "bg-red-500/20 text-red-400 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.3)]" 
                  : "bg-dark-800 text-slate-400 border-dark-600 hover:bg-dark-700"
              )}>
              <ShieldAlert className="w-3.5 h-3.5" /> Critical Only
            </button>

            <button
              onClick={() => setFilter('is_zero_day', filters.is_zero_day === 'true' ? '' : 'true')}
              className={clsx(
                "flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all border",
                filters.is_zero_day === 'true' 
                  ? "bg-orange-500/20 text-orange-400 border-orange-500/50 shadow-[0_0_15px_rgba(249,115,22,0.3)]" 
                  : "bg-dark-800 text-slate-400 border-dark-600 hover:bg-dark-700"
              )}>
              <AlertTriangle className="w-3.5 h-3.5" /> 0-Day
            </button>
            
            <button
              onClick={() => setFilter('is_kev', filters.is_kev === 'true' ? '' : 'true')}
              className={clsx(
                "flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all border",
                filters.is_kev === 'true' 
                  ? "bg-purple-500/20 text-purple-400 border-purple-500/50 shadow-[0_0_15px_rgba(168,85,247,0.3)]" 
                  : "bg-dark-800 text-slate-400 border-dark-600 hover:bg-dark-700"
              )}>
              <Activity className="w-3.5 h-3.5" /> KEV
            </button>
          </div>

          <div className="hidden xl:block w-px h-8 bg-dark-600 mx-2" />

          {/* Select Dropdowns */}
          <div className="flex flex-wrap items-center gap-3 flex-1">
            <select className="bg-dark-800 border-dark-600 text-slate-300 rounded-xl px-4 py-2 text-sm focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all cursor-pointer font-medium" 
              value={filters.status} onChange={e => setFilter('status', e.target.value)}>
              <option value="">All Statuses</option>
              {visibleStatuses.slice(1).map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
            
            <select className="bg-dark-800 border-dark-600 text-slate-300 rounded-xl px-4 py-2 text-sm focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all cursor-pointer font-medium" 
              value={filters.severity} onChange={e => setFilter('severity', e.target.value)}>
              <option value="">All Severities</option>
              {SEVERITIES.slice(1).map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
            
            <select className="bg-dark-800 border-dark-600 text-slate-300 rounded-xl px-4 py-2 text-sm focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all cursor-pointer font-medium" 
              value={filters.sector_id} onChange={e => setFilter('sector_id', e.target.value)}>
              <option value="">All Sectors</option>
              {sectors.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            
            <select className="bg-dark-800 border-dark-600 text-slate-300 rounded-xl px-4 py-2 text-sm focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all cursor-pointer font-medium" 
              value={filters.source} onChange={e => setFilter('source', e.target.value)}>
              <option value="">All Sources</option>
              <option value="manual">SecureEye (Manual)</option>
              <option value="external">Open Source (External)</option>
            </select>

            {filters.mitre_ttp && (
              <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono font-bold uppercase tracking-wider">
                TTP: {filters.mitre_ttp}
                <button onClick={() => setFilter('mitre_ttp', '')} className="hover:text-white transition-colors ml-1 bg-blue-500/20 rounded-full p-0.5">×</button>
              </div>
            )}
            
            {Object.values(filters).some(v => v) && (
              <button onClick={() => { setFilters({ status: '', severity: '', sector_id: '', source: '', is_kev: '', is_zero_day: '', is_critical: '', mitre_ttp: '' }); setPage(1) }}
                className="text-xs font-bold text-red-400 hover:text-red-300 ml-auto uppercase tracking-widest px-3 py-2 rounded-xl hover:bg-red-500/10 transition-colors">
                Reset Filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* List */}
      {loading ? (
        <div className="py-32 flex flex-col items-center justify-center space-y-6 animate-in zoom-in duration-700">
          <div className="relative">
            <div className="absolute inset-0 bg-blue-500/20 blur-3xl rounded-full" />
            <div className="w-24 h-24 border-[4px] border-dark-700 border-t-cyan-500 rounded-full animate-spin shadow-neon-blue" />
            <div className="absolute inset-0 m-auto w-16 h-16 border-[3px] border-dark-700 border-b-blue-500 rounded-full animate-radar-spin" style={{ animationDirection: 'reverse' }} />
            <Crosshair className="absolute inset-0 m-auto w-6 h-6 text-cyan-400 animate-pulse" />
          </div>
          <div className="text-center space-y-2">
            <h3 className="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400 tracking-[0.2em] uppercase animate-pulse">Syncing Intel Feeds...</h3>
            <p className="text-sm text-slate-400 font-mono">Retrieving latest advisories and threat data.</p>
          </div>
        </div>
      ) : data.items.length === 0 ? (
        <div className="card p-16 flex flex-col items-center justify-center text-center bg-dark-900/50 border-dark-600/50 border-dashed">
          <ShieldAlert className="w-16 h-16 text-dark-500 mb-4" />
          <h3 className="text-xl font-bold text-white mb-2">No Active Threats Found</h3>
          <p className="text-slate-500">There are no advisories matching your current filter configuration.</p>
          {Object.values(filters).some(v => v) && (
            <button onClick={() => setFilters({ status: '', severity: '', sector_id: '', source: '', is_kev: '', is_zero_day: '', is_critical: '', mitre_ttp: '' })} className="mt-6 btn-primary">
              Clear All Filters
            </button>
          )}
        </div>
      ) : (
        <div className="grid gap-4 animate-in fade-in slide-in-from-bottom-8 duration-700 fill-mode-both" style={{ stagger: 0.1 }}>
          {data.items.map((a, i) => (
            <div key={a.id} className="animate-in fade-in slide-in-from-bottom-4 duration-500 fill-mode-both" style={{ animationDelay: `${i * 50}ms` }}>
              <AdvisoryCard advisory={a} />
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {data.total_pages > 1 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-5 rounded-2xl bg-dark-900/40 border border-white/5 mt-6">
          <span className="text-sm font-bold text-slate-400 tracking-wider">
            PAGE <span className="text-white">{data.page}</span> OF <span className="text-white">{data.total_pages}</span> <span className="mx-2 text-dark-600">|</span> <span className="text-blue-400">{data.total}</span> RESULTS
          </span>
          <div className="flex gap-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="bg-dark-800 hover:bg-dark-700 text-white disabled:opacity-30 disabled:hover:bg-dark-800 border border-dark-600 px-4 py-2 rounded-xl text-sm font-bold flex items-center gap-2 transition-all uppercase tracking-wider">
              <ChevronLeft className="w-4 h-4" /> Prev
            </button>
            <button onClick={() => setPage(p => Math.min(data.total_pages, p + 1))} disabled={page === data.total_pages}
              className="bg-dark-800 hover:bg-dark-700 text-white disabled:opacity-30 disabled:hover:bg-dark-800 border border-dark-600 px-4 py-2 rounded-xl text-sm font-bold flex items-center gap-2 transition-all uppercase tracking-wider">
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
