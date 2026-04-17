import { useEffect, useState, useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Plus, Filter, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'
import api from '../services/api'
import AdvisoryCard from '../components/AdvisoryCard'
import { useAuth } from '../context/AuthContext'
import toast from 'react-hot-toast'

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
      
      // Update URL
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
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Advisories</h1>
          <p className="text-slate-400 text-sm mt-0.5">{data.total} total advisories</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchData} className="btn-ghost flex items-center gap-2 text-sm">
            <RefreshCw className="w-4 h-4" /> Refresh
          </button>
          {isAnalyst && (
            <Link to="/advisories/new" className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> New Advisory
            </Link>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-slate-500" />
        <select className="input w-auto text-sm" value={filters.status} onChange={e => setFilter('status', e.target.value)}>
          <option value="">All Statuses</option>
          {visibleStatuses.slice(1).map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
        <select className="input w-auto text-sm" value={filters.severity} onChange={e => setFilter('severity', e.target.value)}>
          <option value="">All Severities</option>
          {SEVERITIES.slice(1).map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
        <select className="input w-auto text-sm" value={filters.sector_id} onChange={e => setFilter('sector_id', e.target.value)}>
          <option value="">All Sectors</option>
          {sectors.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        <select className="input w-auto text-sm" value={filters.source} onChange={e => setFilter('source', e.target.value)}>
          <option value="">All Sources</option>
          <option value="manual">SecureEye (Manual)</option>
          <option value="external">Open Source (External)</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
          <input type="checkbox" className="rounded bg-dark-800 border-dark-600"
            checked={filters.is_kev === 'true'} onChange={e => setFilter('is_kev', e.target.checked ? 'true' : '')} />
          KEV Only
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
          <input type="checkbox" className="rounded bg-dark-800 border-dark-600"
            checked={filters.is_zero_day === 'true'} onChange={e => setFilter('is_zero_day', e.target.checked ? 'true' : '')} />
          Zero-Days
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
          <input type="checkbox" className="rounded bg-dark-800 border-dark-600"
            checked={filters.is_critical === 'true'} onChange={e => setFilter('is_critical', e.target.checked ? 'true' : '')} />
          Critical Only
        </label>
        {filters.mitre_ttp && (
            <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 text-[10px] font-mono font-bold uppercase tracking-wider">
                Technique: {filters.mitre_ttp}
                <button onClick={() => setFilter('mitre_ttp', '')} className="hover:text-blue-200 ml-1">×</button>
            </div>
        )}
        {Object.values(filters).some(v => v) && (
          <button onClick={() => { setFilters({ status: '', severity: '', sector_id: '', source: '', is_kev: '', is_zero_day: '', is_critical: '', mitre_ttp: '' }); setPage(1) }}
            className="text-sm text-red-400 hover:text-red-300 ml-auto">Clear filters</button>
        )}
      </div>

      {/* List */}
      {loading ? (
        <div className="flex justify-center py-12">
          <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
        </div>
      ) : data.items.length === 0 ? (
        <div className="card p-12 text-center text-slate-500">No advisories found matching your filters.</div>
      ) : (
        <div className="space-y-3">
          {data.items.map(a => <AdvisoryCard key={a.id} advisory={a} />)}
        </div>
      )}

      {/* Pagination */}
      {data.total_pages > 1 && (
        <div className="flex items-center justify-between pt-2">
          <span className="text-sm text-slate-400">
            Page {data.page} of {data.total_pages} · {data.total} results
          </span>
          <div className="flex gap-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="btn-ghost text-sm flex items-center gap-1 disabled:opacity-40">
              <ChevronLeft className="w-4 h-4" /> Prev
            </button>
            <button onClick={() => setPage(p => Math.min(data.total_pages, p + 1))} disabled={page === data.total_pages}
              className="btn-ghost text-sm flex items-center gap-1 disabled:opacity-40">
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
