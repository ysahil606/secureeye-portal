import { useEffect, useState, useCallback, useRef } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import {
  Plus, Filter, RefreshCw, ChevronLeft, ChevronRight, ShieldAlert,
  Activity, Crosshair, AlertTriangle, Search, X, LayoutGrid,
  List, Zap, Shield, Tag, Clock, ExternalLink, Fingerprint
} from 'lucide-react'
import api from '../services/api'
import AdvisoryCard from '../components/AdvisoryCard'
import CyberBriefingPlayer from '../components/CyberBriefingPlayer'
import SeverityBadge from '../components/SeverityBadge'
import { useAuth } from '../context/AuthContext'
import { timeAgo, cvssColor } from '../utils/helpers'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'informational']
const STATUSES   = ['', 'pending', 'published', 'archived', 'rejected']

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, color, glow }) {
  return (
    <div className={clsx(
      'relative flex items-center gap-3 rounded-xl border border-slate-800/80 bg-slate-900/60 px-4 py-3 backdrop-blur-sm transition-all hover:border-slate-700/80',
      glow
    )}>
      <div className={clsx('p-1.5 rounded-lg border', color.bg, color.border)}>
        <Icon className={clsx('w-4 h-4', color.text)} />
      </div>
      <div>
        <div className={clsx('text-xl font-black leading-none tabular-nums', color.text)}>{value ?? '—'}</div>
        <div className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mt-0.5">{label}</div>
      </div>
    </div>
  )
}

// ── Active filter chip ─────────────────────────────────────────────────────────
function FilterChip({ label, onRemove }) {
  return (
    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-blue-500/10 border border-blue-500/25 text-blue-300 text-[10px] font-bold uppercase tracking-wider">
      {label}
      <button onClick={onRemove} className="hover:text-white transition-colors">
        <X className="w-3 h-3" />
      </button>
    </span>
  )
}

// ── Table row ─────────────────────────────────────────────────────────────────
function AdvisoryRow({ advisory, navigate }) {
  return (
    <tr
      onClick={() => navigate(`/advisories/${advisory.id}`)}
      className="group cursor-pointer border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors"
    >
      <td className="p-3 pl-4">
        <SeverityBadge severity={advisory.severity} />
      </td>
      <td className="p-3 max-w-sm">
        <div className="font-semibold text-sm text-slate-100 group-hover:text-white line-clamp-1 transition-colors">{advisory.title}</div>
        {advisory.cve_ids?.length > 0 && (
          <div className="flex gap-1 mt-1">
            {advisory.cve_ids.slice(0, 2).map(c => (
              <span key={c} className="text-[9px] font-mono text-cyan-500 bg-cyan-950/30 px-1.5 py-0.5 rounded border border-cyan-800/30">{c}</span>
            ))}
            {advisory.cve_ids.length > 2 && <span className="text-[9px] text-slate-600 px-1">+{advisory.cve_ids.length - 2}</span>}
          </div>
        )}
      </td>
      <td className="p-3 text-sm font-black tabular-nums" style={{
        color: advisory.cvss_score >= 9 ? '#ef4444' : advisory.cvss_score >= 7 ? '#f97316' : advisory.cvss_score >= 4 ? '#eab308' : '#22c55e'
      }}>
        {advisory.cvss_score?.toFixed(1) ?? '—'}
      </td>
      <td className="p-3">
        {advisory.affected_vendors?.length > 0 ? (
          <span className="text-xs text-slate-400">{advisory.affected_vendors.slice(0, 2).join(', ')}{advisory.affected_vendors.length > 2 ? ` +${advisory.affected_vendors.length - 2}` : ''}</span>
        ) : <span className="text-slate-700">—</span>}
      </td>
      <td className="p-3">
        <div className="flex flex-wrap gap-1">
          {advisory.is_kev && <span className="text-[9px] font-black px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/25 text-purple-400 uppercase">KEV</span>}
          {advisory.is_zero_day && <span className="text-[9px] font-black px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/25 text-red-400 uppercase">0-Day</span>}
        </div>
      </td>
      <td className="p-3 text-[11px] text-slate-500 font-mono whitespace-nowrap">{timeAgo(advisory.created_at)}</td>
      <td className="p-3 pr-4">
        <ChevronRight className="w-4 h-4 text-slate-700 group-hover:text-blue-400 transition-colors" />
      </td>
    </tr>
  )
}

export default function Advisories() {
  const { isAnalyst } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [data, setData]   = useState({ items: [], total: 0, page: 1, total_pages: 1 })
  const [loading, setLoading] = useState(true)
  const [page, setPage]   = useState(parseInt(searchParams.get('page')) || 1)
  const [sectors, setSectors] = useState([])
  const [view, setView]   = useState('grid') // 'grid' | 'table'
  const [stats, setStats] = useState({ total: 0, critical: 0, zeroday: 0, kev: 0 })
  const [search, setSearch] = useState(searchParams.get('search') || '')
  const searchRef = useRef(null)

  const [filters, setFilters] = useState({
    status:      searchParams.get('status')      || '',
    severity:    searchParams.get('severity')    || '',
    sector_id:   searchParams.get('sector_id')   || '',
    source:      searchParams.get('source')      || '',
    is_kev:      searchParams.get('is_kev')      || '',
    is_zero_day: searchParams.get('is_zero_day') || '',
    is_critical: searchParams.get('is_critical') || '',
    mitre_ttp:   searchParams.get('mitre_ttp')   || '',
  })

  // Debounced search
  useEffect(() => {
    const t = setTimeout(() => { setPage(1) }, 400)
    return () => clearTimeout(t)
  }, [search])

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const active = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== ''))
      const params = { page, per_page: 20, ...active }
      if (search.trim()) params.search = search.trim()
      const r = await api.get('/advisories', { params })
      setData(r.data)
      const newParams = { ...active }
      if (page > 1) newParams.page = page
      if (search.trim()) newParams.search = search.trim()
      setSearchParams(newParams, { replace: true })
    } catch { toast.error('Failed to load advisories') }
    finally { setLoading(false) }
  }, [page, filters, search, setSearchParams])

  // Fetch stats (parallel, independent of main filters)
  const fetchStats = useCallback(async () => {
    try {
      const [total, critical, zeroday, kev] = await Promise.all([
        api.get('/advisories', { params: { per_page: 1 } }),
        api.get('/advisories', { params: { per_page: 1, severity: 'critical' } }),
        api.get('/advisories', { params: { per_page: 1, is_zero_day: true } }),
        api.get('/advisories', { params: { per_page: 1, is_kev: true } }),
      ])
      setStats({
        total:    total.data.total,
        critical: critical.data.total,
        zeroday:  zeroday.data.total,
        kev:      kev.data.total,
      })
    } catch {}
  }, [])

  useEffect(() => { fetchData() }, [fetchData])
  useEffect(() => { fetchStats() }, [fetchStats])
  useEffect(() => {
    api.get('/admin/sectors').then(r => setSectors(r.data)).catch(() => {})
  }, [])

  const setFilter = (k, v) => { setFilters(f => ({ ...f, [k]: v })); setPage(1) }
  const clearAllFilters = () => {
    setFilters({ status: '', severity: '', sector_id: '', source: '', is_kev: '', is_zero_day: '', is_critical: '', mitre_ttp: '' })
    setSearch('')
    setPage(1)
  }
  const visibleStatuses = isAnalyst ? STATUSES : ['', 'published', 'archived']
  const hasFilters = Object.values(filters).some(v => v) || search.trim()

  // Active filter chip labels
  const activeChips = []
  if (filters.severity)    activeChips.push({ key: 'severity',    label: `Severity: ${filters.severity}` })
  if (filters.status)      activeChips.push({ key: 'status',      label: `Status: ${filters.status}` })
  if (filters.sector_id)   activeChips.push({ key: 'sector_id',   label: `Sector: ${sectors.find(s => String(s.id) === filters.sector_id)?.name || filters.sector_id}` })
  if (filters.source)      activeChips.push({ key: 'source',      label: `Source: ${filters.source}` })
  if (filters.is_kev === 'true')      activeChips.push({ key: 'is_kev',      label: 'KEV Only' })
  if (filters.is_zero_day === 'true') activeChips.push({ key: 'is_zero_day', label: '0-Day Only' })
  if (filters.is_critical === 'true') activeChips.push({ key: 'is_critical', label: 'Critical Only' })
  if (filters.mitre_ttp)   activeChips.push({ key: 'mitre_ttp',   label: `TTP: ${filters.mitre_ttp}` })

  // ── Navigate (used for table row clicks) ──────────────────────────────────
  const navigate = useNavigate()

  return (
    <div className="space-y-6 pb-10">
      <CyberBriefingPlayer />

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-5 pb-5 border-b border-white/5">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 mb-3 rounded-full bg-blue-500/10 border border-blue-500/25 text-blue-400 text-[10px] font-black uppercase tracking-widest">
            <Crosshair className="w-3 h-3" /> Threat Intelligence Feed
          </div>
          <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white to-slate-400 tracking-tight">
            Advisories
          </h1>
          <p className="text-slate-500 text-sm mt-1.5">
            Tracking <span className="text-white font-bold">{data.total}</span> active threats &amp; vulnerabilities
          </p>
        </div>
        <div className="flex items-center gap-2 mt-1">
          <button onClick={fetchData} className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 text-sm font-bold transition-all">
            <RefreshCw className={clsx('w-4 h-4', loading && 'animate-spin text-blue-400')} /> Sync
          </button>
          {isAnalyst && (
            <Link to="/advisories/new"
              className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-black px-5 py-2 rounded-xl text-sm uppercase tracking-wider transition-all shadow-lg">
              <Plus className="w-4 h-4" /> New Advisory
            </Link>
          )}
        </div>
      </div>

      {/* ── Stats bar ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard icon={Shield}        label="Total Advisories" value={stats.total}    color={{ text: 'text-slate-200', bg: 'bg-slate-700/50', border: 'border-slate-600/50' }} />
        <StatCard icon={ShieldAlert}   label="Critical Alerts"  value={stats.critical} color={{ text: 'text-red-400',   bg: 'bg-red-500/10',   border: 'border-red-500/25' }}    glow="hover:shadow-red-500/5" />
        <StatCard icon={Zap}           label="Zero-Days Active"  value={stats.zeroday}  color={{ text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/25' }} glow="hover:shadow-orange-500/5" />
        <StatCard icon={Activity}      label="CISA KEV Tracked"  value={stats.kev}      color={{ text: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/25' }} glow="hover:shadow-purple-500/5" />
      </div>

      {/* ── Filter bar ──────────────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 backdrop-blur-xl p-4 sticky top-2 z-20">
        <div className="flex flex-col gap-3">
          {/* Row 1: search + view toggle */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
              <input
                ref={searchRef}
                type="text"
                placeholder="Search advisories, CVE IDs, vendors, TTPs..."
                className="w-full bg-slate-950/60 border border-slate-700/60 text-white rounded-xl pl-10 pr-4 py-2.5 text-sm placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/40 transition-all"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
              {search && (
                <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white transition-colors">
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Quick toggles */}
            <div className="flex items-center gap-2 flex-shrink-0">
              {[
                { key: 'is_critical', val: 'true', label: 'Critical', icon: ShieldAlert, active: 'bg-red-500/15 text-red-400 border-red-500/40', inactive: 'bg-slate-800 text-slate-500 border-slate-700 hover:border-slate-600' },
                { key: 'is_zero_day', val: 'true', label: '0-Day',    icon: Zap,         active: 'bg-orange-500/15 text-orange-400 border-orange-500/40', inactive: 'bg-slate-800 text-slate-500 border-slate-700 hover:border-slate-600' },
                { key: 'is_kev',      val: 'true', label: 'KEV',      icon: Activity,    active: 'bg-purple-500/15 text-purple-400 border-purple-500/40', inactive: 'bg-slate-800 text-slate-500 border-slate-700 hover:border-slate-600' },
              ].map(({ key, val, label, icon: Icon, active, inactive }) => (
                <button key={key}
                  onClick={() => setFilter(key, filters[key] === val ? '' : val)}
                  className={clsx('flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition-all border', filters[key] === val ? active : inactive)}>
                  <Icon className="w-3.5 h-3.5" />{label}
                </button>
              ))}

              {/* View toggle */}
              <div className="flex rounded-xl border border-slate-700 overflow-hidden ml-1">
                <button onClick={() => setView('grid')} className={clsx('p-2 transition-colors', view === 'grid' ? 'bg-blue-500/15 text-blue-400' : 'bg-slate-800 text-slate-500 hover:text-slate-300')}>
                  <LayoutGrid className="w-4 h-4" />
                </button>
                <button onClick={() => setView('table')} className={clsx('p-2 transition-colors', view === 'table' ? 'bg-blue-500/15 text-blue-400' : 'bg-slate-800 text-slate-500 hover:text-slate-300')}>
                  <List className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Row 2: selects + active chip strip */}
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
            {[
              { key: 'status', label: 'All Statuses', options: visibleStatuses.slice(1) },
              { key: 'severity', label: 'All Severities', options: SEVERITIES.slice(1) },
            ].map(({ key, label, options }) => (
              <select key={key}
                className="bg-slate-800/80 border border-slate-700/60 text-slate-300 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500/40 transition-all cursor-pointer"
                value={filters[key]} onChange={e => setFilter(key, e.target.value)}>
                <option value="">{label}</option>
                {options.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
              </select>
            ))}
            <select className="bg-slate-800/80 border border-slate-700/60 text-slate-300 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500/40 transition-all cursor-pointer"
              value={filters.sector_id} onChange={e => setFilter('sector_id', e.target.value)}>
              <option value="">All Sectors</option>
              {sectors.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            <select className="bg-slate-800/80 border border-slate-700/60 text-slate-300 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500/40 transition-all cursor-pointer"
              value={filters.source} onChange={e => setFilter('source', e.target.value)}>
              <option value="">All Sources</option>
              <option value="manual">SecureEye (Manual)</option>
              <option value="external">External Feed</option>
            </select>

            {/* Active filter chips */}
            {activeChips.map(c => (
              <FilterChip key={c.key} label={c.label} onRemove={() => setFilter(c.key, '')} />
            ))}

            {hasFilters && (
              <button onClick={clearAllFilters}
                className="text-[10px] font-bold text-red-400 hover:text-red-300 ml-auto px-3 py-1.5 rounded-lg hover:bg-red-500/10 transition-colors uppercase tracking-wider">
                Reset All
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Content ─────────────────────────────────────────────────────────── */}
      {loading ? (
        <div className="py-24 flex flex-col items-center justify-center gap-6">
          <div className="relative w-20 h-20">
            <div className="absolute inset-0 bg-blue-500/10 blur-3xl rounded-full animate-pulse" />
            <div className="w-20 h-20 border-[3px] border-slate-800 border-t-cyan-500 rounded-full animate-spin" />
            <div className="absolute inset-[8px] border-[2px] border-slate-800 border-b-blue-500 rounded-full animate-spin" style={{ animationDirection: 'reverse' }} />
            <Crosshair className="absolute inset-0 m-auto w-5 h-5 text-cyan-400 animate-pulse" />
          </div>
          <div className="text-center">
            <h3 className="text-lg font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400 tracking-widest uppercase animate-pulse">
              Syncing Intel Feeds...
            </h3>
            <p className="text-sm text-slate-500 mt-1">Retrieving latest threat advisories</p>
          </div>
        </div>
      ) : data.items.length === 0 ? (
        <div className="py-20 flex flex-col items-center justify-center text-center rounded-2xl border border-dashed border-slate-800 bg-slate-900/30">
          <ShieldAlert className="w-14 h-14 text-slate-700 mb-4" />
          <h3 className="text-lg font-bold text-white mb-2">No Advisories Found</h3>
          <p className="text-sm text-slate-500 max-w-sm">No advisories match your current filter configuration.</p>
          {hasFilters && (
            <button onClick={clearAllFilters} className="mt-5 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold rounded-xl transition-colors">
              Clear All Filters
            </button>
          )}
        </div>
      ) : view === 'grid' ? (
        <div className="grid gap-3 animate-in fade-in duration-500">
          {data.items.map((a, i) => (
            <div key={a.id} className="animate-in fade-in slide-in-from-bottom-2 duration-300" style={{ animationDelay: `${i * 30}ms` }}>
              <AdvisoryCard advisory={a} />
            </div>
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800 overflow-hidden animate-in fade-in duration-300">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr className="text-[10px] font-black uppercase tracking-widest text-slate-500">
                <th className="p-3 pl-4">Severity</th>
                <th className="p-3">Title / CVEs</th>
                <th className="p-3">CVSS</th>
                <th className="p-3">Vendors</th>
                <th className="p-3">Flags</th>
                <th className="p-3">Age</th>
                <th className="p-3 pr-4"></th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a, i) => (
                <AdvisoryRow key={a.id} advisory={a} navigate={navigate} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Pagination ──────────────────────────────────────────────────────── */}
      {data.total_pages > 1 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-2xl bg-slate-900/40 border border-slate-800/60">
          <span className="text-sm text-slate-500">
            Page <span className="text-white font-bold">{data.page}</span> of <span className="text-white font-bold">{data.total_pages}</span>
            <span className="mx-2 text-slate-700">·</span>
            <span className="text-blue-400 font-bold">{data.total}</span> total results
          </span>
          <div className="flex items-center gap-1.5">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 disabled:opacity-30 text-sm font-bold transition-all">
              <ChevronLeft className="w-4 h-4" /> Prev
            </button>
            {Array.from({ length: Math.min(5, data.total_pages) }, (_, i) => {
              const p = Math.max(1, Math.min(data.page - 2, data.total_pages - 4)) + i
              return (
                <button key={p} onClick={() => setPage(p)}
                  className={clsx('w-8 h-8 rounded-lg text-sm font-bold transition-all', p === page ? 'bg-blue-600 text-white' : 'border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600')}>
                  {p}
                </button>
              )
            })}
            <button onClick={() => setPage(p => Math.min(data.total_pages, p + 1))} disabled={page === data.total_pages}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 disabled:opacity-30 text-sm font-bold transition-all">
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
