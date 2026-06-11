import { useEffect, useState, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  RadialBarChart, RadialBar, Cell, AreaChart, Area, PieChart, Pie
} from 'recharts'
import {
  AlertTriangle, FileText, Shield, Bug, Clock, Cpu, Activity,
  TrendingUp, Search, ChevronRight, ExternalLink, Zap, Globe,
  Lock, Radio, Eye, BarChart2, Layers, RefreshCw, Sparkles,
  ArrowUpRight, ArrowDownRight, Minus, Terminal, Database
} from 'lucide-react'
import ThreatHeatmap from './ThreatHeatmap'
import MITREMatrix from './MITREMatrix'
import api from '../services/api'
import { cvssColor, formatDateTime } from '../utils/helpers'
import toast from 'react-hot-toast'
import { useAuth } from '../context/AuthContext'
import clsx from 'clsx'

// ── Severity color map ────────────────────────────────────────────────────────
const SEV_CONFIG = {
  critical:      { color: '#ef4444', glow: 'rgba(239,68,68,0.4)',   bar: 'bg-red-500',    text: 'text-red-400',    border: 'border-red-500/30',    bg: 'bg-red-500/10' },
  high:          { color: '#f97316', glow: 'rgba(249,115,22,0.4)',  bar: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-500/10' },
  medium:        { color: '#eab308', glow: 'rgba(234,179,8,0.4)',   bar: 'bg-yellow-500', text: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-500/10' },
  low:           { color: '#22c55e', glow: 'rgba(34,197,94,0.4)',   bar: 'bg-green-500',  text: 'text-green-400',  border: 'border-green-500/30',  bg: 'bg-green-500/10' },
  informational: { color: '#3b82f6', glow: 'rgba(59,130,246,0.4)',  bar: 'bg-blue-500',   text: 'text-blue-400',   border: 'border-blue-500/30',   bg: 'bg-blue-500/10' },
}
const SECTOR_COLORS = ['#06b6d4','#8b5cf6','#f97316','#22c55e','#ef4444','#eab308','#3b82f6']

// ── Animated counter ─────────────────────────────────────────────────────────
function AnimatedNumber({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    let start = 0
    const steps = 40
    const increment = value / steps
    const interval = duration / steps
    const timer = setInterval(() => {
      start += increment
      if (start >= value) { setDisplay(value); clearInterval(timer) }
      else setDisplay(Math.floor(start))
    }, interval)
    return () => clearInterval(timer)
  }, [value])
  return display
}

// ── KPI Metric Card ───────────────────────────────────────────────────────────
function MetricCard({ icon: Icon, label, value, sub, color = 'cyan', trend, delay = 0 }) {
  const C = {
    red:    { border: 'border-red-500/20',    bg: 'bg-red-500/8',    text: 'text-red-400',    iconBg: 'bg-red-500/15',    glow: '0 0 30px rgba(239,68,68,0.12)' },
    orange: { border: 'border-orange-500/20', bg: 'bg-orange-500/8', text: 'text-orange-400', iconBg: 'bg-orange-500/15', glow: '0 0 30px rgba(249,115,22,0.12)' },
    cyan:   { border: 'border-cyan-500/20',   bg: 'bg-cyan-500/8',   text: 'text-cyan-400',   iconBg: 'bg-cyan-500/15',   glow: '0 0 30px rgba(6,182,212,0.12)' },
    purple: { border: 'border-purple-500/20', bg: 'bg-purple-500/8', text: 'text-purple-400', iconBg: 'bg-purple-500/15', glow: '0 0 30px rgba(139,92,246,0.12)' },
    green:  { border: 'border-green-500/20',  bg: 'bg-green-500/8',  text: 'text-green-400',  iconBg: 'bg-green-500/15',  glow: '0 0 30px rgba(34,197,94,0.12)' },
    yellow: { border: 'border-yellow-500/20', bg: 'bg-yellow-500/8', text: 'text-yellow-400', iconBg: 'bg-yellow-500/15', glow: '0 0 30px rgba(234,179,8,0.12)' },
  }[color] || {}

  return (
    <div
      className={clsx('relative rounded-2xl border p-5 overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:brightness-110 cursor-default', C.border, C.bg)}
      style={{ boxShadow: C.glow, animationDelay: `${delay}ms` }}
    >
      {/* Top glow blob */}
      <div className={clsx('absolute -top-6 -right-6 w-24 h-24 rounded-full blur-2xl opacity-30', C.iconBg)} />

      <div className="relative z-10">
        <div className="flex items-start justify-between mb-4">
          <div className={clsx('p-2.5 rounded-xl', C.iconBg)}>
            <Icon className={clsx('w-5 h-5', C.text)} />
          </div>
          {trend !== undefined && (
            <div className={clsx('flex items-center gap-0.5 text-[10px] font-black uppercase tracking-wider', trend > 0 ? 'text-red-400' : trend < 0 ? 'text-green-400' : 'text-slate-500')}>
              {trend > 0 ? <ArrowUpRight className="w-3 h-3" /> : trend < 0 ? <ArrowDownRight className="w-3 h-3" /> : <Minus className="w-3 h-3" />}
              {Math.abs(trend)}%
            </div>
          )}
        </div>
        <div className={clsx('text-3xl font-black tracking-tighter tabular-nums', C.text)}>
          <AnimatedNumber value={value ?? 0} />
        </div>
        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">{label}</div>
        {sub && <div className="text-[10px] text-slate-600 mt-0.5">{sub}</div>}
      </div>
    </div>
  )
}

// ── Live Threat Ticker ────────────────────────────────────────────────────────
function ThreatTicker({ advisories }) {
  const [idx, setIdx] = useState(0)
  useEffect(() => {
    if (!advisories?.length) return
    const t = setInterval(() => setIdx(i => (i + 1) % advisories.length), 4000)
    return () => clearInterval(t)
  }, [advisories])
  if (!advisories?.length) return null
  const a = advisories[idx]
  const sev = SEV_CONFIG[a.severity] || SEV_CONFIG.informational
  return (
    <div className="flex items-center gap-3 overflow-hidden">
      <span className="flex-shrink-0 flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-red-400 bg-red-500/10 border border-red-500/20 px-2.5 py-1 rounded-full">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" /> Live
      </span>
      <span className={clsx('flex-shrink-0 text-[10px] font-black uppercase px-2 py-0.5 rounded border', sev.text, sev.bg, sev.border)}>{a.severity}</span>
      <span className="text-sm text-slate-300 font-medium truncate">{a.title}</span>
      <span className="flex-shrink-0 text-[10px] text-slate-600">{formatDateTime(a.published_at || a.created_at)}</span>
    </div>
  )
}

// ── Severity Donut ────────────────────────────────────────────────────────────
function SeverityRadial({ data }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1
  return (
    <div className="relative flex flex-col items-center">
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={65}
            outerRadius={85}
            paddingAngle={4}
            dataKey="value"
            stroke="none"
          >
            {data.map((d, i) => (
              <Cell key={i} fill={SEV_CONFIG[d.name.toLowerCase()]?.color || '#64748b'} />
            ))}
          </Pie>
          <Tooltip
            content={({ active, payload }) => active && payload?.length ? (
              <div className="bg-slate-900/95 border border-slate-700 rounded-xl px-3 py-2 text-xs shadow-2xl">
                <div className="font-black text-white flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: payload[0].payload.fill }} />
                  {payload[0].payload.name}
                </div>
                <div className="text-slate-400 mt-1">{payload[0].value} advisories tracked</div>
              </div>
            ) : null}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="text-3xl font-black text-white tabular-nums tracking-tighter drop-shadow-lg">{total}</div>
        <div className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-0.5">Total</div>
      </div>
    </div>
  )
}

// ── Sector Bar ────────────────────────────────────────────────────────────────
function SectorBar({ sectors }) {
  return (
    <div className="space-y-3 mt-2">
      {sectors.slice(0, 6).map((s, i) => (
        <div key={s.sector}>
          <div className="flex justify-between items-center mb-1">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">{s.sector}</span>
            <span className="text-[10px] font-black tabular-nums" style={{ color: SECTOR_COLORS[i % SECTOR_COLORS.length] }}>
              {s.count} <span className="text-slate-600">({s.percentage}%)</span>
            </span>
          </div>
          <div className="h-1.5 rounded-full bg-slate-800/80 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-1000"
              style={{ width: `${s.percentage}%`, background: SECTOR_COLORS[i % SECTOR_COLORS.length], boxShadow: `0 0 8px ${SECTOR_COLORS[i % SECTOR_COLORS.length]}60` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

// ── CVE Radar Card ────────────────────────────────────────────────────────────
function CveCard({ cve, idx }) {
  const sev = SEV_CONFIG[cve.severity] || SEV_CONFIG.informational
  return (
    <div className={clsx('group relative rounded-xl border p-4 transition-all duration-200 hover:-translate-y-0.5 overflow-hidden cursor-pointer', sev.border, sev.bg)}
      style={{ boxShadow: `0 0 20px ${sev.glow}20` }}>
      <div className="absolute top-0 right-0 w-16 h-16 rounded-full blur-2xl opacity-20" style={{ background: sev.color }} />
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: sev.color }} />
            <span className={clsx('font-mono text-xs font-black px-2 py-0.5 rounded border', sev.text, sev.bg, sev.border)}>{cve.cve_id}</span>
          </div>
          {cve.cvss_score && (
            <span className={clsx('text-sm font-black tabular-nums', sev.text)}>{cve.cvss_score}</span>
          )}
        </div>
        <p className="text-xs text-slate-300 leading-snug line-clamp-2 mb-3">{cve.title}</p>
        <div className="flex justify-between items-center">
          <span className={clsx('text-[10px] font-black uppercase px-2 py-0.5 rounded-full border', sev.text, sev.bg, sev.border)}>{cve.severity}</span>
          <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noreferrer"
            className="flex items-center gap-1 text-[10px] font-bold text-slate-500 hover:text-cyan-400 transition-colors">
            NVD <ExternalLink className="w-2.5 h-2.5" />
          </a>
        </div>
      </div>
    </div>
  )
}

// ── Advisory Feed Row ─────────────────────────────────────────────────────────
function FeedRow({ advisory, compact }) {
  const sev = SEV_CONFIG[advisory.severity] || SEV_CONFIG.informational
  return (
    <Link to={`/advisories/${advisory.id}`}
      className="group flex items-start gap-3 p-3 rounded-xl border border-transparent hover:border-slate-700/50 hover:bg-slate-800/20 transition-all duration-200">
      <div className="flex-shrink-0 mt-0.5 w-2 h-2 rounded-full mt-1.5" style={{ background: sev.color, boxShadow: `0 0 6px ${sev.color}` }} />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-slate-200 group-hover:text-white transition-colors line-clamp-1 leading-snug">
          {advisory.title}
        </div>
        <div className="flex items-center gap-2 mt-1">
          <span className={clsx('text-[9px] font-black uppercase px-1.5 py-0.5 rounded border', sev.text, sev.bg, sev.border)}>{advisory.severity}</span>
          {advisory.cvss_score > 0 && (
            <span className={clsx('text-[10px] font-black tabular-nums', sev.text)}>{advisory.cvss_score}</span>
          )}
          <span className="text-[10px] text-slate-600 ml-auto flex-shrink-0">{formatDateTime(advisory.published_at || advisory.created_at)}</span>
        </div>
      </div>
      <ChevronRight className="w-3.5 h-3.5 text-slate-700 group-hover:text-slate-400 transition-colors flex-shrink-0 mt-1" />
    </Link>
  )
}

// ── CISO Briefing Bot ─────────────────────────────────────────────────────────
function CISOBriefing() {
  const [script, setScript] = useState(null)
  const [loading, setLoading] = useState(false)
  const [words, setWords] = useState([])
  const [wordIdx, setWordIdx] = useState(0)
  const intervalRef = useRef(null)

  const fetchBriefing = async () => {
    setLoading(true)
    setWords([])
    setWordIdx(0)
    try {
      const r = await api.get('/dashboard/briefing')
      const allWords = r.data.script.split(' ')
      setScript(r.data.script)
      setWords(allWords)
    } catch { toast.error('Briefing failed') }
    finally { setLoading(false) }
  }

  useEffect(() => {
    if (!words.length) return
    setWordIdx(0)
    intervalRef.current = setInterval(() => {
      setWordIdx(i => {
        if (i >= words.length - 1) { clearInterval(intervalRef.current); return i }
        return i + 1
      })
    }, 60)
    return () => clearInterval(intervalRef.current)
  }, [words])

  return (
    <div className="rounded-2xl border border-indigo-500/20 bg-gradient-to-br from-indigo-950/40 to-purple-950/20 p-5 relative overflow-hidden">
      <div className="absolute top-0 right-0 w-40 h-40 bg-indigo-500/10 blur-3xl rounded-full pointer-events-none" />
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-xl bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-indigo-400" />
          </div>
          <div>
            <div className="text-xs font-black text-indigo-300 uppercase tracking-widest">CISO AI Briefing</div>
            <div className="text-[9px] text-slate-600 uppercase tracking-wider">Powered by Neural Intelligence</div>
          </div>
        </div>
        <button onClick={fetchBriefing} disabled={loading}
          className="flex items-center gap-1.5 text-[10px] font-bold text-indigo-400 hover:text-white bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/20 px-3 py-1.5 rounded-lg transition-all uppercase tracking-wider disabled:opacity-50">
          {loading ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
          {loading ? 'Generating...' : script ? 'Refresh' : 'Generate'}
        </button>
      </div>
      <div className="relative z-10 min-h-[60px]">
        {loading ? (
          <div className="flex items-center gap-3 text-indigo-300/60 py-4">
            <div className="flex gap-1">
              {[0,1,2].map(i => <div key={i} className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: `${i * 0.15}s` }} />)}
            </div>
            <span className="text-sm animate-pulse">Analysing threat landscape…</span>
          </div>
        ) : words.length > 0 ? (
          <p className="text-sm text-slate-200 leading-relaxed">
            {words.slice(0, wordIdx + 1).join(' ')}
            {wordIdx < words.length - 1 && <span className="inline-block w-0.5 h-4 bg-indigo-400 ml-0.5 animate-pulse align-middle" />}
          </p>
        ) : (
          <p className="text-sm text-slate-600 italic">Click "Generate" for your daily intelligence briefing.</p>
        )}
      </div>
    </div>
  )
}

// ── MAIN DASHBOARD ────────────────────────────────────────────────────────────
export default function Dashboard() {
  const { isAnalyst } = useAuth()
  const navigate = useNavigate()
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [syncing, setSyncing] = useState(false)
  const [lastPing, setLastPing] = useState(new Date())

  const fetchStats = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const r = await api.get('/dashboard/stats')
      setStats(r.data)
      setLastPing(new Date())
    } catch (e) {
      console.error('Dashboard error:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStats()
    const interval = setInterval(() => fetchStats(true), 300000)
    return () => clearInterval(interval)
  }, [])

  const handleTriggerFeed = async () => {
    setSyncing(true)
    try {
      await api.post('/admin/feeds/run')
      toast.success('Feed sync initiated')
      setTimeout(() => fetchStats(true), 3000)
    } catch { toast.error('Feed sync failed') }
    finally { setTimeout(() => setSyncing(false), 2000) }
  }

  const handleSearch = (e) => {
    e.preventDefault()
    if (searchQuery.trim()) navigate('/search', { state: { query: searchQuery } })
  }

  if (loading) return (
    <div className="flex flex-col items-center justify-center h-[70vh] gap-4">
      <div className="relative w-20 h-20">
        <div className="absolute inset-0 rounded-full border-[3px] border-slate-800" />
        <div className="absolute inset-0 rounded-full border-[3px] border-t-cyan-500 animate-spin" />
        <div className="absolute inset-0 rounded-full border-[3px] border-r-purple-500 animate-spin" style={{ animationDuration: '1.5s', animationDirection: 'reverse' }} />
        <Shield className="absolute inset-0 m-auto w-8 h-8 text-cyan-400" />
      </div>
      <div className="text-[11px] font-black text-cyan-500/60 uppercase tracking-[0.25em] animate-pulse">Initializing Operations Center</div>
    </div>
  )

  const severityData = stats?.severity_breakdown
    ? Object.entries(stats.severity_breakdown)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v }))
    : []

  const allAdvisories = [
    ...(stats?.secure_advisories || []),
    ...(stats?.open_source_advisories || [])
  ].sort((a, b) => new Date(b.published_at || b.created_at) - new Date(a.published_at || a.created_at))

  return (
    <div className="space-y-6 pb-20 relative">

      {/* ── Ambient Background ─────────────────────────────────────────────── */}
      <div className="fixed top-0 left-1/4 w-[600px] h-[600px] bg-cyan-600/5 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-[600px] h-[600px] bg-purple-600/5 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-indigo-600/3 rounded-full blur-[160px] pointer-events-none -z-10" />

      {/* ── Top Header Bar ─────────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-5 flex flex-col lg:flex-row lg:items-center gap-5">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping absolute" />
              <span className="w-2 h-2 rounded-full bg-emerald-500 relative" />
            </div>
            <h1 className="text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-200 to-slate-400 tracking-tight">
              SecureEye Operations Center
            </h1>
            <span className="text-[9px] font-black text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-full uppercase tracking-widest">Live</span>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
            <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> Last sync: {stats?.feed_last_run ? formatDateTime(stats.feed_last_run) : 'N/A'}</span>
            <span className="w-1 h-1 rounded-full bg-slate-700" />
            <span className="flex items-center gap-1"><Database className="w-3 h-3" /> {stats?.total_advisories ?? 0} advisories indexed</span>
            <span className="w-1 h-1 rounded-full bg-slate-700" />
            <span className="flex items-center gap-1"><Globe className="w-3 h-3" /> {stats?.active_sectors ?? 0} sectors monitored</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <form onSubmit={handleSearch} className="relative flex items-center">
            <Search className="absolute left-3 w-4 h-4 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search CVE, threat, IOC…"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="bg-slate-800/60 border border-slate-700/60 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 w-64 transition-colors"
            />
          </form>

          {/* Sync */}
          {isAnalyst && (
            <button onClick={handleTriggerFeed} disabled={syncing}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-600/15 border border-cyan-500/25 text-cyan-400 text-xs font-bold uppercase tracking-wider hover:bg-cyan-600/25 transition-all disabled:opacity-50">
              <RefreshCw className={clsx('w-3.5 h-3.5', syncing && 'animate-spin')} />
              {syncing ? 'Syncing…' : 'Sync Feeds'}
            </button>
          )}

          <Link to="/advisories/new"
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold uppercase tracking-wider transition-all">
            <Zap className="w-3.5 h-3.5" /> New Advisory
          </Link>
        </div>
      </div>

      {/* ── Live Ticker ────────────────────────────────────────────────────── */}
      <div className="rounded-xl border border-red-500/10 bg-red-950/10 px-4 py-2.5">
        <ThreatTicker advisories={allAdvisories} />
      </div>

      {/* ── KPI Cards Row ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-4 gap-4">
        <MetricCard icon={AlertTriangle} label="Critical Today"       value={stats?.critical_today ?? 0}       color="red"    sub="Immediate action" delay={0} />
        <MetricCard icon={Bug}          label="Zero-Days Tracked"     value={stats?.zero_days_tracked ?? 0}     color="purple" sub="Active zero-day"  delay={50} />
        <MetricCard icon={Shield}       label="CISA KEV Matches"      value={stats?.kev_count ?? 0}             color="orange" sub="Exploited in wild"  delay={100} />
        <MetricCard icon={Activity}     label="Published This Week"   value={stats?.published_this_week ?? 0}   color="cyan"   sub="New intelligence"  delay={150} />
        <MetricCard icon={Layers}       label="Total Advisories"      value={stats?.total_advisories ?? 0}      color="cyan"   sub="All time"          delay={200} />
        <MetricCard icon={FileText}     label="Internal Advisories"   value={stats?.manual_count ?? 0}          color="green"  sub="Analyst authored"  delay={250} />
        <MetricCard icon={Globe}        label="External Intel"        value={stats?.external_count ?? 0}        color="purple" sub="Feed ingested"      delay={300} />
        {isAnalyst && <MetricCard icon={Clock} label="Pending Review" value={stats?.pending_review ?? 0}       color="yellow" sub="Awaiting approval"  delay={350} />}
      </div>

      {/* ── CISO Briefing ──────────────────────────────────────────────────── */}
      <CISOBriefing />

      {/* ── Charts Row ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* Severity Radial */}
        <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-7 h-7 rounded-lg bg-red-500/15 border border-red-500/25 flex items-center justify-center">
              <BarChart2 className="w-3.5 h-3.5 text-red-400" />
            </div>
            <span className="text-xs font-black text-slate-400 uppercase tracking-widest">Severity Distribution</span>
          </div>
          {severityData.length > 0 ? (
            <div className="flex items-center gap-6">
              <div className="flex-1">
                <SeverityRadial data={severityData} />
              </div>
              <div className="space-y-2.5 min-w-[130px]">
                {severityData.map(d => {
                  const cfg = SEV_CONFIG[d.name.toLowerCase()] || {}
                  return (
                    <div key={d.name} className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: cfg.color }} />
                      <span className="text-xs text-slate-400 flex-1">{d.name}</span>
                      <span className="text-xs font-black tabular-nums" style={{ color: cfg.color }}>{d.value}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-slate-600 text-sm">No data</div>
          )}
        </div>

        {/* Sector Impact */}
        <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/25 flex items-center justify-center">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <span className="text-xs font-black text-slate-400 uppercase tracking-widest">Sector Threat Exposure</span>
            </div>
          </div>
          {stats?.sector_distribution?.length > 0 ? (
            <SectorBar sectors={stats.sector_distribution} />
          ) : (
            <div className="h-48 flex items-center justify-center text-slate-600 text-sm">No sector data</div>
          )}
        </div>
      </div>

      {/* ── CVE Radar ──────────────────────────────────────────────────────── */}
      {stats?.trending_cves?.length > 0 && (
        <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-6">
          <div className="flex items-center justify-between mb-5">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-orange-500/15 border border-orange-500/25 flex items-center justify-center">
                <Radio className="w-3.5 h-3.5 text-orange-400" />
              </div>
              <span className="text-xs font-black text-slate-400 uppercase tracking-widest">Active Exploitation Radar</span>
              <span className="text-[10px] text-orange-400 bg-orange-500/10 border border-orange-500/20 px-2 py-0.5 rounded-full font-bold">{stats.trending_cves.length} detected</span>
            </div>
            <Link to="/zero-days" className="text-[10px] font-bold text-slate-500 hover:text-orange-400 uppercase tracking-wider transition-colors flex items-center gap-1">
              Full Tracker <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {stats.trending_cves.map((cve, i) => <CveCard key={i} cve={cve} idx={i} />)}
          </div>
        </div>
      )}

      {/* ── Advisory Feed Streams ──────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* Internal */}
        <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-5 flex flex-col h-[420px]">
          <div className="flex items-center justify-between mb-4 flex-shrink-0">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-blue-500/15 border border-blue-500/25 flex items-center justify-center">
                <Lock className="w-3.5 h-3.5 text-blue-400" />
              </div>
              <span className="text-xs font-black text-slate-400 uppercase tracking-widest">Internal Intel Stream</span>
            </div>
            <Link to="/advisories?source=manual" className="flex items-center gap-1 text-[10px] font-bold text-blue-400 hover:text-white uppercase tracking-wider transition-colors">
              View All <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="flex-1 overflow-y-auto space-y-1 pr-1" style={{ scrollbarWidth: 'none' }}>
            {stats?.secure_advisories?.length > 0
              ? stats.secure_advisories.map(a => <FeedRow key={a.id} advisory={a} />)
              : <div className="h-full flex items-center justify-center text-slate-600 text-sm">No internal advisories</div>
            }
          </div>
        </div>

        {/* External */}
        <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-5 flex flex-col h-[420px]">
          <div className="flex items-center justify-between mb-4 flex-shrink-0">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-purple-500/15 border border-purple-500/25 flex items-center justify-center">
                <Globe className="w-3.5 h-3.5 text-purple-400" />
              </div>
              <span className="text-xs font-black text-slate-400 uppercase tracking-widest">Global Threat Feed</span>
            </div>
            <Link to="/advisories?source=external" className="flex items-center gap-1 text-[10px] font-bold text-purple-400 hover:text-white uppercase tracking-wider transition-colors">
              View All <ChevronRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="flex-1 overflow-y-auto space-y-1 pr-1" style={{ scrollbarWidth: 'none' }}>
            {stats?.open_source_advisories?.length > 0
              ? stats.open_source_advisories.map(a => <FeedRow key={a.id} advisory={a} />)
              : <div className="h-full flex items-center justify-center text-slate-600 text-sm">No external feed data</div>
            }
          </div>
        </div>
      </div>

      {/* ── Threat Matrix + Heatmap ─────────────────────────────────────────── */}
      <div className="space-y-5">
        <MITREMatrix />
        {ThreatHeatmap && <ThreatHeatmap />}
      </div>

      {/* ── Quick Nav Footer ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Advisories',    icon: FileText,     to: '/advisories',   color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/20' },
          { label: 'Zero-Day Tracker', icon: Bug,       to: '/zero-days',    color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/20' },
          { label: 'IOC Lookup',    icon: Eye,          to: '/iocs',         color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' },
          { label: 'Threat Intel',  icon: Terminal,     to: '/search',       color: 'text-cyan-400',   bg: 'bg-cyan-500/10',   border: 'border-cyan-500/20' },
        ].map(({ label, icon: Icon, to, color, bg, border }) => (
          <Link key={to} to={to}
            className={clsx('flex items-center gap-3 rounded-xl border p-4 transition-all hover:-translate-y-0.5 hover:brightness-110', bg, border)}>
            <Icon className={clsx('w-4 h-4 flex-shrink-0', color)} />
            <span className={clsx('text-xs font-bold uppercase tracking-wider', color)}>{label}</span>
            <ChevronRight className={clsx('w-3.5 h-3.5 ml-auto', color)} />
          </Link>
        ))}
      </div>
    </div>
  )
}
