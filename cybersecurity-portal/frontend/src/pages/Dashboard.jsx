import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, LineChart, Line
} from 'recharts'
import { AlertTriangle, FileText, Shield, Bug, Clock, Cpu, Activity, TrendingUp, Search, ChevronRight, ExternalLink } from 'lucide-react'
import ThreatHeatmap from './ThreatHeatmap'
import MITREMatrix from './MITREMatrix'
import api from '../services/api'
import AdvisoryCard from '../components/AdvisoryCard'
import { cvssColor, formatDateTime } from '../utils/helpers'
import toast from 'react-hot-toast'
import { useAuth } from '../context/AuthContext'
import clsx from 'clsx'

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#a855f7', '#06b6d4']

function StatCard({ icon: Icon, label, value, sub, color = 'blue', pulse, delay = 0 }) {
  const colorMap = {
    red: { bg: 'from-red-500/10 to-transparent', border: 'border-red-500/30', text: 'text-red-400', iconBg: 'bg-red-500/20', shadow: 'shadow-[0_0_20px_rgba(239,68,68,0.15)]', glow: 'group-hover:shadow-[0_0_30px_rgba(239,68,68,0.3)]' },
    blue: { bg: 'from-blue-500/10 to-transparent', border: 'border-blue-500/30', text: 'text-blue-400', iconBg: 'bg-blue-500/20', shadow: 'shadow-[0_0_20px_rgba(59,130,246,0.15)]', glow: 'group-hover:shadow-[0_0_30px_rgba(59,130,246,0.3)]' },
    yellow: { bg: 'from-yellow-500/10 to-transparent', border: 'border-yellow-500/30', text: 'text-yellow-400', iconBg: 'bg-yellow-500/20', shadow: 'shadow-[0_0_20px_rgba(234,179,8,0.15)]', glow: 'group-hover:shadow-[0_0_30px_rgba(234,179,8,0.3)]' },
    green: { bg: 'from-green-500/10 to-transparent', border: 'border-green-500/30', text: 'text-green-400', iconBg: 'bg-green-500/20', shadow: 'shadow-[0_0_20px_rgba(34,197,94,0.15)]', glow: 'group-hover:shadow-[0_0_30px_rgba(34,197,94,0.3)]' },
    purple: { bg: 'from-purple-500/10 to-transparent', border: 'border-purple-500/30', text: 'text-purple-400', iconBg: 'bg-purple-500/20', shadow: 'shadow-[0_0_20px_rgba(168,85,247,0.15)]', glow: 'group-hover:shadow-[0_0_30px_rgba(168,85,247,0.3)]' }
  }
  const theme = colorMap[color] || colorMap.blue

  return (
    <div 
      className={clsx(
        "relative overflow-hidden rounded-3xl border bg-gradient-to-b bg-dark-900/60 backdrop-blur-xl p-5 md:p-6 transition-all duration-500 group animate-in zoom-in-95 fade-in fill-mode-both hover:-translate-y-1",
        theme.bg, theme.border, theme.shadow, theme.glow
      )}
      style={{ animationDelay: `${delay}ms` }}
    >
      {/* Ambient background glow */}
      <div className={clsx("absolute -top-10 -right-10 w-32 h-32 blur-3xl opacity-20 transition-opacity duration-500 group-hover:opacity-40 rounded-full", theme.iconBg)} />
      
      <div className="flex items-start justify-between relative z-10">
        <div>
          <p className="text-slate-400 text-xs font-bold uppercase tracking-widest">{label}</p>
          <p className={clsx(
            "text-4xl font-black mt-2 tracking-tighter drop-shadow-lg", 
            theme.text, 
            pulse && "animate-pulse"
          )}>
            {value}
          </p>
          {sub && <p className="text-[11px] font-bold text-slate-500 mt-2 uppercase tracking-wider">{sub}</p>}
        </div>
        <div className={clsx("p-3 rounded-2xl flex items-center justify-center transition-transform duration-500 group-hover:scale-110", theme.iconBg)}>
          <Icon className={clsx("w-6 h-6", theme.text)} />
        </div>
      </div>
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-dark-900/90 backdrop-blur-xl border border-white/10 p-4 rounded-2xl shadow-[0_0_30px_rgba(0,0,0,0.5)]">
        <p className="text-slate-300 font-bold uppercase tracking-widest text-[10px] mb-2">{label}</p>
        <p className="text-white font-black text-lg flex items-center gap-2">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: payload[0].color || payload[0].fill }} />
          {payload[0].value} <span className="text-slate-500 text-sm font-medium">Advisories</span>
        </p>
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const { isAnalyst } = useAuth()
  const navigate = useNavigate()
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    api.get('/dashboard/stats')
      .then(r => setStats(r.data))
      .catch((err) => {
        console.error('Dashboard error:', err.response?.data || err.message)
        toast.error('Failed to load dashboard')
      })
      .finally(() => setLoading(false))
  }, [])

  const handleTriggerFeed = async () => {
    try {
      await api.post('/admin/feeds/run')
      toast.success('Feed ingestion started — check Feed Logs for results')
    } catch { toast.error('Feed trigger failed') }
  }

  const handleSearch = (e) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      // Pass the query as state to the SmartSearch page so it triggers automatically
      navigate('/search', { state: { query: searchQuery } })
    }
  }

  if (loading) return (
    <div className="flex flex-col items-center justify-center h-[70vh] space-y-4">
      <div className="relative w-20 h-20">
        <div className="absolute inset-0 rounded-full border-[3px] border-dark-700" />
        <div className="absolute inset-0 rounded-full border-[3px] border-t-cyan-500 animate-spin" />
        <div className="absolute inset-0 rounded-full border-[3px] border-r-purple-500 animate-spin" style={{ animationDuration: '1.5s', animationDirection: 'reverse' }} />
        <Shield className="absolute inset-0 m-auto w-8 h-8 text-cyan-400 animate-pulse" />
      </div>
      <div className="text-cyan-500/80 font-mono text-sm tracking-widest uppercase animate-pulse">Initializing Operations Center</div>
    </div>
  )

  const severityChartData = stats?.severity_breakdown ? Object.entries(stats.severity_breakdown).map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v })) : []
  const sectorData = stats?.sector_distribution || []

  return (
    <div className="space-y-10 pb-20 relative">
      {/* Background Ambient Orbs */}
      <div className="fixed top-0 left-1/4 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-[500px] h-[500px] bg-purple-600/10 rounded-full blur-[120px] pointer-events-none -z-10" />
      
      {/* Unified Header & Global Search */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-6 bg-dark-900/40 backdrop-blur-3xl border border-white/5 p-6 md:p-8 rounded-[2rem] shadow-2xl animate-in fade-in duration-1000 delay-100 fill-mode-both relative overflow-hidden">
        <div className="absolute right-0 top-0 w-1/2 h-full bg-gradient-to-l from-cyan-500/5 to-transparent pointer-events-none" />
        
        <div className="relative z-10 space-y-2">
          <h1 className="text-3xl md:text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-cyan-100 to-cyan-400 tracking-tighter">
            Security Dashboard
          </h1>
          <div className="text-slate-400 text-sm font-medium tracking-wide flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-ping" /> Threat intelligence overview</div>
            {stats?.feed_last_run && (
              <span className="text-slate-500 bg-white/5 px-3 py-1 rounded-full text-xs border border-white/5 flex items-center h-[26px]">Last Sync: {formatDateTime(stats.feed_last_run)}</span>
            )}
          </div>
        </div>

        <div className="relative z-10 flex flex-col sm:flex-row items-stretch sm:items-center gap-4 w-full xl:w-auto">
          {/* Quick Global Search */}
          <form onSubmit={handleSearch} className="relative group w-full xl:w-[350px]">
            <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-2xl blur opacity-20 group-hover:opacity-40 transition-opacity" />
            <div className="relative flex items-stretch bg-dark-950/80 border border-white/10 rounded-2xl overflow-hidden shadow-inner focus-within:border-cyan-500/50 focus-within:ring-1 focus-within:ring-cyan-500/50 transition-all">
              <div className="pl-4 pr-2 flex items-center justify-center text-cyan-500/70">
                <Search className="w-5 h-5" />
              </div>
              <input 
                type="text" 
                placeholder="Global Intel Search (e.g. CVE-2024)..." 
                className="w-full bg-transparent border-none text-white text-sm py-3.5 focus:ring-0 placeholder:text-slate-500"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </form>

          {isAnalyst && (
            <button onClick={handleTriggerFeed}
              className="group relative flex items-center justify-center gap-2 rounded-2xl border border-blue-500/30 bg-blue-600/20 px-6 py-3.5 text-sm font-bold uppercase tracking-widest text-blue-300 transition-all hover:bg-blue-600/40 hover:shadow-[0_0_20px_rgba(59,130,246,0.25)] flex-shrink-0">
              <Cpu className="w-4 h-4 group-hover:rotate-180 transition-transform duration-700" /> Sync Feeds
            </button>
          )}
        </div>
      </div>

      {/* Stat cards Grid */}
      <div className="grid grid-cols-1 gap-6 min-[500px]:grid-cols-2 lg:grid-cols-4">
        <StatCard icon={AlertTriangle} label="Critical Threats" value={stats?.critical_today ?? 0} color="red" pulse={stats?.critical_today > 0} delay={200} />
        <StatCard icon={Shield}       label="Active Sectors"   value={stats?.active_sectors ?? 0} color="green" delay={300} />
        <StatCard icon={Bug}          label="Zero-Days"        value={stats?.zero_days_tracked ?? 0} color="purple" delay={400} />
        <StatCard icon={TrendingUp}   label="Weekly Intel"     value={stats?.published_this_week ?? 0} color="blue" delay={500} />
        
        <StatCard icon={Shield}       label="Internal Advisory" value={stats?.manual_count ?? 0} color="yellow" delay={600} />
        <StatCard icon={Activity}     label="CISA KEV Matches" value={stats?.kev_count ?? 0} color="red" delay={700} />
        <StatCard icon={Activity}     label="External Intel"   value={stats?.external_count ?? 0} color="blue" delay={800} />
        {isAnalyst && (
          <StatCard icon={Clock}      label="Pending Review"   value={stats?.pending_review ?? 0} color="yellow" delay={900} />
        )}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity distribution */}
        <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 md:p-8 shadow-2xl relative overflow-hidden animate-in slide-in-from-bottom-8 fade-in duration-1000 delay-500 fill-mode-both">
          <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 blur-3xl rounded-full" />
          <h2 className="text-xs font-black uppercase tracking-[0.2em] text-slate-400 mb-8 flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-blue-500/20 flex items-center justify-center border border-blue-500/30">
              <Activity className="w-4 h-4 text-blue-400" />
            </div>
            Severity Matrix
          </h2>
          <div className="relative z-10 -ml-4">
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={severityChartData} barCategoryGap="25%">
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 11, fontWeight: 700 }} axisLine={false} tickLine={false} dy={10} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11, fontWeight: 700 }} axisLine={false} tickLine={false} dx={-10} />
                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.02)' }} content={<CustomTooltip />} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={50}>
                  {severityChartData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Sector distribution */}
        <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 md:p-8 shadow-2xl relative overflow-hidden animate-in slide-in-from-bottom-8 fade-in duration-1000 delay-[600ms] fill-mode-both">
          <div className="absolute top-0 right-0 w-32 h-32 bg-green-500/10 blur-3xl rounded-full" />
          <h2 className="text-xs font-black uppercase tracking-[0.2em] text-slate-400 mb-8 flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-green-500/20 flex items-center justify-center border border-green-500/30">
              <Shield className="w-4 h-4 text-green-400" />
            </div>
            Sector Impact Topology
          </h2>
          {sectorData.length > 0 ? (
            <div className="space-y-5 relative z-10">
              {sectorData.map((s, i) => (
                <div key={s.sector} className="group animate-in fade-in slide-in-from-right-4 duration-700 fill-mode-both" style={{ animationDelay: `${700 + (i * 150)}ms` }}>
                  <div className="flex justify-between items-center text-xs mb-2">
                    <span className="font-bold text-slate-300 uppercase tracking-wider">{s.sector}</span>
                    <span className="font-black text-slate-400 bg-white/5 px-2 py-1 rounded-md border border-white/5">{s.count} <span className="text-[10px] text-slate-500">({s.percentage}%)</span></span>
                  </div>
                  <div className="h-2.5 bg-dark-950/80 rounded-full overflow-hidden border border-white/5 shadow-inner">
                    <div className="h-full rounded-full transition-all duration-1000 ease-out group-hover:brightness-125 relative animate-sweep-width"
                      style={{ width: `${s.percentage}%`, background: COLORS[i % COLORS.length] }}>
                      <div className="absolute inset-0 bg-white/20 w-1/2 rounded-r-full blur-sm" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-sm bg-dark-950/40 rounded-2xl border border-white/5 border-dashed">
              <Shield className="w-8 h-8 text-slate-700 mb-2" />
              No sector data tracked
            </div>
          )}
        </div>
      </div>


      {/* Trending CVEs Section */}
      {stats?.trending_cves?.length > 0 && (
        <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 md:p-8 shadow-2xl animate-in slide-in-from-bottom-8 fade-in duration-1000 delay-[700ms] fill-mode-both">
          <h2 className="text-xs font-black uppercase tracking-[0.2em] text-slate-400 mb-6 flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-orange-500/20 flex items-center justify-center border border-orange-500/30">
              <TrendingUp className="w-4 h-4 text-orange-400" />
            </div>
            Active Exploitation Radar
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {stats.trending_cves.map((cve, i) => (
              <div 
                key={i} 
                className="group relative bg-dark-950/60 rounded-2xl p-4 border border-white/5 hover:border-orange-500/50 hover:bg-dark-900/80 transition-all duration-300 hover:-translate-y-1 overflow-hidden animate-in fade-in slide-in-from-bottom-4 fill-mode-both"
                style={{ animationDelay: `${700 + (i * 100)}ms` }}
              >
                <div className="absolute top-0 right-0 w-24 h-24 bg-orange-500/10 blur-3xl group-hover:bg-orange-500/30 transition-colors duration-500" />
                <div className="flex items-start justify-between mb-3 relative z-10">
                  <div className="flex items-center gap-2">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-orange-500"></span>
                    </span>
                    <span className="font-mono text-xs text-orange-400 font-bold bg-orange-500/10 px-2 py-1 rounded border border-orange-500/20 shadow-[0_0_10px_rgba(249,115,22,0.1)]">
                      {cve.cve_id}
                    </span>
                  </div>
                  {cve.cvss_score && (
                    <span className={`text-sm font-black drop-shadow-md ${cvssColor(cve.cvss_score)}`}>{cve.cvss_score}</span>
                  )}
                </div>
                <p className="text-[13px] text-slate-300 leading-relaxed line-clamp-2 font-medium relative z-10 mb-4">{cve.title}</p>
                
                <div className="relative z-10 flex justify-end">
                  <a 
                    href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 text-[11px] font-bold text-orange-400 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/20 px-3 py-1.5 rounded-lg transition-all hover:scale-105"
                  >
                    View Source <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Matrix & Heatmap */}
      <div className="grid grid-cols-1 gap-6 animate-in slide-in-from-bottom-8 fade-in duration-1000 delay-[800ms] fill-mode-both">
        <MITREMatrix />
        {ThreatHeatmap && <ThreatHeatmap />}
      </div>

      {/* Advisory Streams */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-in slide-in-from-bottom-8 fade-in duration-1000 delay-[900ms] fill-mode-both">
        {/* Secure Stream */}
        <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 shadow-2xl flex flex-col h-[500px]">
          <div className="flex items-center justify-between mb-6 flex-shrink-0">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-slate-400 flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-blue-500/20 flex items-center justify-center border border-blue-500/30">
                <Shield className="w-4 h-4 text-blue-400" />
              </div>
              Internal Intel Stream
            </h2>
            <Link to="/advisories?source=manual" className="group text-[10px] font-black uppercase tracking-widest text-blue-400 hover:text-white transition-colors flex items-center gap-1 bg-white/5 px-3 py-1.5 rounded-lg">
              View Database <ChevronRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
            </Link>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar pr-2 space-y-4 relative">
            {stats?.secure_advisories?.length > 0 ? (
              stats.secure_advisories.map(a => <AdvisoryCard key={a.id} advisory={a} compact />)
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-sm bg-dark-950/40 rounded-2xl border border-white/5 border-dashed">
                No internal advisories published.
              </div>
            )}
          </div>
          <div className="h-8 bg-gradient-to-t from-dark-900 to-transparent absolute bottom-6 left-6 right-6 pointer-events-none" />
        </div>

        {/* External Stream */}
        <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 shadow-2xl flex flex-col h-[500px]">
          <div className="flex items-center justify-between mb-6 flex-shrink-0">
            <h2 className="text-xs font-black uppercase tracking-[0.2em] text-slate-400 flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-purple-500/20 flex items-center justify-center border border-purple-500/30">
                <Activity className="w-4 h-4 text-purple-400" />
              </div>
              Global Threat Feed
            </h2>
            <Link to="/advisories?source=external" className="group text-[10px] font-black uppercase tracking-widest text-purple-400 hover:text-white transition-colors flex items-center gap-1 bg-white/5 px-3 py-1.5 rounded-lg">
              View Database <ChevronRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
            </Link>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar pr-2 space-y-4 relative">
            {stats?.open_source_advisories?.length > 0 ? (
              stats.open_source_advisories.map(a => <AdvisoryCard key={a.id} advisory={a} compact />)
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 text-sm bg-dark-950/40 rounded-2xl border border-white/5 border-dashed">
                No external advisories ingested.
              </div>
            )}
          </div>
          <div className="h-8 bg-gradient-to-t from-dark-900 to-transparent absolute bottom-6 left-6 right-6 pointer-events-none" />
        </div>
      </div>
    </div>
  )
}
