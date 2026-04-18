import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, LineChart, Line
} from 'recharts'
import { AlertTriangle, FileText, Shield, Bug, Clock, Cpu, Activity, TrendingUp } from 'lucide-react'
import ThreatHeatmap from './ThreatHeatmap'
import MorningBriefing from '../components/MorningBriefing'
import MITREMatrix from './MITREMatrix'
import api from '../services/api'
import AdvisoryCard from '../components/AdvisoryCard'
import { cvssColor, formatDateTime } from '../utils/helpers'
import toast from 'react-hot-toast'
import { useAuth } from '../context/AuthContext'

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#a855f7', '#06b6d4']

function StatCard({ icon: Icon, label, value, sub, color = 'blue', pulse }) {
  const colorMap = { red: 'text-red-400 bg-red-900/20 border-red-700/40', blue: 'text-blue-400 bg-blue-900/20 border-blue-700/40', yellow: 'text-yellow-400 bg-yellow-900/20 border-yellow-700/40', green: 'text-green-400 bg-green-900/20 border-green-700/40', purple: 'text-purple-400 bg-purple-900/20 border-purple-700/40' }
  const cls = colorMap[color] || colorMap.blue
  return (
    <div className={`card p-5 border ${cls.split(' ').slice(2).join(' ')}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-slate-400 text-sm">{label}</p>
          <p className={`text-3xl font-bold mt-1 ${cls.split(' ')[0]} ${pulse ? 'threat-pulse' : ''}`}>{value}</p>
          {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
        </div>
        <div className={`p-2 rounded-lg ${cls.split(' ').slice(1, 2).join(' ')}`}>
          <Icon className={`w-5 h-5 ${cls.split(' ')[0]}`} />
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { isAnalyst } = useAuth()
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

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

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
    </div>
  )

  const severityChartData = stats?.severity_breakdown ? Object.entries(stats.severity_breakdown).map(([k, v]) => ({ name: k, value: v })) : []
  const sectorData = stats?.sector_distribution || []

  return (
    <div className="space-y-6">
      <MorningBriefing />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Real-time threat intelligence overview
            {stats?.feed_last_run && (
              <span className="ml-2 text-slate-500">· Last feed: {formatDateTime(stats.feed_last_run)}</span>
            )}
          </p>
        </div>
        {isAnalyst && (
          <button onClick={handleTriggerFeed}
            className="flex items-center gap-2 bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 border border-blue-500/30 px-4 py-2 rounded-lg text-sm transition-colors">
            <Cpu className="w-4 h-4" /> Run Feeds Now
          </button>
        )}
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Shield}       label="Secure Manual"   value={stats?.manual_count ?? 0}        color="blue" />
        <StatCard icon={AlertTriangle} label="Critical Today"    value={stats?.critical_today ?? 0}       color="red"    pulse={stats?.critical_today > 0} />
        <StatCard icon={Shield}       label="Active Sectors"     value={stats?.active_sectors ?? 0}       color="green" />
        <StatCard icon={Bug}          label="Zero-Days Tracked"  value={stats?.zero_days_tracked ?? 0}    color="purple" />
        {isAnalyst && (
          <StatCard icon={Clock}      label="Pending Review"     value={stats?.pending_review ?? 0}       color="yellow" />
        )}
        <StatCard icon={TrendingUp}   label="Published This Week" value={stats?.published_this_week ?? 0} color="green" />
        <StatCard icon={Activity}     label="CISA KEV Items"     value={stats?.kev_count ?? 0}            color="red" />
        <StatCard icon={Activity}     label="External Feeds"     value={stats?.external_count ?? 0}      color="blue" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity distribution */}
        <div className="card p-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-400" /> Severity Distribution
          </h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityChartData} barCategoryGap="30%">
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#f1f5f9' }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {severityChartData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Sector distribution */}
        <div className="card p-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-green-400" /> Sector Threat Distribution
          </h2>
          {sectorData.length > 0 ? (
            <div className="space-y-2.5">
              {sectorData.map((s, i) => (
                <div key={s.sector}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-slate-300">{s.sector}</span>
                    <span className="text-slate-400">{s.count} ({s.percentage}%)</span>
                  </div>
                  <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${s.percentage}%`, background: COLORS[i % COLORS.length] }} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-40 text-slate-500 text-sm">
              No sector data yet — run feeds or publish advisories
            </div>
          )}
        </div>
      </div>

      {/* Trending CVEs Section */}
      {stats?.trending_cves?.length > 0 && (
        <div className="card p-5">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-orange-400" /> Trending Vulnerabilities
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {stats.trending_cves.map((cve, i) => (
              <div key={i} className="bg-dark-800 rounded-lg p-3 border border-dark-600">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-sm text-blue-400 font-semibold">{cve.cve_id}</span>
                  {cve.cvss_score && (
                    <span className={`text-sm font-bold ${cvssColor(cve.cvss_score)}`}>{cve.cvss_score}</span>
                  )}
                </div>
                <p className="text-xs text-slate-400 leading-snug line-clamp-2">{cve.title}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE Matrix Section */}
      <MITREMatrix />

      {/* Heatmap Section */}
      {ThreatHeatmap && <ThreatHeatmap />}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-400" /> Secure Advisory
            </h2>
            <Link to="/advisories?source=manual" className="text-sm text-blue-400 hover:text-blue-300 transition-colors">
              View all →
            </Link>
          </div>
          <div className="space-y-3">
            {stats?.secure_advisories?.length > 0 ? (
              stats.secure_advisories.map(a => <AdvisoryCard key={a.id} advisory={a} compact />)
            ) : (
              <div className="card p-8 text-center text-slate-500">
                No internal advisories yet.
              </div>
            )}
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-green-400" /> Open Source Advisory
            </h2>
            <Link to="/advisories?source=external" className="text-sm text-blue-400 hover:text-blue-300 transition-colors">
              View all →
            </Link>
          </div>
          <div className="space-y-3">
            {stats?.open_source_advisories?.length > 0 ? (
              stats.open_source_advisories.map(a => <AdvisoryCard key={a.id} advisory={a} compact />)
            ) : (
              <div className="card p-8 text-center text-slate-500">
                No open-source advisories yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
