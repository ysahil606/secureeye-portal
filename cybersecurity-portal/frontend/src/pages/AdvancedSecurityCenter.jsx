import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity, AlertTriangle, Bot, ClipboardList, ExternalLink, Eye,
  FileText, Globe2, ListChecks, Network, Radar, Search, ShieldCheck,
  Siren, Sparkles, Target, Zap
} from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../services/api'
import { formatDateTime } from '../utils/helpers'

const riskColors = {
  Critical: 'text-red-300 border-red-700/40 bg-red-950/30',
  High: 'text-orange-300 border-orange-700/40 bg-orange-950/30',
  Medium: 'text-yellow-300 border-yellow-700/40 bg-yellow-950/30',
  Low: 'text-emerald-300 border-emerald-700/40 bg-emerald-950/30',
  Watch: 'text-blue-300 border-blue-700/40 bg-blue-950/30',
  Elevated: 'text-orange-300 border-orange-700/40 bg-orange-950/30',
}

function Panel({ title, icon: Icon, children, action }) {
  return (
    <section className="card p-5">
      <div className="flex items-center justify-between gap-3 mb-4">
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Icon className="w-4 h-4 text-blue-400" /> {title}
        </h2>
        {action}
      </div>
      {children}
    </section>
  )
}

function RiskBadge({ value }) {
  return (
    <span className={`px-2.5 py-1 rounded-full border text-xs font-semibold ${riskColors[value] || riskColors.Watch}`}>
      {value}
    </span>
  )
}

function AdvisoryLink({ item }) {
  return (
    <Link to={`/advisories/${item.id}`} className="block p-3 rounded-lg bg-dark-800 border border-dark-600 hover:border-blue-500/40 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm text-white font-medium truncate">{item.title}</div>
          <div className="text-xs text-slate-500 mt-1">
            {item.cvss_score ? `CVSS ${item.cvss_score}` : 'No CVSS'} {item.published_at ? `| ${formatDateTime(item.published_at)}` : ''}
          </div>
        </div>
        <RiskBadge value={item.severity?.[0]?.toUpperCase() + item.severity?.slice(1)} />
      </div>
    </Link>
  )
}

export default function AdvancedSecurityCenter() {
  const [overview, setOverview] = useState(null)
  const [patches, setPatches] = useState([])
  const [loading, setLoading] = useState(true)

  const [analystInput, setAnalystInput] = useState('')
  const [analystResult, setAnalystResult] = useState(null)
  const [analystLoading, setAnalystLoading] = useState(false)

  const [domain, setDomain] = useState('')
  const [surface, setSurface] = useState(null)
  const [surfaceLoading, setSurfaceLoading] = useState(false)

  const [watchText, setWatchText] = useState('')
  const [watchlist, setWatchlist] = useState(null)

  const [leakKeyword, setLeakKeyword] = useState('')
  const [leakResult, setLeakResult] = useState(null)

  const loadData = async () => {
    setLoading(true)
    try {
      const [overviewRes, patchRes] = await Promise.all([
        api.get('/advanced/overview'),
        api.get('/advanced/patch-priority'),
      ])
      setOverview(overviewRes.data)
      setPatches(patchRes.data)
    } catch {
      toast.error('Failed to load advanced security center')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadData() }, [])

  const runAnalyst = async (e) => {
    e.preventDefault()
    if (!analystInput.trim()) return
    setAnalystLoading(true)
    try {
      const r = await api.post('/advanced/threat-analyst', { query: analystInput })
      setAnalystResult(r.data)
    } catch {
      toast.error('AI analyst failed')
    } finally {
      setAnalystLoading(false)
    }
  }

  const runSurface = async (e) => {
    e.preventDefault()
    if (!domain.trim()) return
    setSurfaceLoading(true)
    try {
      const r = await api.post('/advanced/attack-surface', { domain })
      setSurface(r.data)
    } catch {
      toast.error('Attack surface scan failed')
    } finally {
      setSurfaceLoading(false)
    }
  }

  const runWatchlist = async (e) => {
    e.preventDefault()
    const keywords = watchText.split(',').map(item => item.trim()).filter(Boolean)
    if (!keywords.length) return
    try {
      const r = await api.post('/advanced/watchlist/preview', { keywords })
      setWatchlist(r.data)
    } catch {
      toast.error('Watchlist preview failed')
    }
  }

  const runLeakCheck = async (e) => {
    e.preventDefault()
    if (!leakKeyword.trim()) return
    try {
      const r = await api.post('/advanced/leak-check', { keyword: leakKeyword })
      setLeakResult(r.data)
    } catch {
      toast.error('Leak monitor failed')
    }
  }

  const stats = useMemo(() => ([
    { label: 'Total Advisories', value: overview?.total_advisories ?? 0, icon: FileText },
    { label: 'Critical', value: overview?.critical ?? 0, icon: AlertTriangle },
    { label: 'KEV Items', value: overview?.kev ?? 0, icon: Siren },
    { label: 'Tracked IOCs', value: overview?.ioc_total ?? 0, icon: Network },
  ]), [overview])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-blue-400" /> Advanced Security Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">AI triage, attack surface checks, patch priority, watchlists, and executive risk in one place.</p>
        </div>
        <RiskBadge value={overview?.risk_level || 'Watch'} />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map(({ label, value, icon: Icon }) => (
          <div key={label} className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500">{label}</div>
                <div className="text-2xl font-bold text-white mt-1">{value}</div>
              </div>
              <Icon className="w-5 h-5 text-blue-400" />
            </div>
          </div>
        ))}
      </div>

      <Panel title="Executive Mode" icon={ShieldCheck} action={<button onClick={loadData} className="btn-ghost text-sm">Refresh</button>}>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <p className="text-slate-300 leading-relaxed">
              Current business risk is <span className="font-semibold text-white">{overview?.risk_level}</span>.
              The most active sector is <span className="font-semibold text-white">{overview?.top_sector}</span>, with {overview?.new_this_week ?? 0} new advisories this week.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-4">
              {(overview?.recommended_actions || []).map(action => (
                <div key={action} className="flex items-start gap-2 text-sm text-slate-300">
                  <ListChecks className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" /> {action}
                </div>
              ))}
            </div>
          </div>
          <div className="space-y-2">
            <Link to="/admin/feeds" className="btn-primary w-full flex items-center justify-center gap-2 text-sm">
              <Activity className="w-4 h-4" /> View Live Feeds
            </Link>
            <Link to="/timeline" className="btn-ghost w-full flex items-center justify-center gap-2 text-sm border border-dark-600">
              <Radar className="w-4 h-4" /> Threat Timeline
            </Link>
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Panel title="AI Threat Analyst" icon={Bot}>
          <form onSubmit={runAnalyst} className="space-y-3">
            <textarea
              className="input min-h-[110px]"
              placeholder="Paste CVE, IOC, URL, hash, IP, or advisory text..."
              value={analystInput}
              onChange={e => setAnalystInput(e.target.value)}
            />
            <button className="btn-primary flex items-center gap-2 text-sm" disabled={analystLoading}>
              <Search className="w-4 h-4" /> {analystLoading ? 'Analyzing...' : 'Analyze Threat'}
            </button>
          </form>
          {analystResult && (
            <div className="mt-4 space-y-3">
              <div className="flex items-center gap-2">
                <RiskBadge value={analystResult.verdict} />
                <span className="text-xs text-slate-500">Confidence: {analystResult.confidence}</span>
              </div>
              <p className="text-sm text-slate-300">{analystResult.summary}</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {analystResult.recommended_actions.map(action => (
                  <div key={action} className="text-xs text-slate-300 bg-dark-800 border border-dark-600 rounded-lg p-2">{action}</div>
                ))}
              </div>
              {analystResult.matches?.map(item => <AdvisoryLink key={item.id} item={item} />)}
            </div>
          )}
        </Panel>

        <Panel title="Attack Surface Monitor" icon={Globe2}>
          <form onSubmit={runSurface} className="flex gap-2">
            <input className="input" placeholder="example.com" value={domain} onChange={e => setDomain(e.target.value)} />
            <button className="btn-primary text-sm whitespace-nowrap" disabled={surfaceLoading}>
              {surfaceLoading ? 'Scanning...' : 'Scan'}
            </button>
          </form>
          {surface && (
            <div className="mt-4 space-y-3">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-dark-800 border border-dark-600 rounded-lg p-3">
                  <div className="text-slate-500 text-xs">Resolved IP</div>
                  <div className="text-white font-mono break-all">{surface.ip || 'Unresolved'}</div>
                </div>
                <div className="bg-dark-800 border border-dark-600 rounded-lg p-3">
                  <div className="text-slate-500 text-xs">Open Ports</div>
                  <div className="text-white">{surface.open_ports?.join(', ') || 'None found'}</div>
                </div>
              </div>
              {surface.days_to_ssl_expiry !== null && (
                <div className="text-sm text-slate-300">SSL expires in {surface.days_to_ssl_expiry} days.</div>
              )}
              <div className="flex flex-wrap gap-2">
                {(surface.risks || []).map(risk => <RiskBadge key={risk} value={risk.includes('not') ? 'High' : 'Watch'} />)}
                {surface.risks?.length === 0 && <RiskBadge value="Low" />}
              </div>
              <div className="space-y-2">
                {surface.subdomains_checked?.map(item => (
                  <div key={item.host} className="text-xs font-mono text-slate-300 bg-dark-800 border border-dark-600 rounded-lg p-2">
                    {item.host} | {item.ip}
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Panel title="Patch Priority Dashboard" icon={Zap} action={<Link to="/zero-days" className="text-sm text-blue-400 hover:text-blue-300">Zero-days</Link>}>
          <div className="space-y-2 max-h-[520px] overflow-y-auto pr-1">
            {patches.map(item => (
              <div key={item.id} className="p-3 rounded-lg bg-dark-800 border border-dark-600">
                <div className="flex items-start justify-between gap-3">
                  <Link to={`/advisories/${item.id}`} className="text-sm text-white font-medium hover:text-blue-300">{item.title}</Link>
                  <span className="text-lg font-bold text-blue-300">{item.score}</span>
                </div>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {(item.why?.length ? item.why : ['Review']).map(reason => (
                    <span key={reason} className="text-[11px] text-slate-300 bg-dark-700 border border-dark-600 rounded px-2 py-0.5">{reason}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="User Watchlists" icon={Target}>
          <form onSubmit={runWatchlist} className="space-y-3">
            <input className="input" placeholder="vendors, products, sectors, domains separated by commas" value={watchText} onChange={e => setWatchText(e.target.value)} />
            <button className="btn-primary flex items-center gap-2 text-sm"><Eye className="w-4 h-4" /> Preview Matches</button>
          </form>
          {watchlist && (
            <div className="mt-4 space-y-3">
              {watchlist.matches.map(group => (
                <div key={group.keyword} className="bg-dark-800 border border-dark-600 rounded-lg p-3">
                  <div className="text-sm font-semibold text-white">{group.keyword}</div>
                  <div className="text-xs text-slate-500 mt-1">
                    {group.advisories.length} advisories | {group.iocs.length} IOCs
                  </div>
                  <div className="space-y-2 mt-2">
                    {group.advisories.slice(0, 2).map(item => <AdvisoryLink key={item.id} item={item} />)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Panel title="Leak Monitor" icon={Siren}>
          <form onSubmit={runLeakCheck} className="flex gap-2">
            <input className="input" placeholder="company.com or user@example.com" value={leakKeyword} onChange={e => setLeakKeyword(e.target.value)} />
            <button className="btn-primary text-sm whitespace-nowrap">Check</button>
          </form>
          {leakResult && (
            <div className="mt-4 space-y-3">
              <div className="flex items-center gap-2">
                <RiskBadge value={leakResult.exposure_level} />
                <span className="text-xs text-slate-500">{leakResult.keyword}</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {leakResult.signals.map(signal => (
                  <div key={signal} className="text-xs text-slate-300 bg-dark-800 border border-dark-600 rounded-lg p-2">{signal}</div>
                ))}
              </div>
            </div>
          )}
        </Panel>

        <Panel title="Connected Advanced Features" icon={ClipboardList}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { to: '/iocs', label: 'IOC Scanner', icon: Network },
              { to: '/timeline', label: 'Threat Timeline', icon: Activity },
              { to: '/zero-days', label: 'Zero-Day Tracker', icon: AlertTriangle },
              { to: '/search', label: 'Smart Search', icon: Search },
              { to: '/admin/feeds', label: 'Real-Time Feeds', icon: Radar },
              { to: '/advisories', label: 'Reports and War Rooms', icon: FileText },
            ].map(({ to, label, icon: Icon }) => (
              <Link key={to} to={to} className="flex items-center justify-between gap-3 p-3 rounded-lg bg-dark-800 border border-dark-600 hover:border-blue-500/40 transition-colors">
                <span className="flex items-center gap-2 text-sm text-slate-200"><Icon className="w-4 h-4 text-blue-400" /> {label}</span>
                <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
              </Link>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  )
}
