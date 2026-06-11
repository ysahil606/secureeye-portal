import { useState, useCallback } from 'react'
import {
  Activity, AlertTriangle, CheckCircle2, Copy, Database, Download, Eye,
  ExternalLink, Ghost, Globe, Loader2, Lock, Mail, Plus, Search,
  ShieldCheck, ShieldAlert, Shield, Trash2, X, Server, Wifi, Key,
  BarChart3, Fingerprint, Clock, Terminal, ChevronDown, ChevronRight,
  AlertCircle, Info, Cpu
} from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'
import clsx from 'clsx'

// ── helpers ─────────────────────────────────────────────────────────────────
const SEVERITY_META = {
  critical: { label: 'Critical', cls: 'text-red-400 bg-red-500/10 border-red-500/25' },
  high:     { label: 'High',     cls: 'text-orange-400 bg-orange-500/10 border-orange-500/25' },
  medium:   { label: 'Medium',   cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25' },
  low:      { label: 'Low',      cls: 'text-green-400  bg-green-500/10  border-green-500/25' },
}

const EXPOSURE_META = {
  Critical: { color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30',    bar: 'bg-red-500',    label: 'CRITICAL EXPOSURE' },
  Elevated: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', bar: 'bg-orange-500', label: 'ELEVATED EXPOSURE' },
  Watch:    { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', bar: 'bg-yellow-500', label: 'WATCHLIST' },
  Low:      { color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30',  bar: 'bg-green-500',  label: 'LOW EXPOSURE' },
}

const SOURCE_ICON = {
  '🔍': <Search className="w-3.5 h-3.5" />,
  '🦠': <AlertTriangle className="w-3.5 h-3.5" />,
  '🎯': <Fingerprint className="w-3.5 h-3.5" />,
  '🎣': <AlertCircle className="w-3.5 h-3.5" />,
  '🔐': <Lock className="w-3.5 h-3.5" />,
  '🔭': <Cpu className="w-3.5 h-3.5" />,
  '🗄️': <Database className="w-3.5 h-3.5" />,
  '🔴': <ShieldAlert className="w-3.5 h-3.5" />,
  '🌐': <Globe className="w-3.5 h-3.5" />,
  '📡': <Wifi className="w-3.5 h-3.5" />,
  '📋': <Database className="w-3.5 h-3.5" />,
}

// ── Data class chip config ─────────────────────────────────────────────────────
const DATA_CLASS_META = {
  'Passwords':              { icon: '🔑', cls: 'bg-red-500/15 border-red-500/30 text-red-400' },
  'Email addresses':        { icon: '📧', cls: 'bg-blue-500/15 border-blue-500/30 text-blue-400' },
  'Phone numbers':          { icon: '📱', cls: 'bg-green-500/15 border-green-500/30 text-green-400' },
  'Names':                  { icon: '👤', cls: 'bg-slate-600/40 border-slate-600/50 text-slate-300' },
  'Usernames':              { icon: '🎭', cls: 'bg-purple-500/15 border-purple-500/30 text-purple-400' },
  'Physical addresses':     { icon: '📍', cls: 'bg-orange-500/15 border-orange-500/30 text-orange-400' },
  'Geographic locations':   { icon: '🌍', cls: 'bg-orange-500/15 border-orange-500/30 text-orange-400' },
  'Dates of birth':         { icon: '🎂', cls: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-400' },
  'IP addresses':           { icon: '🌐', cls: 'bg-cyan-500/15 border-cyan-500/30 text-cyan-400' },
  'Credit cards':           { icon: '💳', cls: 'bg-red-500/20 border-red-500/40 text-red-300 font-black' },
  'Social security numbers':{ icon: '🇺🇸', cls: 'bg-red-500/20 border-red-500/40 text-red-300 font-black' },
  'Auth tokens':            { icon: '🔐', cls: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-400' },
  'Social media profiles':  { icon: '🔗', cls: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-400' },
  'Gender':                 { icon: '♀', cls: 'bg-slate-600/40 border-slate-600/50 text-slate-400' },
  'Employers':              { icon: '🏢', cls: 'bg-slate-600/40 border-slate-600/50 text-slate-400' },
  'Job titles':             { icon: '💼', cls: 'bg-slate-600/40 border-slate-600/50 text-slate-400' },
}

function DataClassChips({ classes = [], max = 4 }) {
  if (!classes || classes.length === 0) return <span className="text-xs text-slate-600">—</span>
  const shown = classes.slice(0, max)
  const extra = classes.length - max
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map(c => {
        const m = DATA_CLASS_META[c] || { icon: '📄', cls: 'bg-slate-700/60 border-slate-600/50 text-slate-400' }
        return (
          <span key={c} className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold border ${m.cls}`}>
            <span>{m.icon}</span>{c}
          </span>
        )
      })}
      {extra > 0 && (
        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold border border-slate-700 bg-slate-800 text-slate-500">+{extra} more</span>
      )}
    </div>
  )
}

function SeverityBadge({ severity }) {
  const m = SEVERITY_META[severity] || SEVERITY_META.medium
  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-widest border', m.cls)}>
      {m.label}
    </span>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, sub, color = 'text-white', accent = 'purple' }) {
  const glowMap = { red: 'hover:border-red-500/30', orange: 'hover:border-orange-500/30', purple: 'hover:border-purple-500/30', green: 'hover:border-green-500/30', blue: 'hover:border-blue-500/30' }
  return (
    <div className={clsx('relative rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-sm transition-all', glowMap[accent])}>
      <div className="flex items-start justify-between mb-3">
        <div className="p-2 rounded-xl bg-slate-800 border border-slate-700">
          <Icon className={clsx('w-4 h-4', color)} />
        </div>
        {sub && <span className="text-[10px] text-slate-600 font-mono uppercase">{sub}</span>}
      </div>
      <div className={clsx('text-3xl font-black tabular-nums mb-0.5', color)}>{value ?? '—'}</div>
      <div className="text-xs text-slate-500 font-bold uppercase tracking-widest">{label}</div>
    </div>
  )
}

// ── Leak row ─────────────────────────────────────────────────────────────────
function LeakRow({ leak, resolved, onResolve, onSelect }) {
  const isResolved = resolved.includes(leak.id || leak.email)
  return (
    <tr
      className={clsx('group transition-colors cursor-pointer border-b border-slate-800/60',
        isResolved ? 'opacity-40' : 'hover:bg-white/[0.025]'
      )}
      onClick={() => onSelect(leak)}
    >
      {/* Resolved checkbox */}
      <td className="p-3 pl-4 w-8">
        <div className="w-4 h-4 rounded border border-slate-700 group-hover:border-purple-500/60 mx-auto flex items-center justify-center transition-colors">
          {isResolved && <CheckCircle2 className="w-3 h-3 text-green-400" />}
        </div>
      </td>

      {/* Source */}
      <td className="p-3 max-w-[160px]">
        <div className="flex items-center gap-1.5">
          <Globe className="w-3 h-3 text-slate-600 shrink-0" />
          <span className="text-[11px] text-slate-400 truncate font-mono">{leak.source || 'Unknown'}</span>
        </div>
      </td>

      {/* Identity */}
      <td className="p-3">
        <div className="flex items-center gap-1.5">
          {leak.has_password && <Lock className="w-3 h-3 text-red-400 shrink-0" title="Password in breach" />}
          <span className="font-mono text-sm text-white font-semibold truncate max-w-[180px]">{leak.email}</span>
        </div>
        {leak.breach_size > 0 && (
          <div className="text-[10px] text-slate-600 mt-0.5 font-mono">{leak.breach_size.toLocaleString()} records</div>
        )}
      </td>

      {/* Data leaked — the KEY column */}
      <td className="p-3">
        <DataClassChips classes={leak.data_classes} max={3} />
      </td>

      {/* Severity */}
      <td className="p-3">
        <SeverityBadge severity={leak.severity} />
      </td>

      {/* Date */}
      <td className="p-3 text-[11px] text-slate-500 font-mono whitespace-nowrap">{leak.date || '—'}</td>

      {/* Action */}
      <td className="p-3 pr-4">
        <button
          onClick={e => { e.stopPropagation(); onResolve(leak) }}
          disabled={isResolved}
          className="text-[10px] font-bold text-slate-600 hover:text-green-400 transition-colors uppercase tracking-wider disabled:opacity-30"
        >
          {isResolved ? '✓ Done' : 'Resolve'}
        </button>
      </td>
    </tr>
  )
}

// ── Mention card ──────────────────────────────────────────────────────────────
function MentionCard({ mention }) {
  const meta = SEVERITY_META[mention.severity] || SEVERITY_META.medium
  const icon = SOURCE_ICON[mention.source_icon] || <AlertTriangle className="w-3.5 h-3.5" />
  return (
    <div className={clsx('rounded-xl border p-4 transition-all hover:bg-white/[0.02]',
      mention.severity === 'critical' ? 'border-red-500/20 bg-red-950/10' :
      mention.severity === 'high'     ? 'border-orange-500/20 bg-orange-950/10' :
                                        'border-slate-800 bg-slate-900/40'
    )}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={clsx('p-1 rounded', meta.cls)}>{icon}</span>
            <span className="text-sm text-white font-semibold leading-snug truncate">{mention.title}</span>
            <SeverityBadge severity={mention.severity} />
          </div>
          {mention.snippet && (
            <p className="text-xs text-slate-400 leading-5 italic mt-1 line-clamp-2">"{mention.snippet}"</p>
          )}
          <div className="flex items-center gap-3 mt-2">
            <span className="text-[10px] font-mono text-slate-600 uppercase">{mention.onion_site}</span>
          </div>
        </div>
        {mention.url && (
          <a
            href={mention.url}
            target="_blank"
            rel="noreferrer"
            onClick={e => e.stopPropagation()}
            className="flex items-center gap-1 text-[10px] font-bold text-purple-400 hover:text-white bg-purple-500/10 hover:bg-purple-500/20 px-2.5 py-1.5 rounded-lg border border-purple-500/20 transition-all uppercase tracking-widest shrink-0"
          >
            <ExternalLink className="w-3 h-3" /> View
          </a>
        )}
      </div>
    </div>
  )
}

// ── Source health grid ────────────────────────────────────────────────────────
function SourceHealthGrid({ sourceHealth, sourcesChecked }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
      {Object.entries(sourceHealth || {}).map(([name, meta]) => (
        <div key={name} className={clsx(
          'rounded-lg border p-3 flex items-start gap-2',
          meta.status === 'error'   ? 'border-red-500/20 bg-red-950/10' :
          meta.records > 0          ? 'border-green-500/20 bg-green-950/10' :
                                      'border-slate-800 bg-slate-900/40'
        )}>
          <span className={clsx('mt-0.5 shrink-0',
            meta.status === 'error'   ? 'text-red-400' :
            meta.records > 0          ? 'text-green-400' : 'text-slate-600'
          )}>
            {meta.status === 'error' ? <AlertCircle className="w-3.5 h-3.5" /> :
             meta.records > 0        ? <CheckCircle2 className="w-3.5 h-3.5" /> :
                                       <ShieldCheck className="w-3.5 h-3.5" />}
          </span>
          <div className="min-w-0">
            <div className="text-xs text-slate-300 font-semibold truncate">{name}</div>
            <div className={clsx('text-[10px] font-mono',
              meta.status === 'error' ? 'text-red-400' :
              meta.records > 0        ? 'text-green-400' : 'text-slate-600'
            )}>
              {meta.status === 'error' ? 'Timed out' : meta.records > 0 ? `${meta.records} finding${meta.records !== 1 ? 's' : ''}` : 'Clean'}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Shodan panel ──────────────────────────────────────────────────────────────
function ShodanPanel({ intel }) {
  if (!intel) return null
  return (
    <div className="rounded-xl border border-blue-500/20 bg-blue-950/10 p-5">
      <div className="flex items-center gap-2 mb-4">
        <Cpu className="w-4 h-4 text-blue-400" />
        <span className="text-sm font-bold text-blue-300 uppercase tracking-widest">Shodan InternetDB — {intel.ip}</span>
        <a href={`https://www.shodan.io/host/${intel.ip}`} target="_blank" rel="noreferrer"
          className="ml-auto flex items-center gap-1 text-[10px] font-bold text-blue-400 hover:text-white transition uppercase tracking-wider">
          View <ExternalLink className="w-3 h-3" />
        </a>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
          <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Open Ports</div>
          <div className="flex flex-wrap gap-1">
            {(intel.ports || []).slice(0, 8).map(p => (
              <span key={p} className="text-[10px] font-mono bg-blue-500/10 border border-blue-500/20 text-blue-300 rounded px-1.5 py-0.5">{p}</span>
            ))}
            {!intel.ports?.length && <span className="text-xs text-slate-600">None</span>}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
          <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">CVEs Detected</div>
          <div className="flex flex-wrap gap-1">
            {(intel.vulns || []).slice(0, 6).map(v => (
              <span key={v} className="text-[10px] font-mono bg-red-500/10 border border-red-500/20 text-red-300 rounded px-1.5 py-0.5">{v}</span>
            ))}
            {!intel.vulns?.length && <span className="text-xs text-slate-600">None</span>}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
          <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Tags</div>
          <div className="flex flex-wrap gap-1">
            {(intel.tags || []).map(t => (
              <span key={t} className="text-[10px] font-mono bg-slate-700 text-slate-300 rounded px-1.5 py-0.5">{t}</span>
            ))}
            {!intel.tags?.length && <span className="text-xs text-slate-600">None</span>}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
          <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Hostnames</div>
          <div className="space-y-0.5">
            {(intel.hostnames || []).slice(0, 3).map(h => (
              <div key={h} className="text-[10px] font-mono text-slate-400 truncate">{h}</div>
            ))}
            {!intel.hostnames?.length && <span className="text-xs text-slate-600">None</span>}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Leak detail modal ─────────────────────────────────────────────────────────
function LeakModal({ leak, onClose, onResolve, resolved }) {
  const isResolved = resolved.includes(leak.id || leak.email)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl rounded-2xl border border-purple-500/25 bg-slate-950 shadow-2xl p-6 relative animate-in zoom-in-95 duration-200">
        <button onClick={onClose} className="absolute top-4 right-4 p-1.5 text-slate-500 hover:text-white hover:bg-white/10 rounded-lg transition-colors">
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3 border-b border-white/5 pb-4 mb-5 pr-10">
          <div className="w-10 h-10 rounded-xl bg-purple-500/15 flex items-center justify-center border border-purple-500/30">
            <ShieldAlert className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <div className="text-base font-bold text-white">{leak.source}</div>
            <div className="text-xs text-slate-500 flex items-center gap-2 mt-0.5">
              <Clock className="w-3 h-3" /> Indexed: {leak.date || 'Unknown'}
            </div>
          </div>
          <div className="ml-auto"><SeverityBadge severity={leak.severity} /></div>
        </div>

        <div className="grid grid-cols-2 gap-3 mb-4">
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-4">
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1.5">Identity / Account</div>
            <div className="font-mono text-white text-sm break-all">{leak.email}</div>
          </div>
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-4">
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1.5">Status</div>
            <div className={clsx('text-sm font-bold', isResolved ? 'text-green-400' : 'text-orange-400')}>
              {isResolved ? '✓ Resolved' : '⚠ Open — Action Required'}
            </div>
          </div>
        </div>

        {leak.data_classes?.length > 0 && (
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 mb-4">
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Leaked Data Classes</div>
            <div className="flex flex-wrap gap-1.5">
              {leak.data_classes.map(c => (
                <span key={c} className={clsx(
                  'px-2 py-0.5 rounded text-[10px] font-bold border',
                  c === 'Passwords' ? 'bg-red-500/10 border-red-500/25 text-red-400' :
                  c === 'Email addresses' ? 'bg-blue-500/10 border-blue-500/25 text-blue-400' :
                  'bg-slate-800 border-slate-700 text-slate-400'
                )}>{c}</span>
              ))}
            </div>
          </div>
        )}

        <div className="rounded-xl bg-slate-900 border border-slate-800 p-4 mb-5">
          <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Exposure Detail</div>
          <p className="text-sm text-slate-300 leading-relaxed">
            {leak.hint || 'Credential exposure confirmed. Raw data is redacted to prevent misuse.'}
          </p>
          <div className="flex flex-wrap gap-2 mt-3">
            {leak.has_password && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 bg-red-500/10 border border-red-500/20 text-red-400 rounded text-[10px] font-bold">
                <Lock className="w-3 h-3" /> Password in breach
              </span>
            )}
            {leak.email && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded text-[10px] font-bold">
                <Mail className="w-3 h-3" /> Identity exposed
              </span>
            )}
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-5 py-2 rounded-lg border border-slate-700 text-slate-400 hover:text-white text-sm font-bold transition-colors">
            Close
          </button>
          {!isResolved && (
            <button
              onClick={() => { onResolve(leak); onClose() }}
              className="flex items-center gap-2 px-5 py-2 bg-green-500/15 hover:bg-green-500/25 border border-green-500/35 text-green-400 text-sm font-bold rounded-lg transition-colors"
            >
              <CheckCircle2 className="w-4 h-4" /> Mark Resolved
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Tabs config ───────────────────────────────────────────────────────────────
const TABS = [
  { id: 'leaks',    label: 'Credential Leaks', Icon: Key },
  { id: 'mentions', label: 'Threat Mentions',  Icon: AlertTriangle },
  { id: 'intel',    label: 'Host Intel',       Icon: Server },
  { id: 'sources',  label: 'Source Status',    Icon: Activity },
  { id: 'actions',  label: 'Remediation',      Icon: ShieldCheck },
]

// ── Main component ────────────────────────────────────────────────────────────
export default function DarkWebMonitor() {
  const [query,       setQuery]       = useState('')
  const [watchInput,  setWatchInput]  = useState('')
  const [scanning,    setScanning]    = useState(false)
  const [results,     setResults]     = useState(null)
  const [tab,         setTab]         = useState('leaks')
  const [selectedLeak,setSelectedLeak]= useState(null)
  const [expandedIds, setExpandedIds] = useState(new Set())

  const [watchlist, setWatchlist] = useState(() => {
    try { return JSON.parse(localStorage.getItem('darkweb_watchlist') || '[]') } catch { return [] }
  })
  const [resolved, setResolved] = useState(() => {
    try { return JSON.parse(localStorage.getItem('darkweb_resolved') || '[]') } catch { return [] }
  })

  const saveWatchlist = useCallback(next => {
    setWatchlist(next)
    localStorage.setItem('darkweb_watchlist', JSON.stringify(next))
  }, [])

  const saveResolved = useCallback(next => {
    setResolved(next)
    localStorage.setItem('darkweb_resolved', JSON.stringify(next))
  }, [])

  const runScan = async (target) => {
    const q = target.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase()
    if (!q) return
    setQuery(q)
    setScanning(true)
    setResults(null)
    setTab('leaks')
    try {
      const res = await api.get('/darkweb/scan', { params: { q } })
      setResults(res.data)
    } catch {
      toast.error('Dark web scan failed. Backend may be unavailable.')
    } finally {
      setScanning(false)
    }
  }

  const addWatch = (e) => {
    e.preventDefault()
    const item = watchInput.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase()
    if (!item || watchlist.includes(item)) return
    saveWatchlist([item, ...watchlist].slice(0, 12))
    setWatchInput('')
    toast.success('Added to watchlist')
  }

  const markResolved = (leak) => {
    const id = leak.id || leak.email
    saveResolved([...new Set([...resolved, id])])
    toast.success('Marked as resolved')
  }

  const copyEmails = async () => {
    const emails = (results?.leaks || []).map(l => l.email).filter(Boolean).join('\n')
    if (!emails) return
    await navigator.clipboard.writeText(emails)
    toast.success('Copied to clipboard')
  }

  const exportCsv = () => {
    if (!results) return
    const rows = [
      ['type','identity','source','date','severity','has_password','hint','status'],
      ...(results.leaks || []).map(l => ['leak', l.email, l.source, l.date, l.severity, l.has_password, l.hint, resolved.includes(l.id || l.email) ? 'resolved' : 'open']),
      ...(results.mentions || []).map(m => ['mention', m.title, m.onion_site, '', m.severity, '', m.snippet, 'open']),
    ]
    const csv = rows.map(r => r.map(v => `"${String(v || '').replaceAll('"', '""')}"`).join(',')).join('\n')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    a.download = `darkweb-scan-${results.query || 'export'}.csv`
    a.click()
  }

  const leakCount    = results?.leaks?.length ?? 0
  const mentionCount = results?.mentions?.length ?? 0
  const resolvedCount = (results?.leaks || []).filter(l => resolved.includes(l.id || l.email)).length
  const exposure = EXPOSURE_META[results?.exposure_level] || EXPOSURE_META.Low
  const summary = results?.exposure_summary || {}

  return (
    <div className="space-y-6 animate-in fade-in duration-500">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-5 border-b border-white/5">
        <div>
          <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-fuchsia-400 to-pink-400 flex items-center gap-3">
            <div className="p-2.5 bg-gradient-to-br from-purple-600/80 to-pink-600/80 rounded-xl border border-purple-500/30 shadow-lg">
              <Ghost className="w-6 h-6 text-white" />
            </div>
            Dark Web Monitor
          </h1>
          <p className="text-slate-500 text-sm mt-1.5 max-w-lg">
            Real-time breach detection across 14+ intelligence sources. Enter a domain, email, or hash.
          </p>
        </div>
        {results && (
          <div className="flex gap-2">
            <button onClick={copyEmails} className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 text-sm font-bold transition-all">
              <Copy className="w-4 h-4" /> Copy IDs
            </button>
            <button onClick={exportCsv} className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 text-sm font-bold transition-all">
              <Download className="w-4 h-4" /> Export CSV
            </button>
          </div>
        )}
      </div>

      {/* ── Search bar ─────────────────────────────────────────────────────── */}
      <div className="relative">
        <div className="absolute -inset-px rounded-2xl bg-gradient-to-r from-purple-500/20 via-transparent to-pink-500/20 blur-sm" />
        <div className="relative rounded-2xl border border-slate-800 bg-slate-950/80 backdrop-blur-xl p-5">
          <form onSubmit={e => { e.preventDefault(); runScan(query) }} className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-purple-400 pointer-events-none" />
              <input
                type="text"
                placeholder="Enter domain (corp.com), email (user@corp.com), or password hash..."
                className="w-full bg-slate-900/60 border border-slate-700/60 text-white rounded-xl pl-12 pr-4 py-3.5 text-sm placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/40 focus:border-purple-500/40 transition-all"
                value={query}
                onChange={e => setQuery(e.target.value)}
                disabled={scanning}
              />
            </div>
            <button
              type="submit"
              disabled={scanning || !query.trim()}
              className="sm:w-auto w-full flex items-center justify-center gap-2 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 disabled:opacity-40 text-white font-black px-7 py-3.5 rounded-xl transition-all text-sm uppercase tracking-widest"
            >
              {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              {scanning ? 'Scanning...' : 'Initiate Scan'}
            </button>
          </form>

          {/* Watchlist */}
          <div className="mt-4 pt-4 border-t border-white/5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mr-1">Watchlist:</span>
              {watchlist.map(item => (
                <div key={item} className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1">
                  <button onClick={() => runScan(item)} className="text-xs text-slate-400 hover:text-purple-300 font-mono transition-colors">{item}</button>
                  <button onClick={() => saveWatchlist(watchlist.filter(w => w !== item))} className="ml-1 text-slate-700 hover:text-red-400 transition-colors">
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))}
              <form onSubmit={addWatch} className="flex items-center gap-1.5">
                <input
                  className="text-xs bg-slate-900 border border-slate-800 text-white rounded-lg px-2.5 py-1 placeholder-slate-700 focus:outline-none focus:border-purple-500/40 w-32 transition-all"
                  placeholder="add domain..."
                  value={watchInput}
                  onChange={e => setWatchInput(e.target.value)}
                />
                <button type="submit" className="text-[10px] font-bold text-purple-400 hover:text-white px-2 py-1 rounded border border-purple-500/30 hover:border-purple-400 transition-all uppercase">
                  <Plus className="w-3 h-3" />
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>

      {/* ── Scanning state ─────────────────────────────────────────────────── */}
      {scanning && (
        <div className="py-24 flex flex-col items-center justify-center gap-8 animate-in zoom-in duration-500">
          <div className="relative w-28 h-28">
            <div className="absolute inset-0 bg-purple-500/10 blur-3xl rounded-full animate-pulse" />
            <div className="w-28 h-28 border-[3px] border-slate-800 border-t-purple-500 rounded-full animate-spin" />
            <div className="absolute inset-[10px] border-[2px] border-slate-800 border-b-pink-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.2s' }} />
            <Ghost className="absolute inset-0 m-auto w-9 h-9 text-purple-400 animate-pulse" />
          </div>
          <div className="text-center">
            <h3 className="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400 tracking-widest uppercase animate-pulse mb-2">
              Deep Crawling Intelligence Networks
            </h3>
            <p className="text-xs text-slate-500 font-mono">Querying: HIBP · URLScan · URLhaus · ThreatFox · Shodan · IntelX · LeakCheck · XposedOrNot · crt.sh · HackerTarget · OpenPhish · GreyNoise · AlienVault OTX · Pastebin · Wayback</p>
          </div>
        </div>
      )}

      {/* ── Results ─────────────────────────────────────────────────────────── */}
      {results && !scanning && (
        <div className="space-y-5 animate-in slide-in-from-bottom-4 duration-500">

          {/* ── Exposure banner ──────────────────────────────────────────── */}
          <div className={clsx('rounded-2xl border p-5', exposure.bg, exposure.border)}>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className={clsx('p-2.5 rounded-xl border', exposure.bg, exposure.border)}>
                  <ShieldAlert className={clsx('w-5 h-5', exposure.color)} />
                </div>
                <div>
                  <div className={clsx('text-xs font-black uppercase tracking-widest', exposure.color)}>{exposure.label}</div>
                  <div className="text-lg font-extrabold text-white">{results.query}</div>
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Clock className="w-3.5 h-3.5" />
                {results.scanned_at ? new Date(results.scanned_at).toLocaleString() : 'Scan complete'}
              </div>
            </div>
          </div>

          {/* ── Stat grid ────────────────────────────────────────────────── */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <StatCard icon={Key}         label="Credential Leaks"    value={leakCount}                           color="text-red-400"    accent="red"    />
            <StatCard icon={Lock}        label="With Passwords"      value={summary.password_exposure_count ?? 0} color="text-orange-400" accent="orange" />
            <StatCard icon={Fingerprint} label="Unique Identities"   value={summary.exposed_identities ?? 0}     color="text-purple-400" accent="purple" />
            <StatCard icon={AlertTriangle} label="Threat Mentions"   value={mentionCount}                        color="text-yellow-400" accent="orange" />
            <StatCard icon={Server}      label="Host Signals"        value={summary.compromised_endpoint_signals ?? 0} color="text-blue-400" accent="blue" />
            <StatCard icon={CheckCircle2} label="Resolved"           value={resolvedCount}                       color="text-green-400"  accent="green"  />
          </div>

          {/* Data classes */}
          {summary.data_classes?.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Leaked Data Classes</div>
              <div className="flex flex-wrap gap-1.5">
                {summary.data_classes.map(c => (
                  <span key={c} className={clsx(
                    'px-2.5 py-0.5 rounded-full text-[10px] font-bold border',
                    c === 'Passwords' ? 'bg-red-500/10 border-red-500/25 text-red-400' :
                    'bg-slate-800 border-slate-700 text-slate-400'
                  )}>{c}</span>
                ))}
              </div>
            </div>
          )}

          {/* ── Tabs ─────────────────────────────────────────────────────── */}
          <div className="flex border-b border-slate-800 gap-1 overflow-x-auto">
            {TABS.map(({ id, label, Icon }) => {
              const count = id === 'leaks' ? leakCount : id === 'mentions' ? mentionCount : null
              return (
                <button
                  key={id}
                  onClick={() => setTab(id)}
                  className={clsx(
                    'flex items-center gap-2 px-4 py-3 text-xs font-bold uppercase tracking-widest whitespace-nowrap transition-all border-b-2 -mb-px',
                    tab === id
                      ? 'text-purple-400 border-purple-500'
                      : 'text-slate-500 border-transparent hover:text-slate-300'
                  )}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {label}
                  {count != null && count > 0 && (
                    <span className={clsx('rounded-full px-1.5 text-[9px] font-black', tab === id ? 'bg-purple-500/20 text-purple-300' : 'bg-slate-800 text-slate-500')}>
                      {count}
                    </span>
                  )}
                </button>
              )
            })}
          </div>

          {/* ── Tab content ──────────────────────────────────────────────── */}
          <div className="animate-in fade-in duration-300">

            {/* Credential Leaks */}
            {tab === 'leaks' && (
              leakCount > 0 ? (
                <div className="rounded-xl border border-slate-800 overflow-hidden">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b border-slate-800 bg-slate-900/80">
                      <tr className="text-[10px] font-black uppercase tracking-widest text-slate-500">
                        <th className="p-3 pl-4 w-8"></th>
                        <th className="p-3">Source</th>
                        <th className="p-3">Identity / Account</th>
                        <th className="p-3">Data Leaked</th>
                        <th className="p-3">Severity</th>
                        <th className="p-3">Date</th>
                        <th className="p-3 pr-4"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.leaks.map((leak, i) => (
                        <LeakRow key={leak.id || i} leak={leak} resolved={resolved} onResolve={markResolved} onSelect={setSelectedLeak} />
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-16 text-center rounded-2xl border border-green-500/15 bg-green-950/10">
                  <ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-3" />
                  <h3 className="text-white font-bold mb-1">No Credential Leaks Found</h3>
                  <p className="text-sm text-slate-500">Target is currently clean across all indexed breach sources.</p>
                </div>
              )
            )}

            {/* Threat Mentions */}
            {tab === 'mentions' && (
              mentionCount > 0 ? (
                <div className="space-y-3">
                  {results.mentions.map((m, i) => <MentionCard key={m.id || i} mention={m} />)}
                </div>
              ) : (
                <div className="py-16 text-center rounded-2xl border border-slate-800 bg-slate-900/40">
                  <Activity className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                  <h3 className="text-white font-bold mb-1">No Threat Mentions</h3>
                  <p className="text-sm text-slate-500">No malicious activity or forum mentions detected.</p>
                </div>
              )
            )}

            {/* Host Intel */}
            {tab === 'intel' && (
              <div className="space-y-4">
                <ShodanPanel intel={results.shodan_intel} />
                {results.reputation && (
                  <div className="rounded-xl border border-blue-500/20 bg-blue-950/10 p-5">
                    <div className="flex items-center gap-2 mb-4">
                      <Mail className="w-4 h-4 text-blue-400" />
                      <span className="text-sm font-bold text-blue-300 uppercase tracking-widest">EmailRep.io Reputation</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      {Object.entries(results.reputation.details || {}).map(([key, val]) => (
                        <div key={key} className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                          <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">{key.replace(/_/g, ' ')}</div>
                          <div className={clsx('text-sm font-bold', val === true ? 'text-red-400' : val === false ? 'text-green-400' : 'text-slate-300')}>
                            {Array.isArray(val) ? val.join(', ') || 'None' : String(val)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {!results.shodan_intel && !results.reputation && (
                  <div className="py-16 text-center rounded-2xl border border-slate-800 bg-slate-900/40">
                    <Server className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                    <h3 className="text-white font-bold mb-1">No Host Intel</h3>
                    <p className="text-sm text-slate-500">Scan a domain to see IP reputation and Shodan data.</p>
                  </div>
                )}
              </div>
            )}

            {/* Source Status */}
            {tab === 'sources' && (
              <div className="space-y-4">
                <SourceHealthGrid sourceHealth={results.source_health} sourcesChecked={results.sources_checked} />
                {results.premium_sources_skipped?.length > 0 && (
                  <div className="rounded-xl border border-amber-500/20 bg-amber-950/10 p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <Info className="w-4 h-4 text-amber-400" />
                      <span className="text-sm font-bold text-amber-300">Premium Sources Skipped</span>
                    </div>
                    <p className="text-xs text-slate-400 mb-3">Add API keys to <code className="text-amber-300 bg-slate-900 px-1.5 py-0.5 rounded">backend/.env</code> to activate:</p>
                    <div className="flex flex-wrap gap-2">
                      {results.premium_sources_skipped.map(s => (
                        <span key={s} className="px-2.5 py-1 bg-amber-500/10 border border-amber-500/25 text-amber-400 rounded-full text-[10px] font-bold">{s}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Remediation */}
            {tab === 'actions' && (
              <div className="space-y-2">
                {(results.recommendations || []).map((item, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <CheckCircle2 className="w-4 h-4 shrink-0 text-green-400 mt-0.5" />
                    <span className="text-sm text-slate-300">{item}</span>
                  </div>
                ))}
                <div className="rounded-xl border border-purple-500/15 bg-purple-950/10 p-4 mt-3">
                  <div className="flex items-start gap-3">
                    <Info className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                    <p className="text-xs text-slate-400 leading-5">{summary.note}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Empty state ──────────────────────────────────────────────────────── */}
      {!results && !scanning && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 pt-6">
          {[
            { Icon: Key,       title: 'Credential Leaks',  desc: 'Detect exposed emails, passwords, and account credentials across breach databases.', color: 'text-red-400',    glow: 'group-hover:shadow-red-500/10' },
            { Icon: Terminal,  title: 'Threat Intelligence',desc: 'Scan URLhaus, ThreatFox, OpenPhish, and OSINT sources for active threats.', color: 'text-purple-400', glow: 'group-hover:shadow-purple-500/10' },
            { Icon: Server,    title: 'Host Exposure',     desc: 'Interrogate Shodan InternetDB, crt.sh, and HackerTarget for infrastructure risks.', color: 'text-blue-400',   glow: 'group-hover:shadow-blue-500/10' },
          ].map(({ Icon, title, desc, color, glow }) => (
            <div key={title} className={clsx('group rounded-2xl border border-slate-800 bg-slate-900/50 p-7 flex flex-col items-center text-center gap-4 hover:border-slate-700 transition-all shadow-lg', glow)}>
              <div className="w-14 h-14 rounded-2xl bg-slate-800 border border-slate-700 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Icon className={clsx('w-7 h-7', color)} />
              </div>
              <div>
                <h3 className="font-extrabold text-white mb-1.5">{title}</h3>
                <p className="text-xs text-slate-500 leading-5">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Leak detail modal ──────────────────────────────────────────────── */}
      {selectedLeak && (
        <LeakModal leak={selectedLeak} onClose={() => setSelectedLeak(null)} onResolve={markResolved} resolved={resolved} />
      )}
    </div>
  )
}
