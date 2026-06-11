import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, CheckCircle, XCircle, Edit, Trash2,
  MessageSquare, Send, Shield, ExternalLink, AlertTriangle,
  Tag, Clock, User, Activity, Zap, FileText,
  Terminal, BarChart3, Copy, TerminalSquare, Loader2,
  Key, Globe, Hash, Server, Database, ChevronRight,
  Crosshair, ShieldAlert, Lock, Fingerprint, Info, Sparkles
} from 'lucide-react'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import ThreatGraph from './ThreatGraph'
import WarRoom from './WarRoom'
import { useAuth } from '../context/AuthContext'
import { formatDateTime, cvssColor, STATUS_CONFIG, formatMarkdown, formatAIReport } from '../utils/helpers'
import toast from 'react-hot-toast'
import clsx from 'clsx'

// ── CVSS circular SVG gauge (sidebar) ─────────────────────────────────────────
function CvssGaugeLarge({ score }) {
  const r = 40
  const circ = 2 * Math.PI * r
  const pct = Math.min(score / 10, 1)
  const color = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#eab308' : '#22c55e'
  const label = score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW'
  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: 100, height: 100 }}>
        <svg width="100" height="100" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
          <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="6"
            strokeDasharray={circ} strokeDashoffset={circ * (1 - pct)} strokeLinecap="round" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-black leading-none" style={{ color }}>{score.toFixed(1)}</span>
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-wider mt-0.5">CVSS v3</span>
        </div>
      </div>
      <span className="text-[10px] font-black uppercase tracking-widest mt-1.5" style={{ color }}>{label}</span>
    </div>
  )
}

// ── PlaybookModal (unchanged from original) ───────────────────────────────────
function PlaybookModal({ playbook, onClose }) {
  const [copied, setCopied] = useState(false)
  const copyToClipboard = () => {
    navigator.clipboard.writeText(playbook)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    toast.success('Copied to clipboard')
  }
  return (
    <div className="fixed inset-0 z-[110] bg-slate-950/80 backdrop-blur-xl flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div className="bg-slate-900/95 border border-emerald-500/25 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl animate-in zoom-in-95 duration-200 relative">
        <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-emerald-500 via-cyan-500 to-blue-500" />
        <div className="p-5 border-b border-white/5 flex items-center justify-between bg-emerald-500/5">
          <div className="flex items-center gap-2 text-emerald-400 font-bold uppercase tracking-widest text-xs">
            <div className="w-7 h-7 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <TerminalSquare className="w-3.5 h-3.5" />
            </div>
            Mitigation Playbook
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors p-1.5 rounded-lg hover:bg-white/10">
            <XCircle className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div className="max-h-[480px] overflow-y-auto space-y-3 pr-1">
            {playbook.split('\n\n').filter(p => p.trim()).map((paragraph, idx) => {
              const stepMatch = paragraph.match(/^(Step \d+:?)(.*)/i)
              if (stepMatch) {
                return (
                  <div key={idx} className="bg-slate-950/50 p-4 rounded-xl border border-emerald-500/15 group hover:border-emerald-500/30 transition-colors">
                    <span className="inline-flex items-center text-[10px] font-black uppercase tracking-widest text-emerald-300 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/25 mb-2">
                      {stepMatch[1].replace(':', '')}
                    </span>
                    <p className="text-slate-300 text-sm leading-relaxed">{stepMatch[2].trim()}</p>
                  </div>
                )
              }
              return (
                <div key={idx} className="bg-slate-950/30 p-4 rounded-xl border border-white/5 relative">
                  <div className="absolute left-0 top-4 bottom-4 w-0.5 bg-emerald-500/30 rounded-full" />
                  <p className="text-slate-300 text-sm leading-relaxed pl-2">{paragraph.trim()}</p>
                </div>
              )
            })}
          </div>
          <div className="flex gap-3 pt-2 border-t border-white/5">
            <button onClick={copyToClipboard} className="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-bold uppercase tracking-wider py-3 rounded-xl flex items-center justify-center gap-2 text-sm transition-all">
              {copied ? <CheckCircle className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copied!' : 'Copy Playbook'}
            </button>
            <button onClick={onClose} className="flex-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 font-bold py-3 rounded-xl transition-all text-sm">
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── IOC type config ───────────────────────────────────────────────────────────
const IOC_META = {
  ip:     { icon: Server,      color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/20',    label: 'IP' },
  domain: { icon: Globe,       color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/20',   label: 'Domain' },
  url:    { icon: ExternalLink, color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', label: 'URL' },
  hash:   { icon: Hash,        color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20', label: 'Hash' },
  email:  { icon: Key,         color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/20',  label: 'Email' },
}

function IocTable({ iocs }) {
  const [copied, setCopied] = useState(null)
  const copy = async (val, i) => {
    await navigator.clipboard.writeText(val)
    setCopied(i)
    setTimeout(() => setCopied(null), 1500)
    toast.success('Copied!')
  }
  if (!iocs?.length) return (
    <div className="py-12 text-center rounded-xl border border-slate-800 bg-slate-900/40">
      <Database className="w-10 h-10 text-slate-700 mx-auto mb-3" />
      <p className="text-slate-500 text-sm">No IOCs extracted for this advisory.</p>
    </div>
  )
  return (
    <div className="rounded-xl border border-slate-800 overflow-hidden">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-800 bg-slate-900/80">
          <tr className="text-[10px] font-black uppercase tracking-widest text-slate-500">
            <th className="p-3 pl-4">Type</th>
            <th className="p-3">Value</th>
            <th className="p-3 pr-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => {
            const m = IOC_META[ioc.type] || IOC_META.domain
            const Icon = m.icon
            return (
              <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors group">
                <td className="p-3 pl-4">
                  <span className={clsx('inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-black uppercase border', m.color, m.bg, m.border)}>
                    <Icon className="w-3 h-3" />{m.label}
                  </span>
                </td>
                <td className="p-3 font-mono text-xs text-slate-300 max-w-xs truncate">{ioc.value}</td>
                <td className="p-3 pr-4 text-right">
                  <button onClick={() => copy(ioc.value, i)}
                    className="opacity-0 group-hover:opacity-100 text-[10px] font-bold text-slate-500 hover:text-white transition-all px-2.5 py-1 rounded border border-slate-700 hover:border-slate-500">
                    {copied === i ? 'Copied!' : <Copy className="w-3 h-3" />}
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── MITRE TTP card ────────────────────────────────────────────────────────────
function MitreTtpCard({ ttp }) {
  return (
    <a
      href={`https://attack.mitre.org/techniques/${ttp.replace('.', '/')}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center gap-3 p-3 rounded-xl border border-slate-800 bg-slate-900/50 hover:border-cyan-500/30 hover:bg-cyan-950/10 transition-all group"
    >
      <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex-shrink-0">
        <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-sm font-bold text-cyan-300 group-hover:text-cyan-200 transition-colors">{ttp}</div>
        <div className="text-[10px] text-slate-500">Click to view on MITRE ATT&CK</div>
      </div>
      <ExternalLink className="w-3.5 h-3.5 text-slate-700 group-hover:text-cyan-400 transition-colors flex-shrink-0" />
    </a>
  )
}

// ── Attack type chip ──────────────────────────────────────────────────────────
const ATTACK_COLORS = {
  'RCE': 'bg-red-500/10 border-red-500/25 text-red-400',
  'SQLi': 'bg-orange-500/10 border-orange-500/25 text-orange-400',
  'XSS': 'bg-yellow-500/10 border-yellow-500/25 text-yellow-400',
  'SSRF': 'bg-purple-500/10 border-purple-500/25 text-purple-400',
  'LFI': 'bg-pink-500/10 border-pink-500/25 text-pink-400',
  'XXE': 'bg-indigo-500/10 border-indigo-500/25 text-indigo-400',
  'Auth Bypass': 'bg-cyan-500/10 border-cyan-500/25 text-cyan-400',
  'Privilege Escalation': 'bg-blue-500/10 border-blue-500/25 text-blue-400',
  'DoS': 'bg-rose-500/10 border-rose-500/25 text-rose-400',
  'Supply Chain': 'bg-emerald-500/10 border-emerald-500/25 text-emerald-400',
}

// ── Tab config ────────────────────────────────────────────────────────────────
const TABS = [
  { id: 'overview', label: 'Overview',  icon: FileText },
  { id: 'iocs',     label: 'IOCs',      icon: Database },
  { id: 'mitre',    label: 'MITRE TTPs', icon: Crosshair },
  { id: 'ai',       label: 'AI Brief',   icon: Activity },
  { id: 'warroom',  label: 'War Room',   icon: ShieldAlert, analystOnly: true },
]

const formatSourceDomain = (url) => {
  if (!url) return ''
  try {
    let host = new URL(url).hostname.replace('www.', '').replace(/\.[^/.]+$/, '')
    const known = { thehackernews: 'The Hacker News', cisa: 'CISA', bleepingcomputer: 'BleepingComputer', darkreading: 'Dark Reading', securityweek: 'SecurityWeek', threatpost: 'Threatpost', github: 'GitHub', nvd: 'NVD / NIST' }
    return known[host] || (host.charAt(0).toUpperCase() + host.slice(1))
  } catch { return 'External' }
}

// ── Prediction Renderer ───────────────────────────────────────────────────────
// Parses structured AI forecast output into beautiful section cards
function PredictionRenderer({ text }) {
  if (!text) return null

  // Normalize: split on inline dash bullets that appear without newlines
  // e.g. "sentence. - Bullet 1 - Bullet 2" → split them out
  const normalized = text
    .replace(/\. - /g, '.\n• ')
    .replace(/\n- /g, '\n• ')
    .replace(/^- /gm, '• ')

  const lines = normalized.split('\n').map(l => l.trim()).filter(Boolean)

  const sections = []
  let current = null

  for (const line of lines) {
    const isHeader = /^(OVERVIEW|FUTURE SCENARIOS|EVIDENCE GAPS)\s*:?$/i.test(line)
    if (isHeader) {
      const label = line.replace(/:$/, '').toUpperCase()
      current = { label, items: [] }
      sections.push(current)
    } else if (current) {
      current.items.push(line)
    } else {
      // Text before any header — treat as overview
      current = { label: 'OVERVIEW', items: [line] }
      sections.push(current)
    }
  }

  // If AI didn't use structured headers, fallback to bullet detection
  if (sections.length === 0 || (sections.length === 1 && sections[0].label !== 'OVERVIEW')) {
    return (
      <div className="space-y-2">
        {lines.map((line, i) => {
          const isBullet = /^[•\-\*]/.test(line)
          return isBullet ? (
            <div key={i} className="flex items-start gap-3">
              <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-cyan-400 flex-shrink-0" />
              <span className="text-sm text-slate-200 leading-relaxed">{line.replace(/^[•\-\*]\s*/, '')}</span>
            </div>
          ) : (
            <p key={i} className="text-sm text-slate-300 leading-relaxed">{line}</p>
          )
        })}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {sections.map((section, si) => {
        const isScenarios = section.label === 'FUTURE SCENARIOS'
        const isGaps = section.label === 'EVIDENCE GAPS'
        return (
          <div key={si}>
            <div className={clsx(
              'text-[10px] font-black uppercase tracking-[0.18em] mb-2',
              isScenarios ? 'text-cyan-400' : isGaps ? 'text-amber-400' : 'text-blue-300'
            )}>
              {section.label}
            </div>
            {isScenarios ? (
              <div className="space-y-2">
                {section.items.map((item, ii) => {
                  const clean = item.replace(/^[•\-\*]\s*/, '')
                  return (
                    <div key={ii} className="flex items-start gap-3 rounded-lg bg-cyan-950/20 border border-cyan-500/10 px-3 py-2.5">
                      <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-cyan-400 flex-shrink-0" />
                      <span className="text-sm text-slate-200 leading-relaxed">{clean}</span>
                    </div>
                  )
                })}
              </div>
            ) : isGaps ? (
              <div className="rounded-lg border border-amber-500/20 bg-amber-950/10 px-4 py-3">
                {section.items.map((item, ii) => (
                  <p key={ii} className="text-sm text-amber-200/80 leading-relaxed">{item.replace(/^[•\-\*]\s*/, '')}</p>
                ))}
              </div>
            ) : (
              <div className="border-l-2 border-blue-500/40 pl-4">
                {section.items.map((item, ii) => (
                  <p key={ii} className="text-sm text-slate-200 leading-relaxed font-medium">{item}</p>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
export default function AdvisoryDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { isAdmin, isAnalyst } = useAuth()
  const [advisory, setAdvisory]   = useState(null)
  const [annotations, setAnnotations] = useState([])
  const [comment, setComment]     = useState('')
  const [loading, setLoading]     = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [activeTab, setActiveTab] = useState('overview')
  const [playbook, setPlaybook]   = useState(null)
  const [generatingPlaybook, setGeneratingPlaybook] = useState(false)
  const [prediction, setPrediction] = useState(null)
  const [generatingPrediction, setGeneratingPrediction] = useState(false)
  const [isDescExpanded, setIsDescExpanded] = useState(false)

  const load = async () => {
    try {
      const [aRes, annRes] = await Promise.all([
        api.get(`/advisories/${id}`),
        api.get(`/advisories/${id}/annotations`),
      ])
      setAdvisory(aRes.data)
      setAnnotations(annRes.data)
    } catch { toast.error('Advisory not found'); navigate('/advisories') }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [id])

  const generatePlaybook = async () => {
    setGeneratingPlaybook(true)
    try { const r = await api.post(`/ai/generate-playbook/${id}`); setPlaybook(r.data.playbook) }
    catch { toast.error('Failed to generate playbook') }
    finally { setGeneratingPlaybook(false) }
  }

  const generatePrediction = async () => {
    setGeneratingPrediction(true)
    try { const r = await api.post(`/ai/predict-impact/${id}`); setPrediction(r.data.prediction) }
    catch { toast.error('Failed to generate forecast') }
    finally { setGeneratingPrediction(false) }
  }

  const publish = async () => {
    try { const r = await api.post(`/advisories/${id}/publish`); setAdvisory(r.data); toast.success('Published') }
    catch { toast.error('Failed to publish') }
  }

  const reject = async () => {
    try { const r = await api.post(`/advisories/${id}/reject`); setAdvisory(r.data); toast.success('Rejected') }
    catch { toast.error('Failed to reject') }
  }

  const deleteAdvisory = async () => {
    if (!confirm('Delete this advisory permanently?')) return
    try { await api.delete(`/advisories/${id}`); toast.success('Deleted'); navigate('/advisories') }
    catch { toast.error('Failed to delete') }
  }

  const downloadReport = async () => {
    try {
      const r = await api.get(`/reports/advisory/${id}`, { responseType: 'blob' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(new Blob([r.data]))
      a.download = `Secure_Bulletin_${id}.pdf`
      a.click()
    } catch { toast.error('Failed to generate report') }
  }

  const addAnnotation = async () => {
    if (!comment.trim()) return
    setSubmitting(true)
    try {
      const r = await api.post(`/advisories/${id}/annotations`, { content: comment })
      setAnnotations(a => [r.data, ...a])
      setComment('')
      toast.success('Comment added')
    } catch { toast.error('Failed to add comment') }
    finally { setSubmitting(false) }
  }

  if (loading) return (
    <div className="flex justify-center items-center py-32">
      <div className="flex flex-col items-center gap-6">
        <div className="relative w-20 h-20">
          <div className="w-20 h-20 border-[3px] border-slate-800 border-t-cyan-500 rounded-full animate-spin" />
          <div className="absolute inset-[8px] border-[2px] border-slate-800 border-b-blue-500 rounded-full animate-spin" style={{ animationDirection: 'reverse' }} />
          <Crosshair className="absolute inset-0 m-auto w-5 h-5 text-cyan-400 animate-pulse" />
        </div>
        <p className="text-sm text-slate-500 font-mono animate-pulse tracking-widest uppercase">Loading Advisory...</p>
      </div>
    </div>
  )
  if (!advisory) return null

  const status = STATUS_CONFIG[advisory.status] || STATUS_CONFIG.pending
  const visibleTabs = TABS.filter(t => !t.analystOnly || isAnalyst)

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-500">

      {/* ── Back nav + actions ────────────────────────────────────────────── */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <Link to="/advisories"
          className="inline-flex items-center gap-2 text-slate-500 hover:text-white text-xs font-bold uppercase tracking-widest transition-colors bg-slate-900/50 hover:bg-slate-800 px-4 py-2 rounded-xl border border-slate-800/80">
          <ArrowLeft className="w-3.5 h-3.5" /> Advisories
        </Link>
        {isAnalyst && (
          <div className="flex items-center gap-2">
            <Link to={`/advisories/${id}/edit`}
              className="flex items-center gap-1.5 text-slate-400 hover:text-white text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-xl border border-slate-700 hover:border-slate-600 transition-all">
              <Edit className="w-3.5 h-3.5" /> Edit
            </Link>
            <button onClick={downloadReport}
              className="flex items-center gap-1.5 text-slate-400 hover:text-white text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-xl border border-slate-700 hover:border-slate-600 transition-all">
              <FileText className="w-3.5 h-3.5" /> Export PDF
            </button>
            {isAdmin && (
              <button onClick={deleteAdvisory}
                className="flex items-center gap-1.5 text-red-400 hover:text-red-300 text-xs font-bold uppercase tracking-wider px-4 py-2 rounded-xl border border-red-800/50 hover:border-red-700/70 bg-red-950/20 hover:bg-red-950/30 transition-all">
                <Trash2 className="w-3.5 h-3.5" /> Delete
              </button>
            )}
          </div>
        )}
      </div>

      {/* ── Critical banner ───────────────────────────────────────────────── */}
      {advisory.is_critical_alert && (
        <div className="rounded-xl border border-red-500/25 bg-red-950/15 px-5 py-3 flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-red-500 animate-pulse flex-shrink-0" />
          <span className="text-sm font-bold text-red-300">Critical Threat Directive — Immediate action required.</span>
          <span className="text-xs text-red-500/70 ml-auto font-mono uppercase tracking-wider">PRIORITY 1</span>
        </div>
      )}

      {/* ── Title hero ────────────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-6">
        <div className="flex flex-wrap gap-2 mb-4">
          <SeverityBadge severity={advisory.severity} />
          <span className={clsx('inline-flex items-center gap-1 text-[10px] uppercase font-black px-2.5 py-1 rounded border tracking-widest', status.bg, status.color, status.border)}>
            <span className={clsx('w-1 h-1 rounded-full flex-shrink-0', status.dot)} />{status.label}
          </span>
          {advisory.is_kev && <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-purple-500/25 bg-purple-500/10 text-purple-300 text-[10px] font-black uppercase tracking-widest"><Activity className="w-3 h-3" />CISA KEV</span>}
          {advisory.is_zero_day && <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-red-500/25 bg-red-500/10 text-red-400 text-[10px] font-black uppercase tracking-widest"><Zap className="w-3 h-3" />0-Day</span>}
        </div>
        <h1 className="text-2xl md:text-3xl font-black text-white leading-tight tracking-tight">{advisory.title}</h1>
      </div>

      {/* ── Main 2-column layout ──────────────────────────────────────────── */}
      <div className="flex flex-col lg:flex-row gap-5">

        {/* ── LEFT: Tab content ─────────────────────────────────────────── */}
        <div className="flex-1 min-w-0 space-y-4">

          {/* Tab nav */}
          <div className="flex border-b border-slate-800 gap-0.5 overflow-x-auto">
            {visibleTabs.map(({ id: tid, label, icon: Icon }) => (
              <button key={tid} onClick={() => setActiveTab(tid)}
                className={clsx(
                  'flex items-center gap-1.5 px-4 py-2.5 text-xs font-bold uppercase tracking-widest whitespace-nowrap transition-all border-b-2 -mb-px',
                  activeTab === tid
                    ? 'text-cyan-400 border-cyan-500'
                    : 'text-slate-500 border-transparent hover:text-slate-300'
                )}>
                <Icon className="w-3.5 h-3.5" />{label}
              </button>
            ))}
          </div>

          {/* ── Overview tab ────────────────────────────────────────────── */}
          {activeTab === 'overview' && (
            <div className="space-y-5 animate-in fade-in duration-300">
              {/* CVE IDs */}
              {advisory.cve_ids?.length > 0 && (
                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                  <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">CVE Identifiers</div>
                  <div className="flex flex-wrap gap-2">
                    {advisory.cve_ids.map(cve => (
                      <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                        className="flex items-center gap-1.5 font-mono text-xs font-bold text-cyan-400 bg-cyan-950/30 px-3 py-1.5 rounded-lg border border-cyan-800/30 hover:border-cyan-500/50 hover:bg-cyan-950/50 transition-all">
                        <Fingerprint className="w-3 h-3 opacity-60" />{cve}
                        <ExternalLink className="w-2.5 h-2.5 text-cyan-600 hover:text-cyan-300" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Description */}
              {advisory.description && (
                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5" /> Executive Briefing
                    </div>
                    {advisory.description.length > 500 && (
                      <button onClick={() => setIsDescExpanded(v => !v)} className="text-[10px] font-bold text-cyan-400 hover:text-cyan-300 transition-colors uppercase tracking-wider">
                        {isDescExpanded ? 'Collapse' : 'Expand'}
                      </button>
                    )}
                  </div>
                  <div className={clsx('text-sm text-slate-300 leading-relaxed', !isDescExpanded && 'line-clamp-6')}
                    dangerouslySetInnerHTML={{ __html: formatMarkdown(advisory.description) }}
                  />
                </div>
              )}

              {/* Attack types */}
              {advisory.attack_types?.length > 0 && (
                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                  <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">Attack Vectors</div>
                  <div className="flex flex-wrap gap-2">
                    {advisory.attack_types.map(t => (
                      <span key={t} className={clsx('inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-black uppercase tracking-wider border', ATTACK_COLORS[t] || 'bg-slate-700/60 border-slate-600 text-slate-400')}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Mitigation */}
              {advisory.mitigation && (
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="text-[10px] font-black text-emerald-400 uppercase tracking-widest flex items-center gap-2">
                      <CheckCircle className="w-3.5 h-3.5" /> Mitigation Steps
                    </div>
                    <button onClick={generatePlaybook} disabled={generatingPlaybook}
                      className="flex items-center gap-1.5 text-[10px] font-bold text-emerald-400 hover:text-white bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/25 px-3 py-1.5 rounded-lg transition-all uppercase tracking-wider disabled:opacity-50">
                      {generatingPlaybook ? <Loader2 className="w-3 h-3 animate-spin" /> : <Terminal className="w-3 h-3" />}
                      {generatingPlaybook ? 'Generating...' : 'Generate Playbook'}
                    </button>
                  </div>
                  <div className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">{advisory.mitigation}</div>
                </div>
              )}

              {/* Threat Graph */}
              {ThreatGraph && <ThreatGraph advisoryId={id} />}

              {/* Pending actions */}
              {advisory.status === 'pending' && isAnalyst && (
                <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4 flex flex-wrap items-center gap-3">
                  <span className="text-xs text-slate-400 font-bold">Advisory Status: Pending Review</span>
                  <div className="flex gap-2 ml-auto">
                    <button onClick={publish}
                      className="flex items-center gap-2 px-5 py-2 bg-green-600 hover:bg-green-500 text-white text-xs font-black uppercase tracking-wider rounded-xl transition-all">
                      <CheckCircle className="w-4 h-4" /> Approve & Publish
                    </button>
                    <button onClick={reject}
                      className="flex items-center gap-2 px-5 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 text-xs font-black uppercase tracking-wider rounded-xl transition-all">
                      <XCircle className="w-4 h-4" /> Reject
                    </button>
                  </div>
                </div>
              )}

              {/* Analyst comments */}
              {isAnalyst && (
                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-4">
                  <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                    <MessageSquare className="w-3.5 h-3.5" /> Analyst Comments ({annotations.length})
                  </div>
                  <div className="flex gap-3">
                    <textarea
                      className="flex-1 resize-none bg-slate-950/50 border border-slate-700/60 text-slate-200 text-sm p-3 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/40 transition-all"
                      rows={2} placeholder="Add internal analyst note..."
                      value={comment} onChange={e => setComment(e.target.value)}
                    />
                    <button onClick={addAnnotation} disabled={!comment.trim() || submitting}
                      className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white rounded-xl transition-all text-xs font-bold uppercase tracking-wider self-start mt-0.5">
                      <Send className="w-3.5 h-3.5" /> Post
                    </button>
                  </div>
                  {annotations.length > 0 && (
                    <div className="space-y-3 pt-2 border-t border-slate-800/60">
                      {annotations.map(a => (
                        <div key={a.id} className="rounded-xl border border-slate-800 bg-slate-950/30 p-4">
                          <div className="flex items-center gap-2 text-[10px] text-slate-500 mb-2">
                            <User className="w-3 h-3" />
                            <span className="text-slate-300 font-semibold">{a.user?.full_name || a.user?.username}</span>
                            <span className="text-slate-700">·</span>
                            <Clock className="w-3 h-3" />
                            {formatDateTime(a.created_at)}
                          </div>
                          <p className="text-sm text-slate-300 leading-relaxed border-l-2 border-slate-700 pl-3">{a.content}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── IOCs tab ─────────────────────────────────────────────────── */}
          {activeTab === 'iocs' && (
            <div className="animate-in fade-in duration-300">
              <IocTable iocs={advisory.iocs} />
            </div>
          )}

          {/* ── MITRE tab ─────────────────────────────────────────────────── */}
          {activeTab === 'mitre' && (
            <div className="animate-in fade-in duration-300 space-y-3">
              {advisory.mitre_ttps?.length > 0 ? (
                <>
                  <div className="text-xs text-slate-500 mb-4">
                    {advisory.mitre_ttps.length} technique{advisory.mitre_ttps.length !== 1 ? 's' : ''} identified — click any card to view on MITRE ATT&CK
                  </div>
                  <div className="grid sm:grid-cols-2 gap-2">
                    {advisory.mitre_ttps.map(ttp => <MitreTtpCard key={ttp} ttp={ttp} />)}
                  </div>
                </>
              ) : (
                <div className="py-12 text-center rounded-xl border border-slate-800 bg-slate-900/40">
                  <Crosshair className="w-10 h-10 text-slate-700 mx-auto mb-3" />
                  <p className="text-slate-500 text-sm">No MITRE ATT&CK TTPs linked to this advisory.</p>
                </div>
              )}
            </div>
          )}

          {/* ── AI Brief tab ──────────────────────────────────────────────── */}
          {activeTab === 'ai' && (
            <div className="animate-in fade-in duration-300 space-y-6">
              
              {/* AI Intelligence Brief */}
              <div className="rounded-2xl border border-indigo-500/25 bg-gradient-to-br from-indigo-900/15 to-purple-900/10 p-6">
                <div className="flex items-center gap-2 mb-4">
                  <Sparkles className="h-4 w-4 text-indigo-400" />
                  <span className="text-sm font-bold text-indigo-300 uppercase tracking-widest">AI Intelligence Brief</span>
                  <span className="ml-auto text-xs text-slate-500 border border-slate-700 bg-slate-900 rounded-full px-2 py-0.5 font-bold uppercase tracking-wider">Groq-Powered</span>
                </div>
                {advisory.ai_summary ? (
                  <div className="text-sm text-slate-200 leading-relaxed font-medium"
                    dangerouslySetInnerHTML={{ __html: formatAIReport(advisory.ai_summary) }}
                  />
                ) : (
                  <div className="text-center py-6 text-indigo-400/50 text-sm font-medium">
                    No intelligence brief available for this advisory.
                  </div>
                )}
              </div>

              {/* Predictive forecast */}
              <div className="rounded-2xl border border-blue-500/25 bg-gradient-to-br from-blue-900/15 to-cyan-900/10 p-6">
                <div className="flex items-center gap-2 mb-4">
                  <BarChart3 className="h-4 w-4 text-blue-400" />
                  <span className="text-sm font-bold text-blue-300 uppercase tracking-widest">Predictive Threat Forecast</span>
                  <span className="ml-auto text-xs text-slate-500 border border-slate-700 bg-slate-900 rounded-full px-2 py-0.5 font-bold uppercase tracking-wider">Neural Engine</span>
                </div>
                {generatingPrediction ? (
                  <div className="flex items-center gap-3 py-6 text-blue-300">
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span className="text-sm font-medium animate-pulse">Running advanced threat simulations...</span>
                  </div>
                ) : prediction ? (
                  <PredictionRenderer text={prediction} />
                ) : (
                  <div className="text-center py-6">
                    <p className="text-sm text-blue-400/70 mb-4 font-medium">Calculate potential blast radius and future exploit vectors.</p>
                    <button onClick={generatePrediction}
                      className="mx-auto flex items-center gap-2 text-sm font-bold text-white uppercase tracking-wider bg-blue-600 hover:bg-blue-500 px-6 py-3 rounded-xl transition-all shadow-[0_0_20px_rgba(37,99,235,0.2)]">
                      <BarChart3 className="w-4 h-4" /> Execute Forecast Algorithm
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── War Room tab ──────────────────────────────────────────────── */}
          {activeTab === 'warroom' && isAnalyst && (
            <div className="animate-in fade-in duration-300">
              <WarRoom advisoryId={id} />
            </div>
          )}
        </div>

        {/* ── RIGHT: Metadata sidebar ──────────────────────────────────── */}
        <div className="lg:w-72 xl:w-80 space-y-4 flex-shrink-0">

          {/* CVSS + Status */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <div className="flex items-center justify-between mb-4">
              {advisory.cvss_score ? <CvssGaugeLarge score={advisory.cvss_score} /> : <div className="text-slate-600 text-xs">No CVSS score</div>}
              <div className="text-right">
                <div className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1">Status</div>
                <span className={clsx('inline-flex items-center gap-1.5 text-[10px] uppercase font-black px-2.5 py-1 rounded-lg border tracking-widest', status.bg, status.color, status.border)}>
                  <span className={clsx('w-1 h-1 rounded-full', status.dot)} />{status.label}
                </span>
              </div>
            </div>

            <div className="space-y-3 border-t border-slate-800/60 pt-4">
              {[
                { label: 'Sector', value: advisory.sector?.name || 'Cross-Sector', icon: Tag },
                { label: 'Source', value: advisory.source_url ? formatSourceDomain(advisory.source_url) : (advisory.source || 'Unknown'), icon: Globe },
                { label: 'Published', value: formatDateTime(advisory.published_at || advisory.created_at), icon: Clock },
                { label: 'Zero-Day Status', value: advisory.zero_day_status || null, icon: Zap },
              ].filter(m => m.value).map(({ label, value, icon: Icon }) => (
                <div key={label} className="flex items-start gap-2">
                  <Icon className="w-3.5 h-3.5 text-slate-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <div className="text-[9px] font-bold text-slate-600 uppercase tracking-wider">{label}</div>
                    <div className="text-xs text-slate-300 font-semibold">{value}</div>
                  </div>
                </div>
              ))}
            </div>

            {advisory.source_url && (
              <a href={advisory.source_url} target="_blank" rel="noopener noreferrer"
                className="mt-4 flex items-center justify-center gap-2 w-full py-2 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 text-xs font-bold transition-all">
                <ExternalLink className="w-3.5 h-3.5" /> View Source
              </a>
            )}
          </div>

          {/* CVE IDs */}
          {advisory.cve_ids?.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                <Fingerprint className="w-3 h-3" /> CVE IDs
              </div>
              <div className="flex flex-wrap gap-1.5">
                {advisory.cve_ids.map(cve => (
                  <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                    className="font-mono text-[10px] font-bold text-cyan-400 bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-800/30 hover:border-cyan-500/50 transition-colors">
                    {cve}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Affected vendors */}
          {advisory.affected_vendors?.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                <Shield className="w-3 h-3" /> Affected Vendors
              </div>
              <div className="flex flex-wrap gap-1.5">
                {advisory.affected_vendors.map((v, i) => (
                  <span key={i} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800/60 border border-slate-700/50 text-xs text-slate-300 font-semibold">
                    <span className="w-4 h-4 rounded-full bg-slate-700 flex items-center justify-center text-[8px] font-black text-white uppercase">{v.charAt(0)}</span>
                    {v}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* MITRE TTPs mini */}
          {advisory.mitre_ttps?.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                <Crosshair className="w-3 h-3" /> MITRE ATT&CK
              </div>
              <div className="flex flex-wrap gap-1.5">
                {advisory.mitre_ttps.map(t => (
                  <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer"
                    className="font-mono text-[10px] font-bold text-cyan-400 bg-cyan-950/20 px-2 py-0.5 rounded border border-cyan-800/20 hover:border-cyan-500/40 transition-colors">
                    {t}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* APT groups */}
          {advisory.apt_groups?.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                <AlertTriangle className="w-3 h-3" /> APT Groups
              </div>
              <div className="flex flex-wrap gap-1.5">
                {advisory.apt_groups.map((g, i) => (
                  <span key={i} className="text-[10px] font-bold text-rose-400 bg-rose-950/20 px-2 py-0.5 rounded border border-rose-800/20">{g}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {playbook && <PlaybookModal playbook={playbook} onClose={() => setPlaybook(null)} />}
    </div>
  )
}
