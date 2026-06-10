import { useEffect, useState, useMemo, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Bug, ExternalLink, ShieldAlert, Target, Shield, Clock, ChevronRight,
  Search, X, Sparkles, Loader2, AlertTriangle, Activity, Filter,
  RefreshCw, Zap, Globe2, Database, Terminal, BookOpen, AlertCircle,
  TrendingUp, Calendar, Building2, CheckCircle2, XCircle, Eye,
  Copy, ChevronDown, Crosshair, Radio, Flame
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell
} from 'recharts'
import clsx from 'clsx'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import { cvssColor, formatDateTime, timeAgo, formatAIReport } from '../utils/helpers'

// ─── Helpers ──────────────────────────────────────────────────────────────────
// Strip HTML tags + decode HTML entities (handles RSS / CISA KEV descriptions)
const stripHtml = (str = '') =>
  str
    .replace(/<[^>]+>/g, ' ')          // remove tags
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\s{2,}/g, ' ')           // collapse whitespace
    .trim()

// ─── Constants ────────────────────────────────────────────────────────────────
const STATUS_CFG = {
  'Exploited in the Wild': {
    icon: Flame, text: '#ef4444', bg: 'rgba(239,68,68,0.12)',
    border: 'rgba(239,68,68,0.35)', glow: '0 0 24px rgba(239,68,68,0.25)',
    badge: 'bg-red-500/15 text-red-300 border-red-500/35',
  },
  'Patch Available': {
    icon: Shield, text: '#eab308', bg: 'rgba(234,179,8,0.12)',
    border: 'rgba(234,179,8,0.35)', glow: '0 0 24px rgba(234,179,8,0.15)',
    badge: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/35',
  },
  Mitigated: {
    icon: CheckCircle2, text: '#22c55e', bg: 'rgba(34,197,94,0.12)',
    border: 'rgba(34,197,94,0.35)', glow: '0 0 24px rgba(34,197,94,0.12)',
    badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35',
  },
  'Under Investigation': {
    icon: AlertCircle, text: '#3b82f6', bg: 'rgba(59,130,246,0.12)',
    border: 'rgba(59,130,246,0.35)', glow: '0 0 24px rgba(59,130,246,0.15)',
    badge: 'bg-blue-500/15 text-blue-300 border-blue-500/35',
  },
}

const VENDOR_COLORS = [
  '#ef4444', '#f97316', '#eab308', '#22c55e',
  '#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6',
  '#f59e0b', '#06b6d4',
]

const FILTER_OPTIONS = ['All', 'CISA KEV', 'Project Zero', 'PoC Exploit', 'Unpatched (ZDI)']
const SORT_OPTIONS = [
  { value: 'date_desc', label: 'Newest First' },
  { value: 'date_asc', label: 'Oldest First' },
  { value: 'mnc_first', label: 'MNC Priority' },
]

// ─── Small Components ─────────────────────────────────────────────────────────

function LivePulse({ color = 'bg-red-500' }) {
  return (
    <span className="relative flex h-2.5 w-2.5">
      <span className={clsx('absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping', color)} />
      <span className={clsx('relative inline-flex h-2.5 w-2.5 rounded-full', color)} />
    </span>
  )
}

function SourceTag({ label, color = 'text-slate-400', bg = 'bg-slate-800', border = 'border-slate-700', icon: Icon }) {
  return (
    <span className={clsx('inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest', bg, border, color)}>
      {Icon && <Icon className="h-2.5 w-2.5" />}
      {label}
    </span>
  )
}

function CvssRing({ score }) {
  if (!score || score <= 0) return null
  const radius = 18
  const circ = 2 * Math.PI * radius
  const offset = circ - (score / 10) * circ
  const col = score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#eab308' : '#22c55e'
  return (
    <div className="flex flex-col items-center gap-0.5">
      <div className="relative h-11 w-11">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 44 44">
          <circle cx="22" cy="22" r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4" />
          <circle
            cx="22" cy="22" r={radius} fill="none"
            stroke={col} strokeWidth="4"
            strokeDasharray={circ} strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1s ease', filter: `drop-shadow(0 0 3px ${col})` }}
          />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-[11px] font-black" style={{ color: col }}>
          {score.toFixed(1)}
        </span>
      </div>
      <span className="text-[9px] font-bold uppercase tracking-widest text-slate-600">CVSS</span>
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color, glow, bg, border, delay = 0 }) {
  return (
    <div
      className="rounded-2xl p-5 relative overflow-hidden group transition-all duration-300 hover:-translate-y-1 cursor-default"
      style={{ background: bg, border: `1px solid ${border}`, boxShadow: glow, animationDelay: `${delay}ms` }}
    >
      <div className="absolute -right-3 -bottom-3 opacity-[0.07] group-hover:opacity-[0.12] transition-all duration-500 group-hover:scale-110">
        <Icon className="w-20 h-20" style={{ color }} />
      </div>
      <div className="relative z-10">
        <div className="text-4xl font-black mb-2 tabular-nums" style={{ color }}>{value}</div>
        <div className="text-[11px] font-bold uppercase tracking-widest text-slate-400">{label}</div>
      </div>
    </div>
  )
}

// ─── CVE Dossier Modal ────────────────────────────────────────────────────────
function CveDossierModal({ cveId, data, onClose, onGenerateAI }) {
  const [tab, setTab] = useState('overview')
  const [aiSummary, setAiSummary] = useState(null)
  const [generating, setGenerating] = useState(false)
  const [copied, setCopied] = useState(false)

  const handleGenerateAI = async () => {
    setGenerating(true)
    try {
      const result = await onGenerateAI(cveId, data)
      setAiSummary(result)
      setTab('ai')
    } finally {
      setGenerating(false)
    }
  }

  const copyId = () => {
    navigator.clipboard.writeText(cveId)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // ── Helper: parse "**Vendor:** X **Product:** Y ..." inline KEV format ──────
  // MITRE/NVD sometimes embeds the CISA KEV structured text inside the description field.
  const parseKevInlineFields = (raw = '') => {
    const result = {}
    const patterns = {
      vendor:      /\*\*Vendor:\*\*\s*([^*]+?)(?=\s*\*\*|$)/i,
      product:     /\*\*Product:\*\*\s*([^*]+?)(?=\s*\*\*|$)/i,
      shortDesc:   /\*\*Short Description:\*\*\s*([^*]+?)(?=\s*\*\*|$)/i,
      action:      /\*\*Required Action:\*\*\s*([^*]+?)(?=\s*\*\*|$)/i,
      dueDate:     /\*\*Due Date:\*\*\s*([^*]+?)(?=\s*\*\*|$)/i,
    }
    for (const [key, re] of Object.entries(patterns)) {
      const m = raw.match(re)
      if (m) result[key] = m[1].trim()
    }
    return result
  }

  // Raw description text from MITRE / NVD / KEV
  const rawDesc =
    data?.containers?.cna?.descriptions?.[0]?.value ||
    data?.cveMetadata?.description ||
    data?.vulnerabilities?.[0]?.cve?.descriptions?.[0]?.value ||
    data?.summary ||
    data?.shortDescription ||
    ''

  // If the raw description contains embedded KEV fields, extract them
  const inlineParsed = rawDesc.includes('**Vendor:**') ? parseKevInlineFields(rawDesc) : {}

  // CISA KEV fields (from the feed object OR inline-parsed from description)
  const kevVendor    = data?.vendorProject || data?.vendor    || inlineParsed.vendor   || null
  const kevProduct   = data?.product                         || inlineParsed.product   || null
  const kevAction    = data?.requiredAction                  || inlineParsed.action    || null
  const kevDueDate   = data?.dueDate                         || inlineParsed.dueDate   || null

  // Clean description: use parsed shortDesc if available, else strip the whole block
  const summary = stripHtml(
    inlineParsed.shortDesc ||    // parsed "Short Description:" value from inline KEV
    data?.containers?.cna?.descriptions?.[0]?.value ||
    data?.cveMetadata?.description ||
    data?.vulnerabilities?.[0]?.cve?.descriptions?.[0]?.value ||
    data?.summary ||
    data?.shortDescription ||
    '—'
  ).replace(/\*\*[^*]+:\*\*\s*/g, '')  // strip any remaining **Label:** markers


  const cvss = data?.containers?.cna?.metrics?.[0]?.cvssV3_1?.baseScore
    || data?.containers?.cna?.metrics?.[0]?.cvssV3_0?.baseScore
    || data?.cvss?.score
    || null

  const references = data?.containers?.cna?.references || data?.references || []
  const affected = data?.containers?.cna?.affected || []
  const published = data?.cveMetadata?.datePublished || data?.dateAdded || data?.publishedDate

  const TABS = [
    { id: 'overview', label: 'Overview', icon: Eye },
    { id: 'references', label: 'References', icon: BookOpen, count: references.length },
    { id: 'affected', label: 'Affected', icon: Building2, count: affected.length },
    { id: 'raw', label: 'Raw JSON', icon: Terminal },
    { id: 'ai', label: 'AI Brief', icon: Sparkles },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(2,6,23,0.85)', backdropFilter: 'blur(12px)' }}>
      <div
        className="w-full max-w-4xl max-h-[92vh] flex flex-col rounded-3xl overflow-hidden"
        style={{ background: 'rgba(10,14,26,0.98)', border: '1px solid rgba(239,68,68,0.25)', boxShadow: '0 0 80px rgba(239,68,68,0.15)' }}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-red-500/10 shrink-0">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/15 border border-red-500/30">
              <Bug className="h-5 w-5 text-red-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-black text-white">{cveId}</h2>
                <button onClick={copyId} className="text-slate-500 hover:text-cyan-400 transition">
                  {copied ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>
              <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">Vulnerability Dossier</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {cvss && <CvssRing score={cvss} />}
            <button
              onClick={handleGenerateAI}
              disabled={generating || !!aiSummary}
              className={clsx(
                'flex items-center gap-1.5 rounded-xl px-3 py-2 text-xs font-bold transition',
                aiSummary
                  ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 cursor-default'
                  : 'bg-indigo-600 hover:bg-indigo-500 text-white'
              )}
            >
              {generating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
              {aiSummary ? 'AI Generated' : generating ? 'Generating…' : 'AI Brief'}
            </button>
            <button onClick={onClose} className="flex h-9 w-9 items-center justify-center rounded-xl text-slate-500 hover:bg-slate-800 hover:text-white transition">
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 px-6 pt-3 pb-0 border-b border-slate-800/60 shrink-0 overflow-x-auto">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={clsx(
                'flex items-center gap-1.5 px-3 py-2 text-xs font-bold rounded-t-lg transition whitespace-nowrap border-b-2 -mb-px',
                tab === t.id
                  ? 'text-white border-red-400'
                  : 'text-slate-500 border-transparent hover:text-slate-300'
              )}
            >
              <t.icon className="h-3.5 w-3.5" />
              {t.label}
              {t.count > 0 && (
                <span className={clsx('rounded-full px-1.5 text-[10px] font-black', tab === t.id ? 'bg-red-500/20 text-red-300' : 'bg-slate-800 text-slate-500')}>
                  {t.count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">

          {/* Overview */}
          {tab === 'overview' && (
            <div className="space-y-4">

              {/* ── Top info grid ───────────────────────────────────────────── */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">

                {kevVendor && (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Vendor</div>
                    <div className="text-sm font-bold text-blue-300">{kevVendor}</div>
                  </div>
                )}

                {kevProduct && (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Product</div>
                    <div className="text-sm font-bold text-white">{kevProduct}</div>
                  </div>
                )}

                {kevDueDate && (
                  <div className="rounded-xl border border-red-900/30 bg-red-950/20 p-4">
                    <div className="text-[10px] text-red-400 font-bold uppercase tracking-widest mb-1">Patch Due Date</div>
                    <div className="text-sm font-bold text-red-300">{kevDueDate}</div>
                  </div>
                )}

                {cvss && (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">CVSS Score</div>
                    <div className={clsx('text-2xl font-black', cvssColor(cvss))}>{cvss}</div>
                  </div>
                )}

                {published && (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                    <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-1">Published</div>
                    <div className="text-sm font-bold text-white">
                      {new Date(published).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
                    </div>
                  </div>
                )}

                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                  <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-2">Sources</div>
                  <div className="flex flex-col gap-1.5">
                    <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:text-white transition">
                      NVD <ExternalLink className="h-3 w-3" />
                    </a>
                    <a href={`https://www.cvedetails.com/cve/${cveId}/`} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:text-white transition">
                      CVEDetails <ExternalLink className="h-3 w-3" />
                    </a>
                    <a href={`https://cveawg.mitre.org/api/cve/${cveId}`} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:text-white transition">
                      MITRE <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                </div>
              </div>

              {/* ── Description ─────────────────────────────────────────────── */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5">
                <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">Description</div>
                <p className="text-sm text-slate-300 leading-7">{summary}</p>
              </div>

              {/* ── Required Action (CISA KEV) ──────────────────────────────── */}
              {kevAction && (
                <div className="rounded-xl border border-amber-800/40 bg-amber-950/20 p-5">
                  <div className="text-[10px] font-bold uppercase tracking-widest text-amber-400 mb-2 flex items-center gap-2">
                    <span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                    Required Action
                  </div>
                  <p className="text-sm text-amber-100 leading-7">{kevAction}</p>
                </div>
              )}

            </div>
          )}

          {/* References */}

          {tab === 'references' && (
            <div className="space-y-2">
              {references.length === 0 && (
                <div className="text-center py-8 text-slate-500 text-sm">No references available.</div>
              )}
              {references.map((ref, i) => (
                <a
                  key={i}
                  href={ref.url || ref}
                  target="_blank" rel="noreferrer"
                  className="flex items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/50 px-4 py-3 text-sm transition hover:border-cyan-500/30 hover:bg-slate-900 group"
                >
                  <div className="min-w-0">
                    <div className="truncate font-mono text-xs text-slate-400 group-hover:text-slate-300">{ref.url || ref}</div>
                    {ref.tags?.length > 0 && (
                      <div className="flex gap-1 mt-1">
                        {ref.tags.map(t => (
                          <span key={t} className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-500 font-bold uppercase">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <ExternalLink className="h-4 w-4 shrink-0 text-slate-600 group-hover:text-cyan-400 transition" />
                </a>
              ))}
            </div>
          )}

          {/* Affected */}
          {tab === 'affected' && (
            <div className="space-y-3">
              {affected.length === 0 && (
                <div className="text-center py-8 text-slate-500 text-sm">No affected product data returned.</div>
              )}
              {affected.map((item, i) => (
                <div key={i} className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <div className="font-bold text-white">{item.vendor || '—'} · {item.product || '—'}</div>
                  </div>
                  {item.versions?.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {item.versions.slice(0, 12).map((v, j) => (
                        <span key={j} className={clsx(
                          'rounded-md border px-2 py-0.5 font-mono text-xs font-bold',
                          v.status === 'affected'
                            ? 'border-red-500/30 bg-red-500/10 text-red-400'
                            : 'border-slate-700 bg-slate-900 text-slate-500'
                        )}>
                          {v.version}{v.versionType ? ` (${v.versionType})` : ''}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Raw JSON */}
          {tab === 'raw' && (
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 overflow-x-auto">
              <pre className="font-mono text-xs text-slate-400 leading-5 whitespace-pre-wrap">{JSON.stringify(data, null, 2)}</pre>
            </div>
          )}

          {/* AI Brief */}
          {tab === 'ai' && (
            <div className="rounded-2xl border border-indigo-500/25 bg-gradient-to-br from-indigo-900/15 to-purple-900/10 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Sparkles className="h-4 w-4 text-indigo-400" />
                <span className="text-sm font-bold text-indigo-300">AI Intelligence Brief</span>
                <span className="ml-auto text-xs text-slate-500 border border-slate-700 bg-slate-900 rounded-full px-2 py-0.5 font-bold">Groq-Powered</span>
              </div>
              {generating ? (
                <div className="flex items-center gap-3 text-indigo-300 py-6">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span className="text-sm">Synthesising intelligence from multiple sources…</span>
                </div>
              ) : aiSummary ? (
                <div
                  className="text-sm text-slate-300 leading-7 space-y-1"
                  dangerouslySetInnerHTML={{ __html: formatAIReport(aiSummary) }}
                />
              ) : (
                <div className="text-center py-8">
                  <p className="text-sm text-slate-500 mb-4">Generate a board-ready intelligence brief covering impact, attribution, and remediation.</p>
                  <button onClick={handleGenerateAI}
                    className="flex items-center gap-2 mx-auto rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-bold px-5 py-2.5 transition">
                    <Sparkles className="h-4 w-4" /> Generate Executive Brief
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Zero-Day Card ────────────────────────────────────────────────────────────
function ZeroDayCard({ vuln, onAnalyze, index }) {
  const isKev = !vuln.zero_day_status // came from CISA KEV feed
  const exploitColor = '#ef4444'

  return (
    <div
      className="group relative overflow-hidden rounded-2xl border transition-all duration-300 hover:-translate-y-0.5 hover:shadow-lg"
      style={{
        background: 'rgba(10,14,26,0.7)',
        border: '1px solid rgba(239,68,68,0.15)',
        boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
      }}
    >
      {/* Red left bar */}
      <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-red-500 transition-all group-hover:w-1" />

      {/* Hover glow */}
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{ background: 'radial-gradient(ellipse at left, rgba(239,68,68,0.04) 0%, transparent 70%)' }} />

      <div className="pl-4 pr-4 pt-4 pb-3 relative z-10">
        {/* Top row: CVE + badges + date */}
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <span className="rounded-lg border border-red-500/30 bg-red-500/10 px-2.5 py-1 font-mono text-xs font-black text-red-300">
            {vuln.cveID}
          </span>

          {vuln.is_project_zero && (
            <SourceTag label="Project Zero" icon={Shield} color="text-blue-300" bg="bg-blue-500/10" border="border-blue-500/25" />
          )}
          {vuln.has_public_exploit && (
            <SourceTag label="PoC Exploit" icon={Terminal} color="text-orange-300" bg="bg-orange-500/10" border="border-orange-500/25" />
          )}
          {vuln.is_zdi_upcoming && (
            <SourceTag label="Unpatched ZDI" icon={Activity} color="text-purple-300" bg="bg-purple-500/10" border="border-purple-500/25" />
          )}
          <span className="ml-auto text-[10px] font-bold text-slate-600 flex items-center gap-1">
            <Calendar className="h-3 w-3" />
            {vuln.dateAdded}
          </span>
        </div>

        {/* Title */}
        <h3 className="font-bold text-sm text-slate-200 leading-snug mb-1.5 group-hover:text-white transition-colors line-clamp-2">
          {vuln.vulnerabilityName}
        </h3>

        {/* Description */}
        <p className="text-xs text-slate-500 leading-5 line-clamp-2 mb-3">{stripHtml(vuln.shortDescription || '')}</p>

        {/* Footer */}
        <div className="flex items-center justify-between gap-2 pt-3 border-t border-slate-800/60">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-slate-800 border border-slate-700">
              <Building2 className="h-3 w-3 text-slate-400" />
            </div>
            <span className="text-xs font-bold text-slate-400">{vuln.vendorProject}</span>
          </div>

          <div className="flex items-center gap-2">
            <a
              href={`https://nvd.nist.gov/vuln/detail/${vuln.cveID}`}
              target="_blank" rel="noreferrer"
              className="flex items-center gap-1 text-[10px] font-bold text-slate-500 hover:text-cyan-400 transition uppercase tracking-wider"
            >
              NVD <ExternalLink className="h-3 w-3" />
            </a>
            <button
              onClick={() => onAnalyze(vuln.cveID)}
              className="flex items-center gap-1 rounded-lg bg-red-500/10 border border-red-500/20 px-2.5 py-1 text-[10px] font-bold text-red-400 hover:bg-red-500/20 hover:text-red-300 transition uppercase tracking-wider"
            >
              <Eye className="h-3 w-3" /> Dossier
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Internally Tracked Advisory Card ────────────────────────────────────────
function TrackedAdvisoryCard({ adv }) {
  const sc = STATUS_CFG[adv.zero_day_status] || STATUS_CFG['Under Investigation']
  const SIcon = sc.icon
  return (
    <Link
      to={`/advisories/${adv.id}`}
      className="group relative overflow-hidden rounded-2xl transition-all duration-300 hover:-translate-y-0.5 hover:shadow-xl block"
      style={{ background: sc.bg, border: `1px solid ${sc.border}`, boxShadow: sc.glow }}
    >
      <div className="absolute left-0 top-0 bottom-0 w-0.5 transition-all group-hover:w-1" style={{ background: sc.text }} />
      <div className="p-4 pl-5">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <SeverityBadge severity={adv.severity} />
          {adv.zero_day_status && (
            <span className={clsx('inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest', sc.badge)}>
              <SIcon className="h-2.5 w-2.5" />
              {adv.zero_day_status}
            </span>
          )}
          {adv.is_kev && (
            <span className="rounded-md border border-red-500/30 bg-red-500/15 px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest text-red-400">
              CISA KEV
            </span>
          )}
        </div>

        <h3 className="font-bold text-white text-sm line-clamp-2 group-hover:text-slate-100 transition-colors mb-2">
          {adv.title}
        </h3>

        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Clock className="h-3 w-3" />
            {formatDateTime(adv.created_at)}
          </div>
          <div className="flex items-center gap-2">
            {adv.cvss_score > 0 && <CvssRing score={adv.cvss_score} />}
            <ChevronRight className="h-4 w-4 text-slate-600 group-hover:text-white transition" />
          </div>
        </div>
      </div>
    </Link>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function ZeroDayTracker() {
  const [items, setItems] = useState([])
  const [loadingItems, setLoadingItems] = useState(true)
  const [feed, setFeed] = useState([])
  const [loadingFeed, setLoadingFeed] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(null)

  // Filters & search
  const [search, setSearch] = useState('')
  const [activeFilter, setActiveFilter] = useState('All')
  const [sortBy, setSortBy] = useState('date_desc')
  const [showFilters, setShowFilters] = useState(false)

  // CVE Lookup
  const [lookupQuery, setLookupQuery] = useState('')
  const [lookupLoading, setLookupLoading] = useState(false)
  const [lookupData, setLookupData] = useState(null)
  const [lookupCveId, setLookupCveId] = useState(null)
  const [lookupError, setLookupError] = useState(null)
  const [modalOpen, setModalOpen] = useState(false)

  const searchRef = useRef(null)

  const fetchAll = async (silent = false) => {
    if (!silent) { setLoadingItems(true); setLoadingFeed(true) }
    else setRefreshing(true)

    const [itemsRes, feedRes] = await Promise.allSettled([
      api.get('/advisories', { params: { is_zero_day: true, per_page: 100 } }),
      api.get('/cve/actively-exploited', { params: { limit: 100 } }),
    ])

    if (itemsRes.status === 'fulfilled') setItems(itemsRes.value.data.items || [])
    setLoadingItems(false)

    if (feedRes.status === 'fulfilled') setFeed(feedRes.value.data.data || [])
    setLoadingFeed(false)
    setRefreshing(false)
    setLastRefresh(new Date())
  }

  useEffect(() => {
    fetchAll()
    const interval = setInterval(() => fetchAll(true), 300_000)
    return () => clearInterval(interval)
  }, [])

  // ── CVE Lookup ──────────────────────────────────────────────────────────────
  const handleLookup = async (e, overrideId) => {
    if (e?.preventDefault) e.preventDefault()
    const cveId = (overrideId || lookupQuery).trim().toUpperCase()
    if (!cveId) return
    setLookupLoading(true)
    setLookupError(null)
    setLookupData(null)
    setLookupCveId(cveId)
    try {
      const res = await api.get(`/cve/lookup/${cveId}`)
      setLookupData(res.data.data)
      setModalOpen(true)
    } catch (err) {
      setLookupError(err.response?.data?.detail || 'CVE not found.')
    } finally {
      setLookupLoading(false)
    }
  }

  const handleGenerateAI = async (cveId, data) => {
    const res = await api.post(`/cve/lookup/${cveId}/ai-summary`, { content: JSON.stringify(data) })
    return res.data.report
  }

  // ── Filtered & Sorted feed ──────────────────────────────────────────────────
  const filteredFeed = useMemo(() => {
    let data = [...feed]

    // Filter
    if (activeFilter === 'CISA KEV') data = data // all are KEV
    else if (activeFilter === 'Project Zero') data = data.filter(v => v.is_project_zero)
    else if (activeFilter === 'PoC Exploit') data = data.filter(v => v.has_public_exploit)
    else if (activeFilter === 'Unpatched (ZDI)') data = data.filter(v => v.is_zdi_upcoming)

    // Search
    if (search.trim()) {
      const q = search.toLowerCase()
      data = data.filter(v =>
        v.cveID?.toLowerCase().includes(q) ||
        v.vulnerabilityName?.toLowerCase().includes(q) ||
        v.vendorProject?.toLowerCase().includes(q) ||
        v.shortDescription?.toLowerCase().includes(q)
      )
    }

    // Sort
    if (sortBy === 'date_asc') data.sort((a, b) => new Date(a.dateAdded) - new Date(b.dateAdded))
    else if (sortBy === 'date_desc') data.sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))

    return data
  }, [feed, activeFilter, search, sortBy])

  // ── Chart Data ──────────────────────────────────────────────────────────────
  const trendData = useMemo(() => {
    const counts = {}
    feed.forEach(v => {
      const d = v.dateAdded?.slice(0, 7) // YYYY-MM
      if (d) counts[d] = (counts[d] || 0) + 1
    })
    return Object.keys(counts).sort().slice(-12).map(m => ({ month: m, count: counts[m] }))
  }, [feed])

  const vendorData = useMemo(() => {
    const counts = {}
    feed.forEach(v => {
      const vendor = v.vendorProject || 'Unknown'
      counts[vendor] = (counts[vendor] || 0) + 1
    })
    return Object.keys(counts)
      .map(v => ({ vendor: v, count: counts[v] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)
  }, [feed])

  // ── Stats ───────────────────────────────────────────────────────────────────
  const stats = useMemo(() => ({
    exploited: feed.length,
    projectZero: feed.filter(v => v.is_project_zero).length,
    hasExploit: feed.filter(v => v.has_public_exploit).length,
    tracked: items.length,
  }), [feed, items])

  // ── Loading State ───────────────────────────────────────────────────────────
  if (loadingItems && loadingFeed) {
    return (
      <div className="flex flex-col items-center justify-center gap-5 py-32">
        <div className="relative">
          <div className="absolute inset-0 rounded-full border-4 border-red-500/10 animate-ping" style={{ animationDuration: '2s' }} />
          <div className="relative w-20 h-20 rounded-full border-4 border-red-500/20 flex items-center justify-center">
            <div className="absolute inset-0 rounded-full border-4 border-red-500 border-t-transparent animate-spin" />
            <Bug className="h-8 w-8 text-red-400 animate-pulse" />
          </div>
        </div>
        <div>
          <div className="text-sm font-black text-red-400 uppercase tracking-widest text-center animate-pulse">
            Loading Zero-Day Intelligence…
          </div>
          <div className="text-xs text-slate-600 text-center mt-1">CISA KEV · Google Project Zero · Exploit-DB</div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-7">
      <style>{`
        @keyframes slideDown { from { opacity: 0; transform: translateY(-12px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        .zd-animate { animation: fadeUp 0.5s cubic-bezier(0.16,1,0.3,1) both; }
        .zd-header { animation: slideDown 0.4s ease both; }
      `}</style>

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="zd-header flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-4">
          <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl"
            style={{ background: 'linear-gradient(135deg, rgba(239,68,68,0.2), rgba(168,85,247,0.15))', border: '1px solid rgba(239,68,68,0.35)', boxShadow: '0 0 30px rgba(239,68,68,0.2)' }}>
            <Bug className="h-7 w-7 text-red-400" />
            <div className="absolute -top-1 -right-1">
              <LivePulse color="bg-red-500" />
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tight">Zero-Day Tracker</h1>
            <div className="flex items-center gap-3 mt-1">
              <div className="flex items-center gap-1.5 text-xs text-slate-500 font-bold uppercase tracking-widest">
                <LivePulse color="bg-red-500" />
                Live Intelligence
              </div>
              <span className="text-slate-700">·</span>
              <span className="text-xs text-slate-600 font-bold">CISA KEV</span>
              <span className="text-slate-700">·</span>
              <span className="text-xs text-slate-600 font-bold">Project Zero</span>
              <span className="text-slate-700">·</span>
              <span className="text-xs text-slate-600 font-bold">Exploit-DB</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-slate-600 font-bold">
              Synced {timeAgo(lastRefresh)}
            </span>
          )}
          <button
            onClick={() => fetchAll(true)}
            disabled={refreshing}
            className="flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-bold text-slate-400 hover:text-white hover:border-slate-700 transition"
          >
            <RefreshCw className={clsx('h-3.5 w-3.5', refreshing && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {/* ── CVE Lookup Bar ─────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5">
        <div className="flex items-center gap-3 mb-4">
          <Search className="h-4 w-4 text-red-400" />
          <span className="text-sm font-bold text-white">CVE Intelligence Lookup</span>
          <span className="text-xs text-slate-500">· MITRE · NVD · Local DB</span>
        </div>
        <form onSubmit={handleLookup} className="flex gap-3">
          <div className="relative flex-1">
            <input
              ref={searchRef}
              value={lookupQuery}
              onChange={e => setLookupQuery(e.target.value)}
              placeholder="CVE-2024-1234  ·  Enter any CVE ID for full dossier"
              className="input font-mono text-sm"
            />
          </div>
          <button
            type="submit"
            disabled={lookupLoading || !lookupQuery.trim()}
            className="btn-primary flex shrink-0 items-center gap-2 text-sm px-5"
          >
            {lookupLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />}
            {lookupLoading ? 'Looking up…' : 'Lookup'}
          </button>
        </form>
        {lookupError && (
          <div className="mt-3 flex items-center gap-2 text-xs text-red-400">
            <AlertTriangle className="h-3.5 w-3.5" /> {lookupError}
          </div>
        )}
      </div>

      {/* ── Stat Cards ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            label: 'Actively Exploited (KEV)', value: stats.exploited,
            icon: Flame, color: '#ef4444',
            bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)',
            glow: '0 0 24px rgba(239,68,68,0.2)', delay: 0,
          },
          {
            label: 'Google Project Zero', value: stats.projectZero,
            icon: Shield, color: '#3b82f6',
            bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.25)',
            glow: '0 0 20px rgba(59,130,246,0.15)', delay: 100,
          },
          {
            label: 'Public PoC Exploits', value: stats.hasExploit,
            icon: Terminal, color: '#f97316',
            bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.25)',
            glow: '0 0 20px rgba(249,115,22,0.12)', delay: 200,
          },
          {
            label: 'Internally Tracked', value: stats.tracked,
            icon: Database, color: '#8b5cf6',
            bg: 'rgba(139,92,246,0.08)', border: 'rgba(139,92,246,0.25)',
            glow: '0 0 20px rgba(139,92,246,0.12)', delay: 300,
          },
        ].map(s => <StatCard key={s.label} {...s} />)}
      </div>

      {/* ── Main Content Grid ───────────────────────────────────────────── */}
      <div className="grid gap-7 xl:grid-cols-[1fr_380px]">

        {/* ── Left: CISA KEV Zero-Day Feed ────────────────────────────── */}
        <div className="space-y-5 min-w-0">
          {/* Feed Header + Filters */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-white font-bold">
                <Radio className="h-5 w-5 text-red-400 animate-pulse" />
                Zero-Day Intelligence Feed
              </div>
              <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-0.5 text-xs font-black text-red-400">
                {filteredFeed.length} CVEs
              </span>
            </div>

            <div className="flex items-center gap-2">
              {/* Search within feed */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Filter feed…"
                  className="rounded-xl border border-slate-800 bg-slate-950 pl-8 pr-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-slate-700 w-40"
                />
              </div>

              {/* Sort */}
              <select
                value={sortBy}
                onChange={e => setSortBy(e.target.value)}
                className="rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400 focus:outline-none"
              >
                {SORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          </div>

          {/* Filter pills */}
          <div className="flex flex-wrap gap-2">
            {FILTER_OPTIONS.map(f => (
              <button
                key={f}
                onClick={() => setActiveFilter(f)}
                className={clsx(
                  'rounded-full border px-3 py-1 text-xs font-bold transition',
                  activeFilter === f
                    ? 'border-red-500/40 bg-red-500/15 text-red-300'
                    : 'border-slate-800 bg-slate-900 text-slate-500 hover:text-slate-300 hover:border-slate-700'
                )}
              >
                {f}
                {f !== 'All' && (
                  <span className="ml-1.5 text-[10px]">
                    ({f === 'CISA KEV' ? feed.length
                      : f === 'Project Zero' ? feed.filter(v => v.is_project_zero).length
                      : f === 'PoC Exploit' ? feed.filter(v => v.has_public_exploit).length
                      : feed.filter(v => v.is_zdi_upcoming).length})
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Feed Cards */}
          {loadingFeed ? (
            <div className="flex flex-col items-center gap-3 py-16">
              <Loader2 className="h-8 w-8 animate-spin text-red-400" />
              <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">Fetching live zero-day data…</span>
            </div>
          ) : filteredFeed.length === 0 ? (
            <div className="flex flex-col items-center gap-4 py-16 rounded-2xl border border-slate-800 bg-slate-950/50">
              <Bug className="h-10 w-10 text-slate-700" />
              <div className="text-center">
                <div className="text-sm font-bold text-slate-400">No results</div>
                <div className="text-xs text-slate-600 mt-1">Try a different filter or search term</div>
              </div>
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2">
              {filteredFeed.map((vuln, i) => (
                <div key={`${vuln.cveID}-${i}`} className="zd-animate" style={{ animationDelay: `${Math.min(i * 40, 400)}ms` }}>
                  <ZeroDayCard
                    vuln={vuln}
                    index={i}
                    onAnalyze={cveId => {
                      setLookupQuery(cveId)
                      handleLookup(null, cveId)
                    }}
                  />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Right: Tracked Advisories + Charts ──────────────────────── */}
        <div className="space-y-6">

          {/* Internally Tracked */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <ShieldAlert className="h-4 w-4 text-purple-400" />
                Internal Zero-Days
                <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">{items.length}</span>
              </div>
              <Link to="/advisories" className="text-xs text-slate-500 hover:text-cyan-400 transition flex items-center gap-1">
                View all <ChevronRight className="h-3 w-3" />
              </Link>
            </div>
            <div className="p-4 space-y-3">
              {loadingItems ? (
                <div className="flex justify-center py-8"><Loader2 className="h-6 w-6 animate-spin text-purple-400" /></div>
              ) : items.length === 0 ? (
                <div className="flex flex-col items-center gap-3 py-10 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900">
                    <Target className="h-6 w-6 text-slate-700" />
                  </div>
                  <div>
                    <div className="text-sm font-bold text-slate-400">No Zero-Days Tracked</div>
                    <div className="text-xs text-slate-600 mt-1">Tag internal advisories as Zero-Day to monitor here.</div>
                  </div>
                </div>
              ) : (
                items.map(adv => <TrackedAdvisoryCard key={adv.id} adv={adv} />)
              )}
            </div>
          </div>

          {/* Status legend */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5">
            <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-4">Status Legend</div>
            <div className="space-y-2.5">
              {Object.entries(STATUS_CFG).map(([label, cfg]) => {
                const Icon = cfg.icon
                const count = items.filter(i => i.zero_day_status === label).length
                return (
                  <div key={label} className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}>
                        <Icon className="h-3.5 w-3.5" style={{ color: cfg.text }} />
                      </div>
                      <span className="text-xs font-bold text-slate-400">{label}</span>
                    </div>
                    <span className="text-xs font-black" style={{ color: cfg.text }}>{count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ── Analytics Section ──────────────────────────────────────────── */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Trend Chart */}
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-6">
          <div className="flex items-center gap-2 mb-5">
            <TrendingUp className="h-4 w-4 text-red-400" />
            <span className="text-sm font-bold text-white uppercase tracking-widest">Zero-Day Trend (12 Months)</span>
          </div>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="zdGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="month" stroke="#475569" fontSize={10} tickMargin={8} minTickGap={20} />
                <YAxis stroke="#475569" fontSize={10} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: 'rgba(10,14,26,0.95)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '10px', color: '#fff', fontSize: '12px' }}
                  itemStyle={{ color: '#fca5a5', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="count" name="CVEs" stroke="#ef4444" strokeWidth={2.5} fillOpacity={1} fill="url(#zdGrad)" dot={false} activeDot={{ r: 5, fill: '#ef4444', stroke: '#fff', strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Vendor Chart */}
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-6">
          <div className="flex items-center gap-2 mb-5">
            <Building2 className="h-4 w-4 text-purple-400" />
            <span className="text-sm font-bold text-white uppercase tracking-widest">Top Affected Vendors</span>
          </div>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={vendorData} layout="vertical" margin={{ left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#475569" fontSize={10} allowDecimals={false} />
                <YAxis type="category" dataKey="vendor" stroke="#94a3b8" fontSize={9} width={75} />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={{ backgroundColor: 'rgba(10,14,26,0.95)', border: '1px solid rgba(139,92,246,0.3)', borderRadius: '10px', color: '#fff', fontSize: '12px' }}
                />
                <Bar dataKey="count" name="CVEs" radius={[0, 4, 4, 0]}>
                  {vendorData.map((_, i) => (
                    <Cell key={i} fill={VENDOR_COLORS[i % VENDOR_COLORS.length]} opacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ── Sources Banner ─────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800 bg-slate-950/50 px-5 py-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <span className="text-xs font-bold uppercase tracking-widest text-slate-600">Intelligence Sources</span>
          {[
            { name: 'CISA KEV', desc: 'Known Exploited Vulnerabilities', color: 'text-red-400', dot: 'bg-red-400', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
            { name: 'Google Project Zero', desc: 'In-the-wild 0day tracking', color: 'text-blue-400', dot: 'bg-blue-400', url: 'https://googleprojectzero.blogspot.com/' },
            { name: 'Exploit-DB', desc: 'Public exploit database', color: 'text-orange-400', dot: 'bg-orange-400', url: 'https://exploit-db.com/' },
            { name: 'MITRE CVE', desc: 'CVE programme', color: 'text-cyan-400', dot: 'bg-cyan-400', url: 'https://cve.mitre.org/' },
            { name: 'NVD / NIST', desc: 'National Vulnerability DB', color: 'text-emerald-400', dot: 'bg-emerald-400', url: 'https://nvd.nist.gov/' },
          ].map(s => (
            <a key={s.name} href={s.url} target="_blank" rel="noreferrer"
              className="flex items-center gap-2 group transition">
              <span className={clsx('h-1.5 w-1.5 rounded-full', s.dot)} />
              <span className={clsx('text-xs font-bold group-hover:underline', s.color)}>{s.name}</span>
              <span className="text-xs text-slate-600 hidden sm:inline">· {s.desc}</span>
              <ExternalLink className="h-2.5 w-2.5 text-slate-700 group-hover:text-slate-500 transition" />
            </a>
          ))}
        </div>
      </div>

      {/* ── CVE Dossier Modal ───────────────────────────────────────────── */}
      {modalOpen && lookupData && (
        <CveDossierModal
          cveId={lookupCveId}
          data={lookupData}
          onClose={() => { setModalOpen(false); setLookupData(null); setLookupCveId(null) }}
          onGenerateAI={handleGenerateAI}
        />
      )}
    </div>
  )
}
