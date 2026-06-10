import { useCallback, useMemo, useRef, useState, useEffect } from 'react'
import {
  AlertTriangle, CheckCircle2, Clipboard, Database, Download, ExternalLink,
  FileWarning, Globe2, History, Link as LinkIcon, Loader2, Lock, Radar,
  ScanLine, ShieldAlert, ShieldCheck, Trash2, Upload, XCircle, Zap,
  Activity, Server, Cpu, Hash, Eye, Terminal, Layers, BarChart2,
  ChevronRight, RefreshCw, Info, MapPin, Shield, Search, FileText,
  AlertCircle, CheckCircle, Clock, Wifi, WifiOff, Crosshair
} from 'lucide-react'
import clsx from 'clsx'
import api from '../services/api'
import toast from 'react-hot-toast'

// ─── Verdict Config ──────────────────────────────────────────────────────────
const VERDICT_CONFIG = {
  Malicious: {
    bg: 'bg-red-500/10',
    border: 'border-red-500/40',
    text: 'text-red-400',
    glow: 'shadow-[0_0_30px_rgba(239,68,68,0.3)]',
    icon: XCircle,
    badge: 'bg-red-500/20 text-red-300 border-red-500/40',
    ring: 'ring-red-500/30',
    barColor: '#ef4444',
    pulse: true,
  },
  Suspicious: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/40',
    text: 'text-amber-400',
    glow: 'shadow-[0_0_30px_rgba(245,158,11,0.25)]',
    icon: AlertTriangle,
    badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    ring: 'ring-amber-500/30',
    barColor: '#f59e0b',
    pulse: false,
  },
  'Review Required': {
    bg: 'bg-sky-500/10',
    border: 'border-sky-500/40',
    text: 'text-sky-400',
    glow: 'shadow-[0_0_20px_rgba(14,165,233,0.2)]',
    icon: AlertCircle,
    badge: 'bg-sky-500/20 text-sky-300 border-sky-500/40',
    ring: 'ring-sky-500/30',
    barColor: '#0ea5e9',
    pulse: false,
  },
  Clean: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/40',
    text: 'text-emerald-400',
    glow: 'shadow-[0_0_20px_rgba(16,185,129,0.2)]',
    icon: CheckCircle2,
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    ring: 'ring-emerald-500/30',
    barColor: '#10b981',
    pulse: false,
  },
  'Clean (Local Only)': {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/40',
    text: 'text-emerald-400',
    glow: 'shadow-[0_0_20px_rgba(16,185,129,0.2)]',
    icon: CheckCircle2,
    badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    ring: 'ring-emerald-500/30',
    barColor: '#10b981',
    pulse: false,
  },
}

const SCAN_STEPS = [
  { id: 'init', label: 'Initializing scan engine', icon: Cpu },
  { id: 'hash', label: 'Computing cryptographic signatures', icon: Hash },
  { id: 'cloud', label: 'Querying threat intelligence feeds', icon: Globe2 },
  { id: 'vt', label: 'Checking VirusTotal database', icon: Shield },
  { id: 'bazaar', label: 'MalwareBazaar reputation lookup', icon: Database },
  { id: 'network', label: 'Analysing network exposure', icon: Wifi },
  { id: 'ai', label: 'Generating AI analyst verdict', icon: Zap },
]

const SOURCE_ICONS = {
  'VirusTotal': { color: 'text-blue-400', bg: 'bg-blue-500/10' },
  'MalwareBazaar': { color: 'text-red-400', bg: 'bg-red-500/10' },
  'Hybrid Analysis': { color: 'text-purple-400', bg: 'bg-purple-500/10' },
  'Pulsedive': { color: 'text-orange-400', bg: 'bg-orange-500/10' },
  'URLhaus Host': { color: 'text-rose-400', bg: 'bg-rose-500/10' },
  'ThreatFox': { color: 'text-red-400', bg: 'bg-red-500/10' },
  'OpenPhish': { color: 'text-amber-400', bg: 'bg-amber-500/10' },
  'URLScan.io': { color: 'text-cyan-400', bg: 'bg-cyan-500/10' },
  'Shodan InternetDB': { color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function getVerdict(data, type) {
  if (!data) return 'Review Required'
  if (type === 'url') return data.verdict || 'Review Required'
  return data.cloud_analysis?.verdict || data.local_analysis?.verdict || 'Review Required'
}

function getScore(data, type) {
  if (!data) return 0
  if (type === 'url') return Math.max(data.phishing_score || 0, data.threat_score || 0)
  return Math.max(data.cloud_analysis?.threat_score || 0, data.local_analysis?.threat_score || 0)
}

function getSources(data, type) {
  if (!data) return []
  if (type === 'url') return data.source_results || []
  return data.cloud_analysis?.source_results || []
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ScannerAnimation({ status, steps, activeStep }) {
  return (
    <div className="flex flex-col items-center justify-center gap-8 py-12">
      {/* Animated radar ring */}
      <div className="relative flex items-center justify-center">
        <div className="absolute inset-0 rounded-full border border-cyan-500/20 animate-ping" style={{ animationDuration: '2s' }} />
        <div className="absolute inset-0 rounded-full border border-cyan-500/10 animate-ping" style={{ animationDuration: '3s', animationDelay: '0.5s' }} />
        <div className="w-24 h-24 rounded-full border border-cyan-500/30 bg-cyan-500/5 flex items-center justify-center">
          <div className="w-16 h-16 rounded-full border border-cyan-400/40 bg-cyan-500/10 flex items-center justify-center">
            <ScanLine className="h-8 w-8 text-cyan-400 animate-pulse" />
          </div>
        </div>
        {/* Rotating sweep */}
        <div
          className="absolute inset-0 rounded-full"
          style={{
            background: 'conic-gradient(from 0deg, transparent 70%, rgba(6,182,212,0.3) 100%)',
            animation: 'spin 2s linear infinite',
          }}
        />
      </div>

      <div className="text-center">
        <div className="text-sm font-bold text-cyan-300 mb-1 animate-pulse">{status}</div>
        <div className="text-xs text-slate-500">DeepScan Lab — Multi-source intelligence</div>
      </div>

      {/* Step tracker */}
      <div className="w-full max-w-sm space-y-2">
        {steps.map((step, i) => {
          const StepIcon = step.icon
          const isDone = i < activeStep
          const isActive = i === activeStep
          return (
            <div
              key={step.id}
              className={clsx(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-xs transition-all',
                isDone && 'text-emerald-400 bg-emerald-500/5',
                isActive && 'text-cyan-300 bg-cyan-500/10 border border-cyan-500/20',
                !isDone && !isActive && 'text-slate-600',
              )}
            >
              {isDone ? (
                <CheckCircle className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
              ) : isActive ? (
                <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-cyan-400" />
              ) : (
                <StepIcon className="h-3.5 w-3.5 shrink-0 text-slate-700" />
              )}
              {step.label}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function VerdictBadge({ verdict, size = 'md' }) {
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG['Review Required']
  const VIcon = cfg.icon
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 font-bold rounded-full border',
        cfg.badge,
        size === 'sm' && 'text-xs px-2 py-0.5',
        size === 'md' && 'text-sm px-3 py-1',
        size === 'lg' && 'text-base px-4 py-1.5',
      )}
    >
      <VIcon className={clsx(size === 'sm' ? 'h-3 w-3' : 'h-4 w-4')} />
      {verdict}
    </span>
  )
}

function ThreatScoreMeter({ score, verdict }) {
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG['Review Required']
  const radius = 52
  const circ = 2 * Math.PI * radius
  const offset = circ - (score / 100) * circ

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative h-32 w-32">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
          <circle
            cx="60" cy="60" r={radius} fill="none"
            stroke={cfg.barColor} strokeWidth="10"
            strokeDasharray={circ} strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 6px ${cfg.barColor})` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={clsx('text-3xl font-black tabular-nums', cfg.text)}>{score}</span>
          <span className="text-xs text-slate-500 font-bold">/100</span>
        </div>
      </div>
      <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">Risk Score</span>
    </div>
  )
}

function SourceBadge({ source, verdict, found, detections, reportUrl }) {
  const style = SOURCE_ICONS[source] || { color: 'text-slate-400', bg: 'bg-slate-800' }
  const verdictMap = {
    malicious: { cls: 'bg-red-500/20 text-red-300 border-red-500/40', label: 'Malicious' },
    suspicious: { cls: 'bg-amber-500/20 text-amber-300 border-amber-500/40', label: 'Suspicious' },
    clean: { cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40', label: 'Clean' },
  }
  const v = verdictMap[verdict?.toLowerCase()] || { cls: 'bg-slate-800 text-slate-400 border-slate-700', label: verdict || 'Unknown' }

  return (
    <div className="flex items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/50 px-4 py-3 transition hover:border-slate-700 hover:bg-slate-900">
      <div className="flex items-center gap-3 min-w-0">
        <div className={clsx('flex h-8 w-8 shrink-0 items-center justify-center rounded-lg', style.bg)}>
          <Database className={clsx('h-4 w-4', style.color)} />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-bold text-white">{source}</div>
          {detections && <div className="truncate text-xs text-slate-500">{detections}</div>}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <span className={clsx('inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-bold', v.cls)}>
          {found ? v.label : 'Not Found'}
        </span>
        {reportUrl && (
          <a href={reportUrl} target="_blank" rel="noreferrer"
            className="flex h-7 w-7 items-center justify-center rounded-lg text-slate-500 hover:bg-cyan-500/10 hover:text-cyan-300 transition">
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        )}
      </div>
    </div>
  )
}

function InfoCard({ label, value, icon: Icon, mono = false, highlight }) {
  return (
    <div className={clsx(
      'rounded-xl border p-4 transition',
      highlight
        ? 'border-cyan-500/30 bg-cyan-500/5'
        : 'border-slate-800 bg-slate-900/50'
    )}>
      <div className="flex items-center gap-2 mb-2">
        {Icon && <Icon className="h-3.5 w-3.5 text-slate-500" />}
        <span className="text-xs font-bold uppercase tracking-widest text-slate-500">{label}</span>
      </div>
      <div className={clsx('text-sm font-bold text-white break-all', mono && 'font-mono text-xs')}>{value || '—'}</div>
    </div>
  )
}

function ResultTab({ id, label, icon: Icon, active, onClick, count }) {
  return (
    <button
      onClick={() => onClick(id)}
      className={clsx(
        'relative flex items-center gap-2 px-4 py-2.5 text-sm font-bold rounded-lg transition-all whitespace-nowrap',
        active
          ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
          : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50',
      )}
    >
      <Icon className="h-4 w-4" />
      {label}
      {count !== undefined && count > 0 && (
        <span className={clsx(
          'rounded-full px-1.5 py-0.5 text-xs font-black',
          active ? 'bg-cyan-500/30 text-cyan-200' : 'bg-slate-700 text-slate-400'
        )}>
          {count}
        </span>
      )}
    </button>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-6 py-16 text-center">
      <div className="relative">
        <div className="w-20 h-20 rounded-2xl border border-slate-800 bg-slate-900 flex items-center justify-center">
          <Crosshair className="h-10 w-10 text-slate-700" />
        </div>
        <div className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-cyan-500/20 border border-cyan-500/40 animate-pulse" />
      </div>
      <div>
        <div className="text-base font-bold text-slate-400 mb-1">Awaiting Target</div>
        <div className="text-sm text-slate-600 max-w-xs">
          Enter a URL, domain, IP address, or file hash — or upload a file for deep static analysis.
        </div>
      </div>
      <div className="flex flex-wrap justify-center gap-2">
        {['URLhaus', 'ThreatFox', 'MalwareBazaar', 'VirusTotal', 'Shodan', 'OpenPhish', 'URLScan.io'].map(s => (
          <span key={s} className="rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs text-slate-500 font-bold">{s}</span>
        ))}
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function DeepScan() {
  const [activeTab, setActiveTab] = useState('indicator')
  const [target, setTarget] = useState('')
  const [file, setFile] = useState(null)
  const [smartMode, setSmartMode] = useState(true)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('')
  const [result, setResult] = useState(null)
  const [resultTab, setResultTab] = useState('overview')
  const [scanStepIdx, setScanStepIdx] = useState(0)
  const [dragging, setDragging] = useState(false)
  const stepTimerRef = useRef(null)

  const [scanHistory, setScanHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('deepscan_history') || '[]') } catch { return [] }
  })

  const verdict = getVerdict(result?.data, result?.type)
  const score = getScore(result?.data, result?.type)
  const sources = getSources(result?.data, result?.type)
  const positives = sources.filter(item => item.found && item.verdict !== 'clean')

  const riskFactors = useMemo(() => {
    if (!result) return []
    if (result.type === 'url') return result.data.risk_factors || result.data.suspicious_patterns || []
    return [
      ...(result.data.cloud_analysis?.risk_factors || []),
      ...(result.data.local_analysis?.suspicious_features || []),
    ]
  }, [result])

  const networkExposure = useMemo(() => {
    if (!result) return null
    if (result.type === 'url') return result.data.network_exposure || null
    return null
  }, [result])

  const fileMetadata = useMemo(() => {
    if (!result || result.type !== 'file') return null
    return result.data.local_analysis || null
  }, [result])

  // Animate scan steps
  useEffect(() => {
    if (loading) {
      setScanStepIdx(0)
      let i = 0
      stepTimerRef.current = setInterval(() => {
        i++
        if (i < SCAN_STEPS.length) setScanStepIdx(i)
        else clearInterval(stepTimerRef.current)
      }, 900)
    } else {
      clearInterval(stepTimerRef.current)
    }
    return () => clearInterval(stepTimerRef.current)
  }, [loading])

  const rememberScan = useCallback((entry) => {
    setScanHistory(prev => {
      const next = [entry, ...prev].slice(0, 15)
      localStorage.setItem('deepscan_history', JSON.stringify(next))
      return next
    })
  }, [])

  const normalizeTarget = (value) => {
    const trimmed = value.trim()
    if (!trimmed) return ''
    const isHash = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(trimmed)
    if (isHash) return trimmed
    return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  }

  const runIndicatorScan = async (e) => {
    e.preventDefault()
    const normalized = normalizeTarget(target)
    if (!normalized) return
    const isHash = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(normalized)

    setLoading(true)
    setResult(null)
    setResultTab('overview')
    setStatus(isHash ? 'Checking hash reputation across threat DBs' : 'Analysing URL and host intelligence')

    try {
      const formData = new FormData()
      formData.append('mode', smartMode ? 'advanced' : 'basic')
      let res
      if (isHash) {
        formData.append('hash', normalized)
        res = await api.post('/sandbox/scan-hash', formData)
        setResult({ type: 'file', data: res.data })
      } else {
        formData.append('url', normalized)
        res = await api.post('/sandbox/scan-url', formData)
        setResult({ type: 'url', data: res.data })
      }
      rememberScan({
        type: isHash ? 'hash' : 'url',
        label: normalized,
        verdict: isHash ? res.data.cloud_analysis?.verdict : res.data.verdict,
        mode: smartMode ? 'advanced' : 'basic',
        scannedAt: new Date().toISOString(),
      })
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Scan failed')
    } finally {
      setLoading(false)
      setStatus('')
    }
  }

  const runFileScan = async (e) => {
    e.preventDefault()
    if (!file) return
    setLoading(true)
    setResult(null)
    setResultTab('overview')
    setStatus('Computing hash and running local static analysis')

    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('mode', smartMode ? 'advanced' : 'basic')
      const res = await api.post('/sandbox/scan-file', formData)
      setResult({ type: 'file', data: res.data })
      rememberScan({
        type: 'file',
        label: file.name,
        verdict: res.data.cloud_analysis?.verdict || res.data.local_analysis?.verdict,
        mode: smartMode ? 'advanced' : 'basic',
        scannedAt: new Date().toISOString(),
      })
    } catch {
      toast.error('File scan failed')
    } finally {
      setLoading(false)
      setStatus('')
    }
  }

  const copyReport = async () => {
    if (!result) return
    await navigator.clipboard.writeText(JSON.stringify(result.data, null, 2))
    toast.success('Full report copied to clipboard')
  }

  const downloadReport = () => {
    if (!result) return
    const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `deepscan-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const clearHistory = () => {
    localStorage.removeItem('deepscan_history')
    setScanHistory([])
  }

  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG['Review Required']
  const VIcon = cfg.icon

  // Summary text
  const summaryText = result?.data?.summary || result?.data?.ai_report || result?.data?.cloud_analysis?.summary

  return (
    <div className="space-y-6">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-4">
          <div className="relative flex h-12 w-12 items-center justify-center rounded-xl border border-cyan-500/30 bg-cyan-500/10">
            <ScanLine className="h-6 w-6 text-cyan-300" />
            <span className="absolute -top-1 -right-1 h-3 w-3 rounded-full bg-cyan-400 border-2 border-slate-950 animate-pulse" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-white">DeepScan Lab</h1>
            <p className="text-sm text-slate-400">
              Multi-source intelligence · VirusTotal · MalwareBazaar · ThreatFox · URLScan · Shodan
            </p>
          </div>
        </div>

        {/* Mode Toggle */}
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">Scan Mode</span>
          <div className="flex items-center gap-1 rounded-xl border border-slate-800 bg-slate-950 p-1">
            <button
              onClick={() => setSmartMode(false)}
              className={clsx('flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-bold transition',
                !smartMode ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-500 hover:text-slate-300')}
            >
              <Activity className="h-3 w-3" /> Basic
            </button>
            <button
              onClick={() => setSmartMode(true)}
              className={clsx('flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-bold transition',
                smartMode ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/30' : 'text-slate-500 hover:text-slate-300')}
            >
              <Zap className="h-3 w-3" /> Advanced
            </button>
          </div>
        </div>
      </div>

      {/* ── Free Sources Banner ─────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800 bg-slate-950/50 px-4 py-2.5">
        <span className="text-xs font-bold text-slate-500 uppercase tracking-widest mr-1">Live Sources:</span>
        {[
          { name: 'VirusTotal', free: true },
          { name: 'MalwareBazaar', free: true },
          { name: 'ThreatFox', free: true },
          { name: 'URLhaus', free: true },
          { name: 'OpenPhish', free: true },
          { name: 'URLScan.io', free: true },
          { name: 'Shodan InternetDB', free: true },
          { name: 'Pulsedive', free: true },
          { name: 'Hybrid Analysis', free: false },
        ].map(s => (
          <span
            key={s.name}
            className={clsx(
              'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-bold border',
              s.free
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                : 'border-slate-700 bg-slate-900 text-slate-500'
            )}
          >
            <span className={clsx('h-1.5 w-1.5 rounded-full', s.free ? 'bg-emerald-400' : 'bg-slate-600')} />
            {s.name}
          </span>
        ))}
      </div>

      {/* ── Main Grid ──────────────────────────────────────────────────── */}
      <div className="grid gap-6 xl:grid-cols-[380px_1fr]">

        {/* ── Left Panel ─────────────────────────────────────────────── */}
        <div className="space-y-5">

          {/* Input Panel */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Radar className="h-4 w-4 text-cyan-300" />
                Scan Target
              </div>
            </div>

            {/* Tab switcher */}
            <div className="grid grid-cols-2 gap-1 border-b border-slate-800 bg-slate-900/40 p-2">
              <button
                onClick={() => setActiveTab('indicator')}
                className={clsx(
                  'flex items-center justify-center gap-2 rounded-lg py-2.5 text-sm font-bold transition',
                  activeTab === 'indicator'
                    ? 'bg-slate-800 text-white shadow-sm'
                    : 'text-slate-500 hover:text-slate-300'
                )}
              >
                <LinkIcon className="h-4 w-4" /> URL / Hash / IP
              </button>
              <button
                onClick={() => setActiveTab('file')}
                className={clsx(
                  'flex items-center justify-center gap-2 rounded-lg py-2.5 text-sm font-bold transition',
                  activeTab === 'file'
                    ? 'bg-slate-800 text-white shadow-sm'
                    : 'text-slate-500 hover:text-slate-300'
                )}
              >
                <FileWarning className="h-4 w-4" /> File Upload
              </button>
            </div>

            <div className="p-5">
              {activeTab === 'indicator' ? (
                <form onSubmit={runIndicatorScan} className="space-y-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
                    <input
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      disabled={loading}
                      className="input pl-9 font-mono text-sm"
                      placeholder="https://site.com, domain, IP, or hash"
                    />
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    {['URL/Domain', 'IP Address', 'MD5 Hash', 'SHA256'].map(hint => (
                      <span key={hint} className="rounded-md border border-slate-800 bg-slate-900 px-2 py-0.5 text-xs text-slate-500">{hint}</span>
                    ))}
                  </div>

                  <button
                    disabled={loading || !target.trim()}
                    className="btn-primary flex w-full items-center justify-center gap-2 text-sm"
                  >
                    {loading
                      ? <><Loader2 className="h-4 w-4 animate-spin" /> Scanning…</>
                      : <><Zap className="h-4 w-4" /> Run Deep Scan</>}
                  </button>
                </form>
              ) : (
                <form onSubmit={runFileScan} className="space-y-4">
                  <label
                    htmlFor="deepscan-file"
                    onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={(e) => {
                      e.preventDefault()
                      setDragging(false)
                      const dropped = e.dataTransfer.files?.[0]
                      if (dropped) setFile(dropped)
                    }}
                    className={clsx(
                      'flex min-h-40 cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border border-dashed p-5 text-center transition-all',
                      dragging && 'border-cyan-400/60 bg-cyan-500/10 scale-[1.02]',
                      file && !dragging && 'border-cyan-500/40 bg-cyan-500/5',
                      !file && !dragging && 'border-slate-700 bg-slate-900/50 hover:border-cyan-500/30 hover:bg-slate-900',
                    )}
                  >
                    <input id="deepscan-file" type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
                    <div className={clsx('flex h-12 w-12 items-center justify-center rounded-xl border',
                      file ? 'border-cyan-500/40 bg-cyan-500/10' : 'border-slate-700 bg-slate-900'
                    )}>
                      {file
                        ? <FileText className="h-6 w-6 text-cyan-400" />
                        : <Upload className="h-6 w-6 text-slate-600" />}
                    </div>
                    {file ? (
                      <div>
                        <div className="max-w-[220px] truncate text-sm font-bold text-white">{file.name}</div>
                        <div className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB · Click to change</div>
                      </div>
                    ) : (
                      <div>
                        <div className="text-sm font-bold text-slate-300">Drop file or click to browse</div>
                        <div className="text-xs text-slate-600 mt-0.5">EXE, DLL, PDF, ZIP, JS, PS1…</div>
                      </div>
                    )}
                  </label>

                  {file && (
                    <button type="button" onClick={() => setFile(null)}
                      className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-red-400 transition">
                      <Trash2 className="h-3 w-3" /> Remove file
                    </button>
                  )}

                  <button
                    disabled={loading || !file}
                    className="btn-primary flex w-full items-center justify-center gap-2 text-sm"
                  >
                    {loading
                      ? <><Loader2 className="h-4 w-4 animate-spin" /> Scanning…</>
                      : <><Upload className="h-4 w-4" /> Scan File</>}
                  </button>
                </form>
              )}
            </div>
          </div>

          {/* Recent Scans */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950/70 overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <History className="h-4 w-4 text-cyan-300" />
                Scan History
                {scanHistory.length > 0 && (
                  <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">{scanHistory.length}</span>
                )}
              </div>
              {scanHistory.length > 0 && (
                <button onClick={clearHistory}
                  className="flex items-center gap-1 text-xs text-slate-500 hover:text-red-400 transition">
                  <Trash2 className="h-3.5 w-3.5" /> Clear
                </button>
              )}
            </div>
            <div className="p-3">
              {scanHistory.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-6 text-center">
                  <Clock className="h-6 w-6 text-slate-700" />
                  <div className="text-xs text-slate-600">No scan history yet</div>
                </div>
              ) : (
                <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                  {scanHistory.map((item, index) => {
                    const itemVerdict = item.verdict || 'Unknown'
                    const itemCfg = VERDICT_CONFIG[itemVerdict]
                    return (
                      <button
                        key={`${item.scannedAt}-${index}`}
                        onClick={() => item.type !== 'file' && setTarget(item.label)}
                        className="group w-full rounded-xl border border-slate-800 bg-slate-900/50 p-3 text-left transition hover:border-slate-700 hover:bg-slate-900"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <div className={clsx('h-6 w-6 shrink-0 rounded-md flex items-center justify-center text-xs',
                              item.type === 'file' ? 'bg-purple-500/10 text-purple-400' :
                              item.type === 'hash' ? 'bg-orange-500/10 text-orange-400' :
                              'bg-cyan-500/10 text-cyan-400'
                            )}>
                              {item.type === 'file' ? <FileText className="h-3 w-3" /> :
                               item.type === 'hash' ? <Hash className="h-3 w-3" /> :
                               <Globe2 className="h-3 w-3" />}
                            </div>
                            <span className="truncate font-mono text-xs text-slate-400 group-hover:text-slate-300">{item.label}</span>
                          </div>
                          <VerdictBadge verdict={itemVerdict} size="sm" />
                        </div>
                        <div className="mt-1.5 text-xs text-slate-600 ml-8">
                          {new Date(item.scannedAt).toLocaleString()} · {item.mode}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Right Panel ────────────────────────────────────────────── */}
        <div>
          {loading ? (
            <div className="rounded-2xl border border-slate-800 bg-slate-950/70">
              <ScannerAnimation status={status} steps={SCAN_STEPS} activeStep={scanStepIdx} />
            </div>
          ) : !result ? (
            <div className="rounded-2xl border border-slate-800 bg-slate-950/70">
              <EmptyState />
            </div>
          ) : (
            <div className="space-y-5">

              {/* ── Verdict Hero Card ─────────────────────────────── */}
              <div className={clsx(
                'rounded-2xl border p-6 transition',
                cfg.bg, cfg.border, cfg.glow,
              )}>
                <div className="flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
                  {/* Left: Verdict */}
                  <div className="flex items-start gap-4">
                    <div className={clsx(
                      'flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl border',
                      cfg.bg, cfg.border,
                      cfg.pulse && 'animate-pulse',
                    )}>
                      <VIcon className={clsx('h-8 w-8', cfg.text)} />
                    </div>
                    <div>
                      <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-1">Final Verdict</div>
                      <div className={clsx('text-3xl font-black mb-2', cfg.text)}>{verdict}</div>
                      <div className="flex flex-wrap items-center gap-2">
                        <VerdictBadge verdict={verdict} size="md" />
                        <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-bold text-slate-400">
                          {result.type === 'url' ? '🌐 URL/Domain' : '📁 File/Hash'}
                        </span>
                        <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-bold text-slate-400">
                          {smartMode ? '⚡ Advanced' : '🔵 Basic'} mode
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right: Score meter + actions */}
                  <div className="flex flex-col items-end gap-3">
                    <ThreatScoreMeter score={score} verdict={verdict} />
                    <div className="flex gap-2">
                      <button onClick={copyReport} className="btn-ghost flex items-center gap-1.5 text-xs py-2 px-3">
                        <Clipboard className="h-3.5 w-3.5" /> Copy JSON
                      </button>
                      <button onClick={downloadReport} className="btn-ghost flex items-center gap-1.5 text-xs py-2 px-3">
                        <Download className="h-3.5 w-3.5" /> Download
                      </button>
                    </div>
                  </div>
                </div>

                {/* Stats row */}
                <div className="mt-5 grid grid-cols-3 gap-3 border-t border-white/5 pt-5">
                  <div className="text-center">
                    <div className="text-2xl font-black text-white">{positives.length}</div>
                    <div className="text-xs text-slate-500 font-bold">Positive Hits</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-black text-white">{sources.length}</div>
                    <div className="text-xs text-slate-500 font-bold">Sources Checked</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-black text-white">{riskFactors.length}</div>
                    <div className="text-xs text-slate-500 font-bold">Risk Factors</div>
                  </div>
                </div>
              </div>

              {/* ── AI Summary ────────────────────────────────────── */}
              {summaryText && (
                <div className="rounded-2xl border border-cyan-500/20 bg-gradient-to-br from-cyan-500/5 to-blue-500/5 p-5">
                  <div className="mb-3 flex items-center gap-2 text-sm font-bold text-cyan-200">
                    <Zap className="h-4 w-4" /> AI Analyst Summary
                    <span className="ml-auto rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-xs font-bold text-cyan-400">
                      Groq-Powered
                    </span>
                  </div>
                  <p className="text-sm leading-7 text-slate-300">{summaryText}</p>
                </div>
              )}

              {/* ── Result Tabs ───────────────────────────────────── */}
              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 overflow-hidden">
                <div className="flex items-center gap-1.5 overflow-x-auto border-b border-slate-800 p-3">
                  <ResultTab id="overview" label="Overview" icon={Eye} active={resultTab === 'overview'} onClick={setResultTab} />
                  <ResultTab id="sources" label="Sources" icon={Database} active={resultTab === 'sources'} onClick={setResultTab} count={sources.length} />
                  <ResultTab id="evidence" label="Evidence" icon={AlertTriangle} active={resultTab === 'evidence'} onClick={setResultTab} count={riskFactors.length} />
                  {networkExposure && (
                    <ResultTab id="network" label="Network" icon={Wifi} active={resultTab === 'network'} onClick={setResultTab} />
                  )}
                  {fileMetadata && (
                    <ResultTab id="file" label="File Intel" icon={FileText} active={resultTab === 'file'} onClick={setResultTab} />
                  )}
                </div>

                <div className="p-5">
                  {/* ── Overview Tab ─────────────────────────────── */}
                  {resultTab === 'overview' && (
                    <div className="space-y-5">
                      {/* URL / domain metadata */}
                      {result.type === 'url' && (
                        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                          <InfoCard label="Domain" value={result.data.domain} icon={Globe2} />
                          <InfoCard label="IP Address" value={result.data.ip} icon={Server} mono />
                          <InfoCard
                            label="Protocol"
                            value={result.data.is_https ? 'HTTPS (Encrypted)' : 'HTTP (Unencrypted)'}
                            icon={result.data.is_https ? Lock : WifiOff}
                            highlight={!result.data.is_https}
                          />
                          {result.data.ssl_issuer && (
                            <InfoCard label="SSL Issuer" value={result.data.ssl_issuer} icon={Lock} />
                          )}
                          {result.data.location && result.data.location !== 'Unknown' && (
                            <InfoCard label="Location" value={result.data.location} icon={MapPin} />
                          )}
                        </div>
                      )}

                      {/* Hash metadata */}
                      {result.type === 'file' && result.data.local_analysis && (
                        <div className="grid gap-3 sm:grid-cols-2">
                          <InfoCard label="SHA-256" value={result.data.local_analysis.sha256} icon={Hash} mono />
                          <InfoCard label="MD5" value={result.data.local_analysis.md5} icon={Hash} mono />
                          <InfoCard label="File Size" value={`${result.data.local_analysis.size_kb} KB`} icon={FileText} />
                          <InfoCard label="Filename" value={result.data.local_analysis.filename} icon={FileText} />
                        </div>
                      )}

                      {/* Source coverage pills */}
                      <div>
                        <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">Intelligence Sources Checked</div>
                        <div className="flex flex-wrap gap-2">
                          {sources.map(s => {
                            const style = SOURCE_ICONS[s.source] || { color: 'text-slate-400', bg: 'bg-slate-800' }
                            const isPositive = s.found && s.verdict !== 'clean'
                            return (
                              <span
                                key={s.source}
                                className={clsx(
                                  'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-bold',
                                  isPositive
                                    ? 'border-red-500/40 bg-red-500/10 text-red-300'
                                    : s.found
                                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                                    : 'border-slate-700 bg-slate-900 text-slate-500'
                                )}
                              >
                                <span className={clsx('h-1.5 w-1.5 rounded-full',
                                  isPositive ? 'bg-red-400' : s.found ? 'bg-emerald-400' : 'bg-slate-600'
                                )} />
                                {s.source}
                              </span>
                            )
                          })}
                          {sources.length === 0 && (
                            <span className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-500">Local Static Analysis</span>
                          )}
                        </div>
                      </div>

                      {/* URLhaus details */}
                      {result.type === 'url' && result.data.urlhaus && (
                        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4">
                          <div className="flex items-center gap-2 text-sm font-bold text-red-400 mb-3">
                            <AlertTriangle className="h-4 w-4" /> URLhaus Threat Match
                          </div>
                          <div className="grid gap-2 sm:grid-cols-3">
                            <div className="text-xs text-slate-500 font-bold">Threat Type
                              <div className="mt-1 text-sm text-white font-bold">{result.data.urlhaus.threat || '—'}</div>
                            </div>
                            <div className="text-xs text-slate-500 font-bold">Status
                              <div className="mt-1 text-sm text-white font-bold">{result.data.urlhaus.status || '—'}</div>
                            </div>
                            <div className="text-xs text-slate-500 font-bold">Tags
                              <div className="mt-1 flex flex-wrap gap-1">
                                {(result.data.urlhaus.tags || []).map(t => (
                                  <span key={t} className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-xs text-red-400">{t}</span>
                                ))}
                                {!(result.data.urlhaus.tags?.length) && <span className="text-sm text-slate-500">—</span>}
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ── Sources Tab ───────────────────────────────── */}
                  {resultTab === 'sources' && (
                    <div className="space-y-3">
                      {sources.length === 0 ? (
                        <div className="text-center py-8 text-slate-500 text-sm">No source data returned.</div>
                      ) : (
                        sources.map((item, i) => (
                          <SourceBadge
                            key={`${item.source}-${i}`}
                            source={item.source}
                            verdict={item.verdict}
                            found={item.found}
                            detections={item.detections || item.message || item.vx_family}
                            reportUrl={item.report_url}
                          />
                        ))
                      )}
                    </div>
                  )}

                  {/* ── Evidence Tab ──────────────────────────────── */}
                  {resultTab === 'evidence' && (
                    <div className="space-y-3">
                      {riskFactors.length === 0 ? (
                        <div className="flex flex-col items-center gap-3 py-8 text-center">
                          <CheckCircle2 className="h-10 w-10 text-emerald-500/50" />
                          <div className="text-sm text-slate-500">No high-confidence risk factors identified.</div>
                        </div>
                      ) : (
                        riskFactors.map((item, i) => (
                          <div key={i} className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/50 p-3">
                            <div className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-amber-500/10 border border-amber-500/20">
                              <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                            </div>
                            <div className="text-sm text-slate-300 leading-relaxed">{item}</div>
                          </div>
                        ))
                      )}

                      {/* Suspicious patterns from URL scan */}
                      {result.type === 'url' && result.data.suspicious_patterns?.length > 0 && (
                        <div className="mt-4">
                          <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">Heuristic Signals</div>
                          <div className="space-y-2">
                            {result.data.suspicious_patterns.map((p, i) => (
                              <div key={i} className="flex items-start gap-3 rounded-xl border border-orange-500/20 bg-orange-500/5 p-3">
                                <Crosshair className="h-4 w-4 shrink-0 text-orange-400 mt-0.5" />
                                <span className="text-sm text-slate-300">{p}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ── Network Tab ───────────────────────────────── */}
                  {resultTab === 'network' && networkExposure && (
                    <div className="space-y-5">
                      <div className="grid gap-3 sm:grid-cols-3">
                        <InfoCard label="Resolved IP" value={result.data.ip} icon={Server} mono highlight />
                        <InfoCard
                          label="Open Ports"
                          value={networkExposure.ports?.length > 0 ? networkExposure.ports.join(', ') : 'None detected'}
                          icon={Wifi}
                        />
                        <InfoCard
                          label="CVEs on Host"
                          value={networkExposure.vulns?.length > 0 ? `${networkExposure.vulns.length} CVEs detected` : 'None'}
                          icon={AlertCircle}
                          highlight={networkExposure.vulns?.length > 0}
                        />
                      </div>

                      {networkExposure.ports?.length > 0 && (
                        <div>
                          <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">Open Ports</div>
                          <div className="flex flex-wrap gap-2">
                            {networkExposure.ports.map(p => (
                              <span key={p} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono text-sm font-bold text-slate-300">
                                :{p}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {networkExposure.vulns?.length > 0 && (
                        <div>
                          <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">Detected CVEs (via Shodan)</div>
                          <div className="space-y-2">
                            {networkExposure.vulns.slice(0, 10).map(cve => (
                              <div key={cve} className="flex items-center justify-between rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-2.5">
                                <span className="font-mono text-sm font-bold text-red-400">{cve}</span>
                                <a
                                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-xs text-slate-500 hover:text-cyan-300 transition flex items-center gap-1"
                                >
                                  NVD <ExternalLink className="h-3 w-3" />
                                </a>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {networkExposure.cpes?.length > 0 && (
                        <div>
                          <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">CPE Software Fingerprints</div>
                          <div className="space-y-1">
                            {networkExposure.cpes.slice(0, 8).map((cpe, i) => (
                              <div key={i} className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 font-mono text-xs text-slate-400">{cpe}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ── File Intel Tab ─────────────────────────────── */}
                  {resultTab === 'file' && fileMetadata && (
                    <div className="space-y-5">
                      <div className="grid gap-3 sm:grid-cols-2">
                        <div className="sm:col-span-2">
                          <InfoCard label="SHA-256" value={fileMetadata.sha256} icon={Hash} mono />
                        </div>
                        <InfoCard label="MD5" value={fileMetadata.md5} icon={Hash} mono />
                        <InfoCard label="Size" value={`${fileMetadata.size_kb} KB`} icon={FileText} />
                        <InfoCard label="Filename" value={fileMetadata.filename} icon={FileText} />
                        <InfoCard label="Local Verdict" value={fileMetadata.verdict} icon={Shield} />
                      </div>

                      {fileMetadata.strings_sample?.length > 0 && (
                        <div>
                          <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">
                            Extracted ASCII Strings (sample)
                          </div>
                          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                            <div className="font-mono text-xs text-slate-400 leading-6 space-y-0.5">
                              {fileMetadata.strings_sample.slice(0, 12).map((s, i) => (
                                <div key={i} className="flex gap-3">
                                  <span className="text-slate-700 select-none w-6 text-right shrink-0">{i + 1}</span>
                                  <span className="text-slate-300 break-all">{s}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}

                      {fileMetadata.suspicious_features?.length > 0 && (
                        <div>
                          <div className="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">Static Analysis Flags</div>
                          <div className="space-y-2">
                            {fileMetadata.suspicious_features.map((f, i) => (
                              <div key={i} className="flex items-center gap-3 rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3">
                                <Terminal className="h-4 w-4 shrink-0 text-amber-400" />
                                <span className="text-sm text-slate-300">{f}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* ── Full Sources Table ─────────────────────────────── */}
              {sources.length > 0 && resultTab === 'overview' && (
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 overflow-hidden">
                  <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                    <div className="flex items-center gap-2 text-sm font-bold text-white">
                      <BarChart2 className="h-4 w-4 text-cyan-300" />
                      Detection Results
                    </div>
                    <span className="text-xs text-slate-500">{positives.length} of {sources.length} flagged</span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-slate-800 bg-slate-900/60">
                          <th className="text-left px-5 py-3 text-xs font-bold uppercase tracking-widest text-slate-500">Source</th>
                          <th className="text-left px-5 py-3 text-xs font-bold uppercase tracking-widest text-slate-500">Status</th>
                          <th className="text-left px-5 py-3 text-xs font-bold uppercase tracking-widest text-slate-500 hidden md:table-cell">Details</th>
                          <th className="px-5 py-3" />
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {sources.map((item, i) => {
                          const style = SOURCE_ICONS[item.source] || { color: 'text-slate-400', bg: 'bg-slate-800' }
                          const isPos = item.found && item.verdict !== 'clean'
                          return (
                            <tr key={`${item.source}-${i}`} className="transition hover:bg-slate-900/40">
                              <td className="px-5 py-3">
                                <div className="flex items-center gap-2.5">
                                  <div className={clsx('h-7 w-7 rounded-lg flex items-center justify-center', style.bg)}>
                                    <Database className={clsx('h-3.5 w-3.5', style.color)} />
                                  </div>
                                  <span className="font-bold text-white text-sm">{item.source}</span>
                                </div>
                              </td>
                              <td className="px-5 py-3">
                                {item.found ? (
                                  <span className={clsx(
                                    'inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-bold',
                                    isPos ? 'border-red-500/40 bg-red-500/10 text-red-300' : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                                  )}>
                                    <span className={clsx('h-1.5 w-1.5 rounded-full', isPos ? 'bg-red-400' : 'bg-emerald-400')} />
                                    {item.verdict || 'found'}
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-900 px-2.5 py-0.5 text-xs font-bold text-slate-500">
                                    <span className="h-1.5 w-1.5 rounded-full bg-slate-600" />
                                    Not found
                                  </span>
                                )}
                              </td>
                              <td className="px-5 py-3 text-slate-500 text-xs hidden md:table-cell max-w-xs truncate">
                                {item.detections || item.message || item.vx_family || 'Checked'}
                              </td>
                              <td className="px-5 py-3 text-right">
                                {item.report_url && (
                                  <a href={item.report_url} target="_blank" rel="noreferrer"
                                    className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-white transition">
                                    Report <ExternalLink className="h-3 w-3" />
                                  </a>
                                )}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}
