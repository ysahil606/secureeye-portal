import { useState, useRef, useEffect } from 'react'
import {
  Bot, Send, X, Loader2, Maximize2, Minimize2, Mic, MicOff, Volume2, VolumeX,
  ShieldAlert, Zap, AlertTriangle, CheckCircle, Activity, ChevronRight,
  Crosshair, Globe, ExternalLink, Eye, BarChart3, Link, Terminal, Database, User2, Hash, BrainCircuit
} from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { motion } from 'framer-motion'

// ─── Parser ────────────────────────────────────────────────────────────────────
function parseReport(text) {
  if (!text) return null
  const sections = {}

  // Extract header metadata
  const extractMeta = (key) => {
    const m = text.match(new RegExp(`\\[${key}:\\s*([^\\]]+)\\]`, 'i'))
    return m?.[1]?.trim() || null
  }
  sections.threatId    = extractMeta('THREAT_ID')    || 'UNCLASSIFIED-THREAT'
  sections.classification = extractMeta('CLASSIFICATION') || 'HIGH'
  sections.cvssScore   = extractMeta('CVSS_SCORE')   || null
  sections.cvssVector  = extractMeta('CVSS_VECTOR')  || null
  sections.tlp         = extractMeta('TLP')          || 'AMBER'
  sections.reportDate  = extractMeta('REPORT_DATE')  || new Date().toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' })

  // Named section parser
  const SECTIONS = [
    'EXECUTIVE OVERVIEW',
    'THREAT ACTOR PROFILE',
    'MITRE ATT&CK MAPPING',
    'TECHNICAL ANALYSIS',
    'INDICATORS OF COMPROMISE',
    'IMPACT ASSESSMENT',
    'REMEDIATION DIRECTIVES',
    'ANALYST VERDICT',
    'INTELLIGENCE REFERENCES',
  ]
  const escapedNames = SECTIONS.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')
  const regex = new RegExp(`^(${escapedNames})\\s*\\n([\\s\\S]*?)(?=\\n(?:${escapedNames})|====|$)`, 'gim')
  let match
  while ((match = regex.exec(text)) !== null) {
    sections[match[1].trim().toUpperCase()] = match[2].trim()
  }

  if (!sections['EXECUTIVE OVERVIEW']) return null
  return sections
}

// ─── Severity config ────────────────────────────────────────────────────────
const SEV = {
  CRITICAL: { color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: ShieldAlert,   glow: 'shadow-[0_0_30px_rgba(239,68,68,0.2)]',  bar: 'bg-red-500' },
  HIGH:     { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', icon: AlertTriangle, glow: 'shadow-[0_0_30px_rgba(249,115,22,0.15)]', bar: 'bg-orange-500' },
  MEDIUM:   { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', icon: Zap,           glow: '',                                        bar: 'bg-yellow-500' },
  LOW:      { color: 'text-emerald-400',bg: 'bg-emerald-500/10',border: 'border-emerald-500/30',icon: CheckCircle,   glow: '',                                        bar: 'bg-emerald-500' },
}

// ─── Sub-renderers ───────────────────────────────────────────────────────────
function BulletList({ text, accent = 'text-cyan-500' }) {
  const lines = text.split('\n').filter(l => l.trim() && l.trim() !== '-')
  return (
    <div className="space-y-2">
      {lines.map((line, i) => {
        const clean = line.replace(/^[-*•\d.]+\s*/, '').trim()
        if (!clean) return null
        // Sub-items (indented)
        const isSubItem = line.startsWith('  ') && !line.match(/^[-*•\d]/)
        return (
          <div key={i} className={clsx("flex items-start gap-2.5", isSubItem && "ml-5")}>
            {isSubItem
              ? <div className={`w-1 h-1 rounded-full mt-2 flex-shrink-0 ${accent.replace('text-','bg-')}`} />
              : <ChevronRight className={`w-3.5 h-3.5 mt-0.5 flex-shrink-0 ${accent}`} />
            }
            <span className="text-slate-300 text-xs leading-relaxed">{clean}</span>
          </div>
        )
      })}
    </div>
  )
}

function NumberedList({ text }) {
  const lines = text.split('\n').filter(l => l.trim())
  const palette = ['bg-red-500/20 border-red-500/30 text-red-400', 'bg-orange-500/20 border-orange-500/30 text-orange-400', 'bg-yellow-500/20 border-yellow-500/30 text-yellow-400', 'bg-blue-500/20 border-blue-500/30 text-blue-400', 'bg-purple-500/20 border-purple-500/30 text-purple-400']
  return (
    <div className="space-y-3">
      {lines.map((line, i) => {
        const clean = line.replace(/^\d+[.)]\s*\[?[A-Z-\s]+\]?\s*:?\s*/, '').replace(/^\[?[A-Z-\s]+\]?\s*-?\s*/,'').trim()
        const label = line.match(/^\d+\.\s*\[?([^\]:]+)\]?\s*[-:]/)?.[1]?.trim() || `Step ${i+1}`
        if (!clean) return null
        const cls = palette[i] || palette[4]
        return (
          <div key={i} className="flex items-start gap-3">
            <div className={`flex-shrink-0 mt-0.5 px-2 py-0.5 rounded-md border text-[9px] font-black uppercase tracking-widest ${cls}`}>{label}</div>
            <span className="text-slate-300 text-xs leading-relaxed">{clean}</span>
          </div>
        )
      })}
    </div>
  )
}

function ReferencesList({ text }) {
  const lines = text.split('\n').filter(l => l.trim() && l.trim() !== '-')
  return (
    <div className="space-y-2.5">
      {lines.map((line, i) => {
        const clean = line.replace(/^[-*]\s*/, '').trim()
        const urlMatch = clean.match(/https?:\/\/[^\s]+/)
        const label = clean.replace(/https?:\/\/[^\s]+/, '').replace(/:\s*$/, '').replace(/^[-:]\s*/, '').trim()
        const url = urlMatch?.[0]
        const isNotAvailable = clean.toLowerCase().includes('not available')

        if (isNotAvailable) {
          return (
            <div key={i} className="flex items-center gap-2.5 opacity-40">
              <Link className="w-3 h-3 text-slate-600 flex-shrink-0" />
              <span className="text-slate-600 text-xs">{label || clean}</span>
            </div>
          )
        }

        return (
          <div key={i} className="flex items-start gap-2.5">
            <ExternalLink className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              {label && <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-0.5">{label}</div>}
              {url ? (
                <a href={url} target="_blank" rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 text-xs break-all transition-colors underline-offset-2 hover:underline">
                  {url}
                </a>
              ) : (
                <span className="text-slate-400 text-xs">{clean}</span>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Section Card ───────────────────────────────────────────────────────────
function SectionCard({ icon: Icon, label, accent, children, delay = 0 }) {
  return (
    <div className="bg-dark-950/60 border border-white/5 rounded-xl p-4 animate-in slide-in-from-bottom-3 fade-in duration-500 fill-mode-both"
      style={{ animationDelay: `${delay}ms` }}>
      <div className={`text-[9px] uppercase font-black tracking-[0.2em] ${accent} mb-3 flex items-center gap-2`}>
        <Icon className="w-3.5 h-3.5" /> {label}
      </div>
      {children}
    </div>
  )
}

// ─── Full Structured Report ─────────────────────────────────────────────────
function StructuredReport({ sections }) {
  const sevKey = sections.classification?.split('/')[0]?.trim()?.toUpperCase() || 'HIGH'
  const sev = SEV[sevKey] || SEV.HIGH
  const SevIcon = sev.icon
  const cvssNum = parseFloat(sections.cvssScore)

  return (
    <div className="space-y-3 animate-in fade-in duration-500">

      {/* Classification Banner */}
      <div className={`rounded-2xl border ${sev.border} ${sev.bg} ${sev.glow} p-5 relative overflow-hidden`}>
        <div className={`absolute top-0 left-0 w-full h-[2px] ${sev.bar} opacity-60`} />
        <div className="absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl opacity-20 pointer-events-none" style={{ background: sev.bar.replace('bg-','') }} />
        <div className="flex items-start justify-between gap-3 relative z-10">
          <div className="space-y-2 flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[9px] bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-black uppercase tracking-widest">TLP:{sections.tlp}</span>
              <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold">SecureEye Intelligence</span>
              <span className="text-[9px] text-slate-600 tracking-wide">{sections.reportDate}</span>
            </div>
            <div className={`text-sm font-black uppercase tracking-wide ${sev.color} truncate`} title={sections.threatId}>{sections.threatId}</div>
            {sections.cvssVector && <div className="font-mono text-[9px] text-slate-600 truncate">{sections.cvssVector}</div>}
          </div>
          <div className="flex flex-col items-center gap-1 flex-shrink-0">
            <div className={`flex flex-col items-center px-3 py-2.5 rounded-xl border ${sev.border} ${sev.bg}`}>
              <SevIcon className={`w-5 h-5 ${sev.color}`} />
              <div className={`text-[9px] font-black uppercase tracking-widest mt-1 ${sev.color}`}>{sevKey}</div>
              {!isNaN(cvssNum) && <div className={`text-lg font-black ${sev.color} mt-0.5 leading-none`}>{cvssNum.toFixed(1)}</div>}
            </div>
          </div>
        </div>
      </div>

      {/* Executive Overview */}
      {sections['EXECUTIVE OVERVIEW'] && (
        <SectionCard icon={Activity} label="Executive Overview" accent="text-blue-400" delay={50}>
          <p className="text-slate-300 text-xs leading-relaxed">{sections['EXECUTIVE OVERVIEW']}</p>
        </SectionCard>
      )}

      {/* Threat Actor */}
      {sections['THREAT ACTOR PROFILE'] && (
        <SectionCard icon={User2} label="Threat Actor Profile" accent="text-red-400" delay={100}>
          <BulletList text={sections['THREAT ACTOR PROFILE']} accent="text-red-500" />
        </SectionCard>
      )}

      {/* MITRE ATT&CK */}
      {sections['MITRE ATT&CK MAPPING'] && (
        <SectionCard icon={Crosshair} label="MITRE ATT&CK Mapping" accent="text-purple-400" delay={150}>
          <BulletList text={sections['MITRE ATT&CK MAPPING']} accent="text-purple-500" />
        </SectionCard>
      )}

      {/* Technical Analysis */}
      {sections['TECHNICAL ANALYSIS'] && (
        <SectionCard icon={Terminal} label="Technical Analysis" accent="text-orange-400" delay={200}>
          <BulletList text={sections['TECHNICAL ANALYSIS']} accent="text-orange-500" />
        </SectionCard>
      )}

      {/* IOCs */}
      {sections['INDICATORS OF COMPROMISE'] && (
        <SectionCard icon={Hash} label="Indicators of Compromise (IOCs)" accent="text-cyan-400" delay={250}>
          <BulletList text={sections['INDICATORS OF COMPROMISE']} accent="text-cyan-500" />
        </SectionCard>
      )}

      {/* Impact Assessment */}
      {sections['IMPACT ASSESSMENT'] && (
        <SectionCard icon={BarChart3} label="Impact Assessment" accent="text-rose-400" delay={300}>
          <BulletList text={sections['IMPACT ASSESSMENT']} accent="text-rose-500" />
        </SectionCard>
      )}

      {/* Remediation */}
      {sections['REMEDIATION DIRECTIVES'] && (
        <SectionCard icon={CheckCircle} label="Remediation Directives" accent="text-emerald-400" delay={350}>
          <NumberedList text={sections['REMEDIATION DIRECTIVES']} />
        </SectionCard>
      )}

      {/* Analyst Verdict */}
      {sections['ANALYST VERDICT'] && (
        <div className="bg-gradient-to-br from-cyan-950/40 to-blue-950/40 border border-cyan-500/20 rounded-xl p-4 animate-in slide-in-from-bottom-3 fade-in duration-500 fill-mode-both" style={{ animationDelay: '400ms' }}>
          <div className="text-[9px] uppercase font-black tracking-[0.2em] text-cyan-400 mb-2 flex items-center gap-2">
            <Eye className="w-3.5 h-3.5" /> Analyst Verdict
          </div>
          <p className="text-cyan-200 text-xs leading-relaxed font-medium italic">{sections['ANALYST VERDICT']}</p>
        </div>
      )}

      {/* Intelligence References */}
      {sections['INTELLIGENCE REFERENCES'] && (
        <SectionCard icon={Globe} label="Intelligence References" accent="text-blue-400" delay={450}>
          <ReferencesList text={sections['INTELLIGENCE REFERENCES']} />
        </SectionCard>
      )}

      {/* Footer */}
      <div className="flex items-center gap-2 pt-1">
        <div className="h-px flex-1 bg-dark-800" />
        <span className="text-[9px] text-dark-500 uppercase tracking-widest font-bold flex items-center gap-1.5">
          <Database className="w-2.5 h-2.5" /> Powered by Groq · Llama-3.3-70B · SecureEye AI v12
        </span>
        <div className="h-px flex-1 bg-dark-800" />
      </div>
    </div>
  )
}

// ─── Main Component ──────────────────────────────────────────────────────────
export default function AIBotPopup() {
  const [isOpen, setIsOpen] = useState(false)
  const [isExpanded, setIsExpanded] = useState(false)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [summary, setSummary] = useState('')
  const [parsedReport, setParsedReport] = useState(null)
  const [isListening, setIsListening] = useState(false)
  const [isSpeaking, setIsSpeaking] = useState(false)
  const [loadingStep, setLoadingStep] = useState(0)
  const loadingRef = useRef(null)

  const recognitionRef = useRef(null)
  const synthRef = useRef(window.speechSynthesis)

  // Dragging logic
  const [position, setPosition] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const dragStart = useRef({ x: 0, y: 0 })
  const initialPos = useRef({ x: 0, y: 0 })
  const hasDragged = useRef(false)

  const handlePointerDown = (e) => {
    if (e.button !== 0) return // only left click
    setIsDragging(true)
    hasDragged.current = false
    dragStart.current = { x: e.clientX, y: e.clientY }
    initialPos.current = { ...position }
    e.currentTarget.setPointerCapture(e.pointerId)
  }

  const handlePointerMove = (e) => {
    if (!isDragging) return
    const dx = e.clientX - dragStart.current.x
    const dy = e.clientY - dragStart.current.y
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
      hasDragged.current = true
    }
    setPosition({
      x: initialPos.current.x + dx,
      y: initialPos.current.y + dy
    })
  }

  const handlePointerUp = (e) => {
    if (isDragging) {
      setIsDragging(false)
      e.currentTarget.releasePointerCapture(e.pointerId)
    }
  }

  const LOADING_STEPS = [
    'Connecting to Groq Neural Engine...',
    'Parsing threat intelligence data...',
    'Running MITRE ATT&CK correlation...',
    'Generating classified report...',
    'Finalizing analyst verdict...',
  ]

  useEffect(() => {
    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
      const SR = window.webkitSpeechRecognition || window.SpeechRecognition
      recognitionRef.current = new SR()
      recognitionRef.current.continuous = false
      recognitionRef.current.interimResults = false
      recognitionRef.current.lang = 'en-US'
      recognitionRef.current.onresult = (e) => { setInput(e.results[0][0].transcript); setIsListening(false) }
      recognitionRef.current.onerror = () => { setIsListening(false); toast.error('Voice recognition failed') }
      recognitionRef.current.onend = () => setIsListening(false)
    }
  }, [])

  const toggleListening = () => {
    if (isListening) { recognitionRef.current?.stop() }
    else {
      if (!recognitionRef.current) { toast.error('Speech recognition not supported'); return }
      setInput(''); recognitionRef.current.start(); setIsListening(true)
    }
  }

  const toggleSpeaking = () => {
    if (isSpeaking) { synthRef.current.cancel(); setIsSpeaking(false) }
    else if (summary) {
      const u = new SpeechSynthesisUtterance(summary)
      u.onend = () => setIsSpeaking(false)
      u.onerror = () => setIsSpeaking(false)
      setIsSpeaking(true); synthRef.current.speak(u)
    }
  }

  const handleAnalyze = async (e) => {
    if (e) e.preventDefault()
    if (!input.trim()) return
    setLoading(true); setSummary(''); setParsedReport(null)
    synthRef.current.cancel(); setIsSpeaking(false); setLoadingStep(0)

    loadingRef.current = setInterval(() => setLoadingStep(s => (s + 1) % LOADING_STEPS.length), 1800)

    try {
      const isUrl = input.trim().startsWith('http')
      const r = await api.post('/ai/analyze', isUrl ? { url: input.trim() } : { text: input.trim() })
      const raw = r.data.summary
      setSummary(raw)
      setParsedReport(parseReport(raw))
      setIsOpen(true); setIsExpanded(true)
    } catch (err) {
      toast.error(err.response?.data?.detail || 'AI Analysis failed')
    } finally {
      clearInterval(loadingRef.current)
      setLoading(false)
    }
  }

  const handleClose = () => {
    setIsOpen(false); setSummary(''); setParsedReport(null); setInput('')
    synthRef.current.cancel(); setIsSpeaking(false)
  }

  return (
    <div className="fixed bottom-20 right-4 z-50 flex max-w-[calc(100vw-2rem)] flex-col items-end sm:right-6 lg:bottom-6"
         style={{ transform: `translate(${position.x}px, ${position.y}px)`, touchAction: 'none' }}>
      
      {/* Floating Trigger */}
      {!isOpen && (
        <button 
          onClick={() => {
            if (!hasDragged.current) setIsOpen(true)
          }}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          className="relative w-16 h-16 rounded-full shadow-[0_0_40px_rgba(6,182,212,0.4)] flex items-center justify-center transition-all hover:scale-110 group border border-white/5 bg-dark-950 overflow-hidden cursor-move"
        >
          {/* Spinning Gradient Border */}
          <div className="absolute inset-[-100%] animate-spin bg-[conic-gradient(from_0deg_at_50%_50%,#3b82f6_0%,#06b6d4_25%,#a855f7_50%,#3b82f6_75%,#3b82f6_100%)] opacity-50 group-hover:opacity-100 transition-opacity duration-500" style={{ animationDuration: '3s' }} />
          
          {/* Inner Glowing Core */}
          <div className="absolute inset-[2px] rounded-full bg-gradient-to-br from-dark-900 to-dark-950 flex items-center justify-center z-10 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/20 to-purple-500/20 blur-md group-hover:blur-xl transition-all duration-700" />
            <BrainCircuit className="w-8 h-8 text-cyan-400 drop-shadow-[0_0_10px_rgba(34,211,238,0.8)] group-hover:text-white transition-colors duration-300 relative z-20" />
          </div>

          {/* Radar Ping Animation */}
          <div className="absolute inset-0 rounded-full border border-cyan-500/50 animate-ping opacity-30 z-0" style={{ animationDuration: '2s' }} />

          {/* Status Dot */}
          <div className="absolute top-0 right-0 w-4 h-4 bg-emerald-400 rounded-full border-[2.5px] border-dark-950 flex items-center justify-center z-30 shadow-[0_0_15px_rgba(52,211,153,0.8)]">
            <div className="w-1.5 h-1.5 bg-white rounded-full animate-pulse" />
          </div>

          <span className="absolute right-20 bg-dark-900/90 backdrop-blur-md text-cyan-100 text-[11px] uppercase tracking-widest px-4 py-2.5 rounded-xl opacity-0 group-hover:opacity-100 transition-all border border-cyan-500/30 shadow-[0_0_20px_rgba(6,182,212,0.2)] font-black whitespace-nowrap z-50 pointer-events-none">
            Engage AI Copilot
          </span>
        </button>
      )}

      {/* Main Window */}
      {isOpen && (
        <div className={clsx(
          "border border-white/10 rounded-2xl shadow-2xl transition-all duration-500 flex flex-col overflow-hidden max-w-[calc(100vw-2rem)]",
          "bg-dark-900/95 backdrop-blur-3xl shadow-[0_20px_60px_rgba(0,0,0,0.5)]",
          isExpanded ? 'h-[min(780px,calc(100vh-2rem))] w-[min(560px,calc(100vw-2rem))]' : 'h-96 w-[min(22rem,calc(100vw-2rem))]'
        )}>
          {/* Header */}
          <motion.div 
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            className="px-4 py-3 flex items-center justify-between border-b border-cyan-500/20 bg-gradient-to-r from-[#030a16] via-blue-950/40 to-[#030a16] relative flex-shrink-0 cursor-move select-none overflow-hidden"
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
          >
            {/* Animated scanning line in header */}
            <motion.div 
              className="absolute top-0 left-0 w-[200%] h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent pointer-events-none opacity-50"
              animate={{ x: ['-100%', '100%'] }}
              transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
            />
            <div className="flex items-center gap-3 relative z-10">
              <motion.div 
                className="relative w-9 h-9 bg-gradient-to-br from-cyan-900/40 to-blue-900/40 border border-cyan-500/30 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)] pointer-events-none"
                whileHover={{ scale: 1.1, rotate: 5 }}
              >
                <motion.div 
                  className="absolute inset-0 border border-cyan-400/50 rounded-xl"
                  animate={{ rotate: [0, 90, 180, 270, 360] }}
                  transition={{ duration: 10, repeat: Infinity, ease: 'linear' }}
                />
                <Bot className="w-5 h-5 text-cyan-400" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-400 rounded-full border-[2px] border-dark-900 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse" />
              </motion.div>
              <div>
                <motion.div 
                  className="font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 via-blue-400 to-purple-400 text-sm tracking-widest uppercase"
                  animate={{ backgroundPosition: ['0% 50%', '100% 50%', '0% 50%'] }}
                  transition={{ duration: 5, repeat: Infinity, ease: 'linear' }}
                  style={{ backgroundSize: '200% 200%' }}
                >
                  SecureEye AI
                </motion.div>
                <div className="text-[9px] text-emerald-400 uppercase tracking-[0.2em] font-bold flex items-center gap-1.5 opacity-80">
                  <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-ping" />
                  Groq · Llama-3.3-70B · Online
                </div>
              </div>
            </div>
            <div 
              className="flex items-center gap-1 relative z-10"
              onPointerDown={(e) => e.stopPropagation()}
            >
              {summary && (
                <button onClick={toggleSpeaking} title={isSpeaking ? 'Stop' : 'Read Aloud'}
                  className={clsx("p-1.5 rounded-lg transition-colors", isSpeaking ? "text-cyan-400 bg-cyan-500/10 shadow-[0_0_10px_rgba(6,182,212,0.2)]" : "text-cyan-700 hover:text-cyan-400 hover:bg-cyan-500/10")}>
                  {isSpeaking ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
                </button>
              )}
              <button onClick={() => setIsExpanded(!isExpanded)} className="p-1.5 rounded-lg text-cyan-700 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors">
                {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
              </button>
              <button onClick={handleClose} className="p-1.5 rounded-lg text-cyan-700 hover:text-red-400 hover:bg-red-500/10 transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
          </motion.div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
            {/* Welcome State */}
            {!summary && !loading && (
              <div className="text-center py-8 space-y-5 animate-in fade-in duration-500">
                <div className="relative w-16 h-16 mx-auto">
                  <div className="absolute inset-0 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-2xl blur-xl animate-pulse" />
                  <div className="relative w-16 h-16 bg-gradient-to-br from-blue-600/20 to-cyan-600/20 border border-blue-500/20 rounded-2xl flex items-center justify-center">
                    <ShieldAlert className="w-8 h-8 text-blue-400" />
                  </div>
                </div>
                <div className="space-y-2 px-4">
                  <p className="text-white text-sm font-black tracking-wide">Threat Intelligence AI</p>
                  <p className="text-slate-500 text-xs leading-relaxed">Generates a classified 9-section intelligence brief with MITRE ATT&CK mapping, IOCs, and verified references.</p>
                </div>
                <div className="grid grid-cols-3 gap-2 px-2">
                  {[
                    { label: 'CVE Analysis', ex: 'CVE-2024-1234' },
                    { label: 'URL Analysis', ex: 'https://example.com' },
                    { label: 'Threat Query', ex: 'LockBit ransomware' },
                  ].map(({ label, ex }) => (
                    <button key={ex} onClick={() => setInput(ex)}
                      className="bg-dark-800 hover:bg-dark-700 border border-dark-600 hover:border-blue-500/30 rounded-xl p-2.5 transition-all text-left group">
                      <div className="text-[9px] text-slate-500 uppercase tracking-widest font-bold mb-1 group-hover:text-blue-400 transition-colors">{label}</div>
                      <div className="text-[10px] text-slate-400 font-mono truncate">{ex}</div>
                    </button>
                  ))}
                </div>
                <div className="px-4">
                  <div className="text-[9px] text-dark-600 uppercase tracking-widest font-bold">Powered by</div>
                  <div className="flex items-center justify-center gap-3 mt-1">
                    {['Groq', 'Llama-3.3-70B', 'MITRE ATT&CK', 'NVD', 'CISA'].map(tag => (
                      <span key={tag} className="text-[9px] text-dark-500 bg-dark-800 border border-dark-700 px-1.5 py-0.5 rounded">{tag}</span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Loading State */}
            {loading && (
              <div className="flex flex-col items-center justify-center py-12 gap-6">
                <div className="relative w-20 h-20">
                  <div className="absolute inset-0 bg-blue-500/20 blur-2xl rounded-full animate-pulse" />
                  <div className="w-20 h-20 border-[3px] border-dark-700 border-t-cyan-500 rounded-full animate-spin relative z-10" />
                  <div className="absolute inset-0 m-auto w-12 h-12 border-[2px] border-dark-700 border-b-blue-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.2s' }} />
                  <div className="absolute inset-0 m-auto w-5 h-5 bg-gradient-to-br from-blue-600 to-cyan-600 rounded-full flex items-center justify-center z-20">
                    <Bot className="w-3 h-3 text-white" />
                  </div>
                </div>
                <div className="text-center space-y-2">
                  <div className="text-xs font-black text-cyan-400 uppercase tracking-widest animate-pulse">{LOADING_STEPS[loadingStep]}</div>
                  <div className="text-[10px] text-dark-500">Generating full 9-section classified brief...</div>
                </div>
                <div className="flex gap-1.5">
                  {LOADING_STEPS.map((_, i) => (
                    <div key={i} className={clsx("w-6 h-1 rounded-full transition-all duration-500", i <= loadingStep ? 'bg-cyan-500' : 'bg-dark-700')} />
                  ))}
                </div>
              </div>
            )}

            {/* Report */}
            {summary && (
              parsedReport
                ? <StructuredReport sections={parsedReport} />
                : (
                  <div className="bg-dark-950/60 border border-blue-500/20 rounded-xl p-4 animate-in fade-in duration-500">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
                      <span className="text-[10px] uppercase tracking-widest text-blue-400 font-bold">Intelligence Report</span>
                    </div>
                    <pre className="text-slate-300 text-xs leading-relaxed whitespace-pre-wrap font-sans">{summary}</pre>
                  </div>
                )
            )}
          </div>

          {/* Input Footer */}
          <form onSubmit={handleAnalyze} className="p-4 border-t border-white/5 bg-dark-950/50 flex-shrink-0">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  className="w-full bg-dark-800/80 border border-white/10 rounded-xl pl-4 pr-10 py-2.5 text-sm text-white placeholder-dark-400 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                  placeholder={isListening ? 'Listening...' : 'CVE ID, URL, malware name...'}
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  disabled={loading}
                />
                <button type="button" onClick={toggleListening}
                  className={clsx("absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded-lg transition-colors",
                    isListening ? "text-red-500 animate-pulse bg-red-500/10" : "text-slate-500 hover:text-blue-400")}>
                  {isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
                </button>
              </div>
              <button type="submit" disabled={loading || !input.trim()}
                className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white p-2.5 rounded-xl disabled:opacity-30 transition-all hover:scale-105 shadow-lg shadow-blue-900/30 flex-shrink-0">
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
