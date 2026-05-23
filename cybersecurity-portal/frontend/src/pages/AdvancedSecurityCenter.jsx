import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity, AlertTriangle, Bot, ClipboardList, ExternalLink, Eye,
  FileText, Globe2, ListChecks, Network, Radar, Search, ShieldCheck,
  Siren, Sparkles, Target, Zap, Server, ChevronRight
} from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../services/api'
import { formatDateTime, cvssColor, formatAIReport } from '../utils/helpers'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remarkGfm'
const riskColors = {
  Critical: 'text-red-300 border-red-700/40 bg-red-950/30',
  High: 'text-orange-300 border-orange-700/40 bg-orange-950/30',
  Medium: 'text-yellow-300 border-yellow-700/40 bg-yellow-950/30',
  Low: 'text-emerald-300 border-emerald-700/40 bg-emerald-950/30',
  Watch: 'text-blue-300 border-blue-700/40 bg-blue-950/30',
  Elevated: 'text-orange-300 border-orange-700/40 bg-orange-950/30',
}

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.1 }
  }
}

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 300, damping: 24 } }
}

function Panel({ title, icon: Icon, children, action, className = "" }) {
  return (
    <motion.section 
      variants={itemVariants}
      className={`relative overflow-hidden bg-[#0a0f1c]/80 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 shadow-2xl group ${className}`}
    >
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-cyan-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none" />
      <div className="absolute -inset-px bg-gradient-to-r from-cyan-500/20 via-blue-500/20 to-purple-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-700 blur-sm pointer-events-none" />
      
      <div className="relative z-10 flex items-center justify-between gap-3 mb-6">
        <h2 className="text-base font-bold text-white flex items-center gap-3 tracking-wide">
          <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20 group-hover:border-blue-400/50 group-hover:shadow-[0_0_15px_rgba(59,130,246,0.3)] transition-all">
            <Icon className="w-4 h-4 text-cyan-400" />
          </div>
          {title}
        </h2>
        {action}
      </div>
      <div className="relative z-10">
        {children}
      </div>
    </motion.section>
  )
}

function RiskBadge({ value }) {
  return (
    <span className={`px-2.5 py-1 rounded-full border text-xs font-bold tracking-wider uppercase shadow-inner ${riskColors[value] || riskColors.Watch}`}>
      {value}
    </span>
  )
}

function AdvisoryLink({ item }) {
  return (
    <Link to={`/advisories/${item.id}`} className="block p-4 rounded-xl bg-slate-900/50 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/80 transition-all group">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm text-slate-200 font-semibold truncate group-hover:text-cyan-400 transition-colors">{item.title}</div>
          <div className="text-[11px] font-mono text-slate-500 mt-2 flex items-center gap-2">
            {item.cvss_score ? <span className="text-orange-400">CVSS {item.cvss_score}</span> : 'NO CVSS'} 
            {item.published_at ? <span className="text-slate-600">|</span> : ''}
            {item.published_at ? formatDateTime(item.published_at) : ''}
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
  const [watchLoading, setWatchLoading] = useState(false)

  const [leakKeyword, setLeakKeyword] = useState('')
  const [leakResult, setLeakResult] = useState(null)
  const [leakLoading, setLeakLoading] = useState(false)

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
    setWatchLoading(true)
    try {
      const r = await api.post('/advanced/watchlist/preview', { keywords })
      setWatchlist(r.data)
    } catch {
      toast.error('Watchlist preview failed')
    } finally {
      setWatchLoading(false)
    }
  }

  const runLeakCheck = async (e) => {
    e.preventDefault()
    if (!leakKeyword.trim()) return
    setLeakLoading(true)
    try {
      const r = await api.post('/advanced/leak-check', { keyword: leakKeyword })
      setLeakResult(r.data)
    } catch {
      toast.error('Leak monitor failed')
    } finally {
      setLeakLoading(false)
    }
  }

  const stats = useMemo(() => ([
    { label: 'Total Advisories', value: overview?.total_advisories ?? 0, icon: FileText },
    { label: 'Critical Threats', value: overview?.critical ?? 0, icon: AlertTriangle, color: 'text-red-400' },
    { label: 'KEV Exploits', value: overview?.kev ?? 0, icon: Siren, color: 'text-orange-400' },
    { label: 'Tracked IOCs', value: overview?.ioc_total ?? 0, icon: Network },
  ]), [overview])

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-slate-800 rounded-full"></div>
          <div className="w-16 h-16 border-4 border-cyan-500 rounded-full border-t-transparent animate-spin absolute inset-0"></div>
          <ShieldCheck className="w-6 h-6 text-cyan-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-pulse" />
        </div>
        <p className="text-cyan-500 font-mono text-sm tracking-widest uppercase animate-pulse">Initializing Security Center...</p>
      </div>
    )
  }

  return (
    <motion.div 
      initial="hidden" 
      animate="show" 
      variants={containerVariants} 
      className="space-y-8 pb-10"
    >
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-800 pb-6 relative">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-[100px] pointer-events-none -z-10" />
        <div>
          <h1 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 flex items-center gap-3 tracking-tight">
            <Sparkles className="w-8 h-8 text-cyan-400" /> Advanced Security Center
          </h1>
          <p className="text-sm font-medium text-slate-400 mt-2 tracking-wide">AI triage, attack surface checks, patch priority, watchlists, and executive risk.</p>
        </div>
        <div className="flex items-center gap-3 bg-slate-900/50 p-2 rounded-xl border border-slate-800">
          <span className="text-[10px] uppercase tracking-widest text-slate-500 font-bold px-2">Global Posture</span>
          <RiskBadge value={overview?.risk_level || 'Watch'} />
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map(({ label, value, icon: Icon, color = "text-cyan-400" }) => (
          <motion.div key={label} variants={itemVariants} className="relative group overflow-hidden bg-slate-900/40 backdrop-blur-md border border-slate-800 hover:border-cyan-500/30 rounded-2xl p-5 transition-all">
            <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
            <div className="flex items-start justify-between relative z-10">
              <div>
                <div className="text-[11px] font-bold uppercase tracking-widest text-slate-500">{label}</div>
                <div className="text-3xl font-black text-white mt-2 tracking-tight">{value.toLocaleString()}</div>
              </div>
              <div className={`p-3 bg-slate-950/50 rounded-xl border border-slate-800 ${color} group-hover:scale-110 transition-transform duration-300`}>
                <Icon className="w-5 h-5" />
              </div>
            </div>
          </motion.div>
        ))}
      </div>



      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Panel title="AI Threat Analyst" icon={Bot}>
          <form onSubmit={runAnalyst} className="space-y-4">
            <div className="relative group">
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2 h-[2px] w-0 bg-cyan-400 group-focus-within:w-full transition-all duration-500 ease-out z-20 shadow-[0_0_10px_rgba(34,211,238,0.8)]" />
              <textarea
                className="w-full bg-[#050810] border border-slate-700/80 rounded-xl p-4 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none min-h-[120px] font-mono resize-none relative z-10"
                placeholder="Paste CVE, IOC, URL, hash, IP, or advisory text for AI synthesis..."
                value={analystInput}
                onChange={e => setAnalystInput(e.target.value)}
                disabled={analystLoading}
              />
              {analystLoading && (
                <div className="absolute inset-0 z-30 bg-[#050810]/50 flex items-center justify-center backdrop-blur-[2px] rounded-xl border border-cyan-500/30">
                  <div className="flex flex-col items-center gap-2">
                    <Bot className="w-6 h-6 text-cyan-400 animate-bounce" />
                    <span className="text-[10px] uppercase tracking-widest text-cyan-400 font-bold animate-pulse">Processing Intel...</span>
                  </div>
                </div>
              )}
            </div>
            <button className="px-5 py-3 w-full bg-slate-800 hover:bg-cyan-900/80 hover:text-cyan-300 hover:border-cyan-700/50 text-slate-300 border border-slate-700 text-xs font-bold uppercase tracking-widest rounded-xl transition-all flex items-center justify-center gap-2" disabled={analystLoading}>
              <Search className="w-4 h-4" /> {analystLoading ? 'Synthesizing...' : 'Run Triage Analysis'}
            </button>
          </form>
          
          <AnimatePresence>
            {analystResult && !analystLoading && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="mt-6 space-y-4 pt-6 border-t border-slate-800/80"
              >
                <div className="flex items-center gap-3 p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                  <RiskBadge value={analystResult.verdict} />
                  <div className="w-px h-4 bg-slate-700"></div>
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2">
                    <Target className="w-3.5 h-3.5" /> Confidence: <span className="text-slate-300">{analystResult.confidence}</span>
                  </span>
                </div>
                <div className="p-4 bg-gradient-to-br from-[#0d0a1f] to-[#030a16] border border-purple-500/20 rounded-xl text-[13px] leading-[1.7] text-gray-200 shadow-inner overflow-x-auto">
                  <ReactMarkdown
                    remarkPlugins={[remarkGfm]}
                    components={{
                      h1: ({node, ...props}) => <h1 style={{fontSize:'1.2em', fontWeight:700, color:'#c4b5fd', marginBottom:'0.5em', marginTop:'0.75em', borderBottom:'1px solid rgba(139,92,246,0.2)', paddingBottom:'0.3em'}} {...props} />,
                      h2: ({node, ...props}) => <h2 style={{fontSize:'1.05em', fontWeight:700, color:'#a78bfa', marginBottom:'0.4em', marginTop:'0.75em'}} {...props} />,
                      h3: ({node, ...props}) => <h3 style={{fontSize:'0.95em', fontWeight:600, color:'#8b5cf6', marginBottom:'0.3em', marginTop:'0.5em'}} {...props} />,
                      p: ({node, ...props}) => <p style={{marginBottom:'0.6em', color:'#d1d5db', lineHeight:'1.7'}} {...props} />,
                      ul: ({node, ...props}) => <ul style={{paddingLeft:'1.2em', marginBottom:'0.5em', listStyleType:'disc'}} {...props} />,
                      ol: ({node, ...props}) => <ol style={{paddingLeft:'1.2em', marginBottom:'0.5em', listStyleType:'decimal'}} {...props} />,
                      li: ({node, ...props}) => <li style={{marginBottom:'0.2em', color:'#d1d5db'}} {...props} />,
                      strong: ({node, ...props}) => <strong style={{color:'#ffffff', fontWeight:600}} {...props} />,
                      code: ({node, inline, ...props}) => inline
                        ? <code style={{background:'#00050b', color:'#34d399', padding:'0.1em 0.4em', borderRadius:'4px', fontFamily:'monospace', fontSize:'0.85em'}} {...props} />
                        : <code style={{display:'block', background:'#00050b', color:'#93c5fd', padding:'1em', borderRadius:'8px', fontSize:'0.8em', overflowX:'auto', fontFamily:'monospace', marginBottom:'0.5em'}} {...props} />,
                      pre: ({node, ...props}) => <pre style={{background:'transparent', margin:0, padding:0}} {...props} />,
                      table: ({node, ...props}) => <table style={{width:'100%', borderCollapse:'collapse', marginBottom:'0.5em', fontSize:'0.85em'}} {...props} />,
                      th: ({node, ...props}) => <th style={{border:'1px solid rgba(139,92,246,0.3)', padding:'0.4em 0.6em', background:'rgba(88,28,135,0.3)', color:'#e9d5ff', textAlign:'left'}} {...props} />,
                      td: ({node, ...props}) => <td style={{border:'1px solid rgba(139,92,246,0.15)', padding:'0.4em 0.6em', color:'#d1d5db'}} {...props} />,
                      blockquote: ({node, ...props}) => <blockquote style={{borderLeft:'3px solid rgba(139,92,246,0.5)', paddingLeft:'0.8em', color:'#9ca3af', fontStyle:'italic', margin:'0.5em 0'}} {...props} />,
                      a: ({node, ...props}) => <a style={{color:'#22d3ee', textDecoration:'underline'}} target="_blank" rel="noopener noreferrer" {...props} />,
                    }}
                  >
                    {analystResult.summary}
                  </ReactMarkdown>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {analystResult.recommended_actions.map((action, idx) => (
                    <div key={idx} className="text-xs font-medium text-slate-300 bg-[#050810] border border-slate-800/80 rounded-lg p-3 flex items-start gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1 flex-shrink-0" />
                      {action}
                    </div>
                  ))}
                </div>
                {analystResult.matches?.length > 0 && (
                  <div className="space-y-3 pt-2">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Correlated Advisories</p>
                    {analystResult.matches.map(item => <AdvisoryLink key={item.id} item={item} />)}
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </Panel>

        <Panel title="Attack Surface Monitor" icon={Globe2}>
          <form onSubmit={runSurface} className="space-y-4">
            <div className="relative group">
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2 h-[2px] w-0 bg-purple-400 group-focus-within:w-full transition-all duration-500 ease-out z-20 shadow-[0_0_10px_rgba(192,132,252,0.8)]" />
              <div className="flex items-center bg-[#050810] border border-slate-700/80 rounded-xl relative overflow-hidden z-10">
                <div className="px-4 text-slate-500">
                  <Server className="w-4 h-4" />
                </div>
                <input 
                  className="w-full bg-transparent py-4 pr-4 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none font-mono" 
                  placeholder="Scan infrastructure (e.g., example.com)" 
                  value={domain} 
                  onChange={e => setDomain(e.target.value)} 
                  disabled={surfaceLoading}
                />
              </div>
              {surfaceLoading && (
                <div className="absolute inset-0 z-30 pointer-events-none rounded-xl overflow-hidden border border-purple-500/30">
                  <div className="absolute inset-0 bg-purple-500/10 animate-pulse"></div>
                  <div className="h-full w-2 bg-purple-400 blur-sm absolute left-0 animate-[scanline_1s_linear_infinite_alternate]" style={{ transform: 'skewX(-20deg)' }}></div>
                </div>
              )}
            </div>
            <button className="px-5 py-3 w-full bg-slate-800 hover:bg-purple-900/80 hover:text-purple-300 hover:border-purple-700/50 text-slate-300 border border-slate-700 text-xs font-bold uppercase tracking-widest rounded-xl transition-all flex items-center justify-center gap-2" disabled={surfaceLoading}>
              <Radar className="w-4 h-4" /> {surfaceLoading ? 'Mapping Perimeter...' : 'Initiate Scan'}
            </button>
          </form>
          
          <AnimatePresence>
            {surface && !surfaceLoading && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="mt-6 space-y-4 pt-6 border-t border-slate-800/80"
              >
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                    <div className="text-[10px] uppercase font-bold tracking-widest text-slate-500 mb-1">Resolved IP</div>
                    <div className="text-white font-mono text-sm break-all">{surface.ip || 'Unresolved'}</div>
                  </div>
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                    <div className="text-[10px] uppercase font-bold tracking-widest text-slate-500 mb-1">Open Ports</div>
                    <div className="text-white font-mono text-sm">{surface.open_ports?.length ? surface.open_ports.join(', ') : 'None detected'}</div>
                  </div>
                </div>
                
                {surface.days_to_ssl_expiry !== null && (
                  <div className="flex items-center justify-between bg-[#050810] border border-slate-800 rounded-xl p-3 px-4">
                    <span className="text-xs font-bold text-slate-400 tracking-wide uppercase">SSL Certificate</span>
                    <span className={`text-xs font-mono font-bold ${surface.days_to_ssl_expiry < 30 ? 'text-orange-400' : 'text-emerald-400'}`}>
                      Expires in {surface.days_to_ssl_expiry} days
                    </span>
                  </div>
                )}
                
                <div className="space-y-2 pt-2">
                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Detected Risks & Anomalies</p>
                  {(surface.risks || []).length > 0 ? (
                    surface.risks.map((risk, idx) => (
                      <div key={idx} className="flex items-start gap-3 p-3 bg-red-950/10 border border-red-900/20 rounded-xl">
                        <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
                        <span className="text-sm text-slate-300 font-medium leading-relaxed">{risk}</span>
                        <div className="ml-auto">
                          <RiskBadge value={risk.toLowerCase().includes('not') ? 'High' : 'Watch'} />
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="flex items-center gap-3 p-3 bg-emerald-950/10 border border-emerald-900/20 rounded-xl">
                      <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      <span className="text-sm text-slate-300 font-medium">No critical risks detected on perimeter.</span>
                      <div className="ml-auto"><RiskBadge value="Low" /></div>
                    </div>
                  )}
                </div>

                {surface.subdomains_checked?.length > 0 && (
                  <div className="space-y-2 pt-2">
                    <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center justify-between">
                      Discovered Assets <span className="bg-slate-800 text-slate-400 px-2 py-0.5 rounded">{surface.subdomains_checked.length}</span>
                    </p>
                    <div className="max-h-40 overflow-y-auto custom-scrollbar space-y-2 pr-1">
                      {surface.subdomains_checked.map((item, idx) => (
                        <div key={idx} className="flex items-center justify-between text-xs font-mono bg-[#050810] border border-slate-800/80 rounded-lg p-3">
                          <span className="text-slate-300 truncate mr-2">{item.host}</span>
                          <span className={`px-2 py-0.5 rounded ${item.type === 'production' ? 'bg-blue-900/30 text-blue-400' : 'bg-slate-800 text-slate-400'}`}>{item.type}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {surface.ai_summary && (
                  <div className="pt-6 mt-4 border-t border-slate-800/80">
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                      <Bot className="w-4 h-4 text-cyan-400" /> Neural Analysis
                    </h3>
                    <div className="p-4 bg-gradient-to-br from-[#0d0a1f] to-[#030a16] border border-purple-500/20 rounded-xl text-[13px] leading-[1.7] text-gray-200 shadow-inner overflow-x-auto">
                      <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={{
                          h1: ({node, ...props}) => <h1 style={{fontSize:'1.2em', fontWeight:700, color:'#c4b5fd', marginBottom:'0.5em', marginTop:'0.75em', borderBottom:'1px solid rgba(139,92,246,0.2)', paddingBottom:'0.3em'}} {...props} />,
                          h2: ({node, ...props}) => <h2 style={{fontSize:'1.05em', fontWeight:700, color:'#a78bfa', marginBottom:'0.4em', marginTop:'0.75em'}} {...props} />,
                          h3: ({node, ...props}) => <h3 style={{fontSize:'0.95em', fontWeight:600, color:'#8b5cf6', marginBottom:'0.3em', marginTop:'0.5em'}} {...props} />,
                          p: ({node, ...props}) => <p style={{marginBottom:'0.6em', color:'#d1d5db', lineHeight:'1.7'}} {...props} />,
                          ul: ({node, ...props}) => <ul style={{paddingLeft:'1.2em', marginBottom:'0.5em', listStyleType:'disc'}} {...props} />,
                          ol: ({node, ...props}) => <ol style={{paddingLeft:'1.2em', marginBottom:'0.5em', listStyleType:'decimal'}} {...props} />,
                          li: ({node, ...props}) => <li style={{marginBottom:'0.2em', color:'#d1d5db'}} {...props} />,
                          strong: ({node, ...props}) => <strong style={{color:'#ffffff', fontWeight:600}} {...props} />,
                          code: ({node, inline, ...props}) => inline
                            ? <code style={{background:'#00050b', color:'#34d399', padding:'0.1em 0.4em', borderRadius:'4px', fontFamily:'monospace', fontSize:'0.85em'}} {...props} />
                            : <code style={{display:'block', background:'#00050b', color:'#93c5fd', padding:'1em', borderRadius:'8px', fontSize:'0.8em', overflowX:'auto', fontFamily:'monospace', marginBottom:'0.5em'}} {...props} />,
                          pre: ({node, ...props}) => <pre style={{background:'transparent', margin:0, padding:0}} {...props} />,
                          table: ({node, ...props}) => <table style={{width:'100%', borderCollapse:'collapse', marginBottom:'0.5em', fontSize:'0.85em'}} {...props} />,
                          th: ({node, ...props}) => <th style={{border:'1px solid rgba(139,92,246,0.3)', padding:'0.4em 0.6em', background:'rgba(88,28,135,0.3)', color:'#e9d5ff', textAlign:'left'}} {...props} />,
                          td: ({node, ...props}) => <td style={{border:'1px solid rgba(139,92,246,0.15)', padding:'0.4em 0.6em', color:'#d1d5db'}} {...props} />,
                          blockquote: ({node, ...props}) => <blockquote style={{borderLeft:'3px solid rgba(139,92,246,0.5)', paddingLeft:'0.8em', color:'#9ca3af', fontStyle:'italic', margin:'0.5em 0'}} {...props} />,
                          a: ({node, ...props}) => <a style={{color:'#22d3ee', textDecoration:'underline'}} target="_blank" rel="noopener noreferrer" {...props} />,
                        }}
                      >
                        {surface.ai_summary}
                      </ReactMarkdown>
                    </div>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </Panel>
      </div>


      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">


        <Panel title="Connected Architecture" icon={ClipboardList}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { to: '/iocs', label: 'IOC Management', icon: Network, color: 'text-blue-400' },
              { to: '/timeline', label: 'Threat Timeline', icon: Activity, color: 'text-cyan-400' },
              { to: '/zero-days', label: 'Zero-Day Tracker', icon: AlertTriangle, color: 'text-red-400' },
              { to: '/search', label: 'Smart Intelligence Search', icon: Search, color: 'text-emerald-400' },
              { to: '/admin/feeds', label: 'Real-Time Feeds', icon: Radar, color: 'text-purple-400' },
              { to: '/advisories', label: 'Advisory War Rooms', icon: FileText, color: 'text-orange-400' },
            ].map(({ to, label, icon: Icon, color }) => (
              <Link key={to} to={to} className="flex items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/40 border border-slate-800 hover:border-slate-500/50 hover:bg-slate-800/60 transition-all group">
                <span className="flex items-center gap-3 text-sm font-medium text-slate-200">
                  <div className="p-1.5 bg-[#050810] rounded-lg border border-slate-800 group-hover:scale-110 transition-transform">
                    <Icon className={`w-4 h-4 ${color}`} />
                  </div>
                  {label}
                </span>
                <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-400 transition-colors" />
              </Link>
            ))}
          </div>
        </Panel>
      </div>
    </motion.div>
  )
}
