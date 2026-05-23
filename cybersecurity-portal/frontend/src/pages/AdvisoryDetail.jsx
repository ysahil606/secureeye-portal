import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, CheckCircle, XCircle, Edit, Trash2,
  MessageSquare, Send, Shield, ExternalLink, AlertTriangle,
  Tag, Clock, User, Info, Activity, Zap, FileText,
  Terminal, BarChart3, ChevronRight, Copy, TerminalSquare, Loader2
} from 'lucide-react'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import ThreatGraph from './ThreatGraph'
import WarRoom from './WarRoom'
import { useAuth } from '../context/AuthContext'
import { formatDateTime, cvssColor, STATUS_CONFIG, formatMarkdown, formatAIReport } from '../utils/helpers'
import toast from 'react-hot-toast'
import clsx from 'clsx'

function PlaybookModal({ playbook, onClose }) {
  const [copied, setCopied] = useState(false)
  const copyToClipboard = () => {
    navigator.clipboard.writeText(playbook)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    toast.success('Copied to clipboard')
  }

  return (
    <div className="fixed inset-0 z-[110] bg-dark-950/80 backdrop-blur-xl flex items-center justify-center p-4 animate-in fade-in duration-300">
      <div className="bg-dark-900/90 border border-emerald-500/30 rounded-3xl w-full max-w-2xl overflow-hidden shadow-[0_0_80px_rgba(16,185,129,0.15)] animate-in zoom-in-95 duration-500 relative">
        {/* Holographic Header */}
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500 via-cyan-500 to-blue-500 animate-pulse" />
        <div className="p-5 border-b border-white/5 flex items-center justify-between bg-emerald-500/5 relative z-10">
          <div className="flex items-center gap-3 text-emerald-400 font-bold uppercase tracking-widest text-xs">
            <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center animate-pulse">
              <TerminalSquare className="w-4 h-4 text-emerald-400" />
            </div>
            Neural Mitigation Playbook
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors bg-white/5 hover:bg-white/10 p-2 rounded-full"><XCircle className="w-5 h-5" /></button>
        </div>
        <div className="p-8 space-y-6 relative z-10">
          <div className="max-h-[500px] overflow-y-auto custom-scrollbar pr-2 space-y-4">
            {playbook.split('\n\n').filter(p => p.trim()).map((paragraph, idx) => {
              // Highlight steps dynamically if the AI generates "Step X:"
              const stepMatch = paragraph.match(/^(Step \d+:?)(.*)/i)
              if (stepMatch) {
                return (
                  <div key={idx} className="bg-dark-950/60 p-5 rounded-2xl border border-emerald-500/20 shadow-inner group hover:bg-dark-900/80 transition-colors">
                    <div className="flex flex-col gap-2">
                      <span className="inline-flex items-center self-start text-[10px] font-black uppercase tracking-widest text-emerald-300 bg-emerald-500/10 px-3 py-1 rounded-lg border border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.15)] group-hover:shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-shadow">
                        {stepMatch[1].replace(':', '')}
                      </span>
                      <p className="text-slate-300 text-[14px] leading-relaxed font-medium mt-1 text-justify hyphens-auto">
                        {stepMatch[2].trim()}
                      </p>
                    </div>
                  </div>
                )
              }
              return (
                <div key={idx} className="bg-dark-950/40 p-5 rounded-2xl border border-white/5 relative">
                  <div className="absolute -left-1 top-4 bottom-4 w-1 bg-emerald-500/40 rounded-full" />
                  <p className="text-slate-300 text-[14px] leading-relaxed font-medium text-justify hyphens-auto">
                    {paragraph.trim()}
                  </p>
                </div>
              )
            })}
          </div>
          <div className="flex gap-4">
            <button onClick={copyToClipboard} className="flex-1 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white shadow-[0_0_30px_rgba(16,185,129,0.2)] font-bold uppercase tracking-widest py-4 rounded-2xl flex items-center justify-center gap-3 transition-all hover:scale-[1.02]">
              {copied ? <CheckCircle className="w-5 h-5" /> : <Copy className="w-5 h-5" />}
              {copied ? 'Intel Copied!' : 'Copy Playbook'}
            </button>
            <button onClick={onClose} className="flex-1 bg-dark-800 hover:bg-dark-700 text-slate-300 hover:text-white border border-white/5 font-bold uppercase tracking-widest py-4 rounded-2xl transition-all">
              Close Terminal
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
const formatSourceDomain = (url) => {
  if (!url) return '';
  try {
    let host = new URL(url).hostname.replace('www.', '').replace(/\.[^/.]+$/, "");
    const known = {
      'thehackernews': 'Hacker News',
      'cisa': 'CISA',
      'bleepingcomputer': 'Bleeping Computer',
      'darkreading': 'Dark Reading',
      'securityweek': 'SecurityWeek',
      'threatpost': 'Threatpost',
      'github': 'GitHub',
      'reddit': 'Reddit'
    };
    return known[host] || (host.charAt(0).toUpperCase() + host.slice(1));
  } catch (e) {
    return 'External';
  }
};

export default function AdvisoryDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { isAdmin, isAnalyst } = useAuth()
  const [advisory, setAdvisory] = useState(null)
  const [annotations, setAnnotations] = useState([])
  const [comment, setComment] = useState('')
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [isDescExpanded, setIsDescExpanded] = useState(false)
  const [activeTab, setActiveTab] = useState('intel') // 'intel' or 'warroom'
  const [playbook, setPlaybook] = useState(null)
  const [generatingPlaybook, setGeneratingPlaybook] = useState(false)
  const [prediction, setPrediction] = useState(null)
  const [generatingPrediction, setGeneratingPrediction] = useState(false)

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
    try {
      const r = await api.post(`/ai/generate-playbook/${id}`)
      setPlaybook(r.data.playbook)
    } catch { toast.error('Failed to generate playbook') }
    finally { setGeneratingPlaybook(false) }
  }

  const generatePrediction = async () => {
    setGeneratingPrediction(true)
    try {
      const r = await api.post(`/ai/predict-impact/${id}`)
      setPrediction(r.data.prediction)
    } catch { toast.error('Failed to generate forecast') }
    finally { setGeneratingPrediction(false) }
  }

  // Predictive Threat Forecast is now manual to save token usage

  const publish = async () => {
    try {
      const r = await api.post(`/advisories/${id}/publish`)
      setAdvisory(r.data)
      toast.success('Advisory published')
    } catch { toast.error('Failed to publish') }
  }

  const downloadReport = async () => {
    try {
      const r = await api.get(`/reports/advisory/${id}`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([r.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `Secure_Bulletin_${id}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.remove()
    } catch { toast.error('Failed to generate report') }
  }

  const reject = async () => {
    try {
      const r = await api.post(`/advisories/${id}/reject`)
      setAdvisory(r.data)
      toast.success('Advisory rejected')
    } catch { toast.error('Failed to reject') }
  }

  const deleteAdvisory = async () => {
    if (!confirm('Delete this advisory?')) return
    try {
      await api.delete(`/advisories/${id}`)
      toast.success('Advisory deleted')
      navigate('/advisories')
    } catch { toast.error('Failed to delete') }
  }

  const addAnnotation = async () => {
    if (!comment.trim()) return
    setSubmitting(true)
    try {
      const r = await api.post(`/advisories/${id}/annotations`, { content: comment })
      setAnnotations(a => [r.data, ...a])
      setComment('')
      toast.success('Note added')
    } catch { toast.error('Failed to add note') }
    finally { setSubmitting(false) }
  }

  if (loading) return (
    <div className="flex justify-center py-32 animate-in zoom-in duration-700">
      <div className="relative flex flex-col items-center justify-center space-y-6">
        <div className="absolute inset-0 bg-blue-500/20 blur-3xl rounded-full" />
        <div className="w-24 h-24 border-[4px] border-dark-700 border-t-cyan-500 rounded-full animate-spin shadow-[0_0_30px_rgba(6,182,212,0.3)]" />
        <div className="absolute inset-0 m-auto w-16 h-16 border-[3px] border-dark-700 border-b-blue-500 rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }} />
        <h3 className="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400 tracking-[0.2em] uppercase animate-pulse mt-8">Establishing Link...</h3>
      </div>
    </div>
  )
  if (!advisory) return null

  const status = STATUS_CONFIG[advisory.status]

  return (
    <div className="max-w-5xl mx-auto space-y-8 pb-12 relative overflow-hidden">
      
      {/* --- CUSTOM CSS ANIMATIONS INJECTED HERE --- */}
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes laser-scan {
          0% { top: -10%; opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { top: 110%; opacity: 0; }
        }
        .animate-laser {
          animation: laser-scan 4s linear infinite;
        }
        @keyframes radar-pulse {
          0% { transform: scale(1); opacity: 0.6; }
          100% { transform: scale(2.5); opacity: 0; }
        }
        .animate-radar-pulse {
          animation: radar-pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
      `}} />

      {/* Top Nav - Slide In Down */}
      <div className="flex items-center justify-between animate-in slide-in-from-top-8 fade-in duration-700">
        <Link to="/advisories" className="inline-flex items-center gap-2 text-slate-500 hover:text-cyan-400 text-xs font-bold uppercase tracking-widest transition-colors bg-dark-900/50 hover:bg-dark-800 px-4 py-2 rounded-xl border border-white/5">
          <ArrowLeft className="w-4 h-4" /> Back to Advisories
        </Link>
        {isAnalyst && (
          <div className="flex items-center gap-3">
            <Link to={`/advisories/${id}/edit`} className="bg-dark-900/50 border border-white/5 hover:border-cyan-500/50 hover:bg-cyan-950/20 text-slate-400 hover:text-cyan-400 py-2 px-5 rounded-xl flex items-center gap-2 text-xs font-bold uppercase tracking-widest transition-all shadow-sm">
              <Edit className="w-3.5 h-3.5" /> Edit Advisory
            </Link>
            {isAdmin && (
              <button onClick={deleteAdvisory} className="bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 py-2 px-5 rounded-xl flex items-center gap-2 text-xs font-bold uppercase tracking-widest transition-all shadow-sm">
                <Trash2 className="w-3.5 h-3.5" /> Delete Advisory
              </button>
            )}
          </div>
        )}
      </div>

      {/* Tab Switcher - Slide In Right */}
      <div className="flex gap-6 relative animate-in slide-in-from-left-8 fade-in duration-700 delay-100 fill-mode-both">
        <button 
          onClick={() => setActiveTab('intel')}
          className={clsx(
            "pb-4 text-xs font-black uppercase tracking-[0.2em] transition-all relative z-10 px-4",
            activeTab === 'intel' ? "text-cyan-400" : "text-slate-500 hover:text-slate-300"
          )}
        >
          Tactical Intel
          {activeTab === 'intel' && (
            <>
              <div className="absolute bottom-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent shadow-[0_0_15px_rgba(34,211,238,0.8)]" />
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-4 h-[2px] bg-white shadow-[0_0_10px_white]" />
            </>
          )}
        </button>
        {isAnalyst && (
          <button 
            onClick={() => setActiveTab('warroom')}
            className={clsx(
              "pb-4 text-xs font-black uppercase tracking-[0.2em] transition-all flex items-center gap-2 relative z-10 px-4",
              activeTab === 'warroom' ? "text-orange-400" : "text-slate-500 hover:text-slate-300"
            )}
          >
            <div className={`w-2 h-2 rounded-full ${activeTab === 'warroom' ? 'bg-orange-400 animate-pulse shadow-[0_0_10px_rgba(251,146,60,1)]' : 'bg-slate-600'}`} />
            Incident War Room
            {activeTab === 'warroom' && (
              <>
                <div className="absolute bottom-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-orange-400 to-transparent shadow-[0_0_15px_rgba(251,146,60,0.8)]" />
                <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-4 h-[2px] bg-white shadow-[0_0_10px_white]" />
              </>
            )}
          </button>
        )}
        <div className="absolute bottom-0 left-0 w-full h-[1px] bg-dark-600/50" />
      </div>

      {activeTab === 'intel' ? (
        <div className="space-y-8">
          
          {/* Critical Pulse Banner - Zoom In */}
          {advisory.is_critical_alert && (
            <div className="relative overflow-hidden bg-red-950/40 border border-red-500/30 rounded-3xl p-6 flex items-center gap-6 animate-in zoom-in-95 fade-in duration-700 delay-200 fill-mode-both shadow-[0_0_40px_rgba(220,38,38,0.15)] group">
              {/* Radar Pulse Background */}
              <div className="absolute -left-10 top-1/2 -translate-y-1/2 w-48 h-48 bg-red-500/20 rounded-full blur-2xl animate-pulse" />
              
              <div className="relative w-16 h-16 bg-red-500/10 border border-red-500/30 rounded-2xl flex items-center justify-center flex-shrink-0 backdrop-blur-md">
                <AlertTriangle className="w-8 h-8 text-red-500 animate-pulse" />
                <div className="absolute inset-0 rounded-2xl border-2 border-red-500 animate-radar-pulse" />
              </div>
              <div className="relative z-10">
                <div className="text-red-400 font-black uppercase tracking-[0.2em] text-sm md:text-lg">Critical Threat Directive Issued</div>
                <div className="text-red-300/80 text-sm mt-1 font-medium">System analysis demands immediate containment and triage procedures.</div>
              </div>
            </div>
          )}

          {/* Primary Intelligence Card - Staggered Slide In */}
          <div className="overflow-hidden border border-white/10 bg-dark-900/60 backdrop-blur-3xl shadow-2xl relative rounded-3xl animate-in slide-in-from-bottom-12 fade-in duration-1000 delay-300 fill-mode-both">
            
            {/* Cinematic Scanning Laser Layer */}
            <div className="absolute left-0 w-full h-[2px] bg-cyan-400/50 shadow-[0_0_20px_rgba(34,211,238,0.8)] animate-laser z-20 pointer-events-none" />
            <div className="absolute left-0 w-full h-32 bg-gradient-to-b from-transparent to-cyan-500/5 animate-laser z-10 pointer-events-none" style={{ transform: 'translateY(-100%)' }} />

            {/* Glowing Orb Backdrop */}
            <div className="absolute -top-40 -right-40 w-96 h-96 bg-blue-500/20 rounded-full blur-[100px] pointer-events-none" />
            
            {/* Header Bar */}
            <div className="p-8 md:p-10 border-b border-white/5 bg-gradient-to-b from-white/[0.03] to-transparent relative z-30">
              <div className="flex flex-col lg:flex-row items-start justify-between gap-10">
                <div className="space-y-6 flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <SeverityBadge severity={advisory.severity} />
                    <span className={`inline-flex items-center gap-1.5 text-[10px] uppercase font-black px-3 py-1.5 rounded-lg border ${status.bg} ${status.color} ${status.border} ${status.glow || ''} tracking-[0.2em]`}>
                      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${status.dot}`} />
                      {status.label}
                    </span>
                    {advisory.is_kev && <span className="text-[10px] uppercase font-black bg-purple-500/10 text-purple-400 border border-purple-500/30 px-3 py-1.5 rounded-lg tracking-[0.2em] flex items-center gap-2 shadow-[0_0_15px_rgba(168,85,247,0.2)]"><Activity className="w-3.5 h-3.5" /> CISA KEV Identified</span>}
                    {advisory.is_zero_day && <span className="text-[10px] uppercase font-black bg-red-500/10 text-red-500 border border-red-500/30 px-3 py-1.5 rounded-lg tracking-[0.2em] flex items-center gap-2 shadow-[0_0_15px_rgba(239,68,68,0.2)]"><Zap className="w-3.5 h-3.5" /> 0-Day Exploit</span>}
                  </div>
                  <h1 className="text-4xl md:text-5xl font-black text-transparent bg-clip-text bg-gradient-to-br from-white via-blue-50 to-slate-500 leading-[1.1] tracking-tight">{advisory.title}</h1>
                </div>
                
                {/* CVSS Score Radar Ring */}
                {advisory.cvss_score && (
                  <div className="relative group">
                    <div className="absolute inset-0 rounded-full border border-blue-500/30 animate-radar-pulse pointer-events-none" />
                    <div className="flex flex-col items-center justify-center w-36 h-36 rounded-full bg-dark-900/80 border border-white/10 shadow-[inset_0_4px_20px_rgba(0,0,0,0.5)] backdrop-blur-md relative z-10 transition-transform duration-500 group-hover:scale-105">
                      <div className={`text-5xl font-black tracking-tighter ${cvssColor(advisory.cvss_score)} drop-shadow-lg`}>{advisory.cvss_score.toFixed(1)}</div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-400 font-bold mt-2">CVSS v3.1</div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Intelligence Metadata */}
            <div className="p-8 md:p-10 space-y-12 relative z-30">
              
              {/* Metadata Grid - Staggered Fade In */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                {[
                  { label: "Target Sector", value: advisory.sector?.name || 'Uncategorized', icon: Tag, color: "text-blue-400" },
                  { 
                    label: "Intel Origin", 
                    value: advisory.source_url 
                      ? formatSourceDomain(advisory.source_url)
                      : advisory.source?.replace('_', ' ') + ' Network', 
                    icon: Shield, 
                    color: "text-purple-400" 
                  },
                  { label: "Temporal Data", value: formatDateTime(advisory.published_at || advisory.created_at), icon: Clock, color: "text-emerald-400" },
                  { label: "Threat Matrix", value: advisory.zero_day_status || 'Stable Analysis', icon: Zap, color: "text-orange-400" }
                ].map((meta, i) => (
                  <div key={i} className="bg-dark-950/40 p-5 rounded-2xl border border-white/5 backdrop-blur-md animate-in slide-in-from-bottom-4 fade-in duration-700 fill-mode-both shadow-inner hover:bg-dark-900/60 transition-colors" style={{ animationDelay: `${400 + (i * 100)}ms` }}>
                    <div className={`text-[10px] uppercase font-black tracking-widest ${meta.color} flex items-center gap-2 mb-2`}>
                      <meta.icon className="w-4 h-4" /> {meta.label}
                    </div>
                    <div className="text-sm text-white font-bold capitalize">{meta.value}</div>
                  </div>
                ))}
              </div>

              {/* Technical Identification */}
              {advisory.cve_ids?.length > 0 && (
                <div className="space-y-5 animate-in slide-in-from-bottom-8 fade-in duration-700 delay-700 fill-mode-both">
                  <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-white/5 pb-4 gap-4">
                    <h3 className="text-xs uppercase tracking-[0.2em] text-cyan-400 font-black flex items-center gap-3">
                      <Terminal className="w-4 h-4" /> Global Vulnerability Index
                    </h3>
                    <div className="flex flex-wrap gap-3">
                      {advisory.source_url && (
                        <a href={advisory.source_url} target="_blank" rel="noopener noreferrer"
                          className="group relative overflow-hidden text-[10px] uppercase font-black text-white flex items-center gap-2 bg-blue-600 hover:bg-blue-500 px-5 py-2.5 rounded-xl transition-all shadow-[0_0_20px_rgba(37,99,235,0.2)] hover:shadow-[0_0_30px_rgba(37,99,235,0.4)] tracking-widest">
                          <div className="absolute inset-0 w-1/4 h-full bg-white/20 skew-x-12 -translate-x-full group-hover:animate-[shimmer_1.5s_infinite]" />
                          <ExternalLink className="w-4 h-4" /> Access Core Database
                        </a>
                      )}
                      <button onClick={downloadReport} className="text-[10px] uppercase font-black text-slate-300 hover:text-white flex items-center gap-2 transition-all bg-dark-800 hover:bg-dark-700 px-5 py-2.5 rounded-xl border border-white/10 shadow-sm tracking-widest hover:border-white/20">
                        <FileText className="w-4 h-4 text-slate-400" /> Export PDF Dossier
                      </button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    {advisory.cve_ids.map(cve => (
                      <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                        className="group font-mono text-sm font-bold bg-dark-950/80 text-cyan-400 border border-cyan-900/50 px-4 py-2 rounded-xl hover:bg-cyan-950/50 hover:border-cyan-500/50 transition-all flex items-center gap-2 shadow-inner hover:shadow-[0_0_15px_rgba(6,182,212,0.15)]">
                        {cve} <ExternalLink className="w-3.5 h-3.5 text-cyan-700 group-hover:text-cyan-400 transition-colors" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Technical Intelligence / Description */}
              {advisory.description && (
                <div className="space-y-5 animate-in slide-in-from-bottom-8 fade-in duration-700 delay-[800ms] fill-mode-both">
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <h3 className="text-xs uppercase tracking-[0.2em] text-slate-300 font-black flex items-center gap-2">
                      <FileText className="w-4 h-4" /> Executive Intel Briefing
                    </h3>
                    {advisory.description.length > 500 && (
                      <button onClick={() => setIsDescExpanded(!isDescExpanded)} className="text-[10px] uppercase font-black text-cyan-400 hover:text-cyan-300 transition-colors tracking-widest bg-cyan-500/10 px-3 py-1.5 rounded-lg">
                        {isDescExpanded ? 'Minimize Data' : 'Expand DataStream'}
                      </button>
                    )}
                  </div>
                  <div className={clsx("bg-dark-950/40 p-8 rounded-3xl border border-white/5 shadow-inner", !isDescExpanded && "line-clamp-6 relative")}>
                    {!isDescExpanded && <div className="absolute bottom-0 left-0 w-full h-16 bg-gradient-to-t from-dark-900/90 to-transparent rounded-b-3xl pointer-events-none" />}
                    {advisory.description.includes('<') && advisory.description.includes('>') ? (
                      <div className="text-slate-300 text-[15px] leading-relaxed prose prose-invert max-w-none font-medium text-justify hyphens-auto whitespace-pre-wrap" dangerouslySetInnerHTML={{ __html: formatMarkdown(advisory.description) }} />
                    ) : (
                      <div className="text-slate-300 text-[15px] leading-relaxed whitespace-pre-wrap font-medium text-justify hyphens-auto" dangerouslySetInnerHTML={{ __html: formatMarkdown(advisory.description) }} />
                    )}
                  </div>
                </div>
              )}

              {/* AI Summary Block */}
              {advisory.ai_summary && (
                <div className="bg-gradient-to-br from-purple-900/20 to-blue-900/20 border border-purple-500/20 rounded-3xl p-8 shadow-[inset_0_0_40px_rgba(168,85,247,0.05)] animate-in slide-in-from-bottom-8 fade-in duration-700 delay-[900ms] fill-mode-both">
                  <h3 className="text-[11px] uppercase tracking-[0.2em] text-purple-400 font-black mb-4 flex items-center gap-3">
                    <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center animate-pulse"><Activity className="w-3.5 h-3.5 text-purple-300" /></div>
                    Neural Analysis Engine
                  </h3>
                  <div 
                    className="text-slate-200 text-[15px] leading-relaxed whitespace-pre-wrap font-medium text-justify hyphens-auto"
                    dangerouslySetInnerHTML={{ __html: formatAIReport(advisory.ai_summary) }}
                  />
                </div>
              )}

              {/* AI Remediation & Playbook Block */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in slide-in-from-bottom-8 fade-in duration-700 delay-[1000ms] fill-mode-both">
                <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-3xl p-8 flex flex-col h-full shadow-[inset_0_0_30px_rgba(16,185,129,0.05)] hover:border-emerald-500/40 transition-colors">
                  <h3 className="text-[11px] uppercase tracking-[0.2em] text-emerald-400 font-black mb-4 flex items-center gap-3">
                    <div className="w-6 h-6 rounded-full bg-emerald-500/20 flex items-center justify-center"><CheckCircle className="w-3.5 h-3.5 text-emerald-300" /></div>
                    Tactical Remediation
                  </h3>
                  <div className="text-slate-300 text-[15px] leading-relaxed whitespace-pre-line flex-1 mb-8 font-medium">{advisory.mitigation}</div>
                  <button 
                    onClick={generatePlaybook}
                    disabled={generatingPlaybook}
                    className="group relative overflow-hidden w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-[11px] font-black uppercase tracking-widest py-4 rounded-xl flex items-center justify-center gap-3 transition-all shadow-[0_0_20px_rgba(16,185,129,0.2)] hover:shadow-[0_0_30px_rgba(16,185,129,0.4)] hover:scale-[1.02]"
                  >
                    <div className="absolute inset-0 w-1/4 h-full bg-white/20 skew-x-12 -translate-x-full group-hover:animate-[shimmer_1.5s_infinite]" />
                    {generatingPlaybook ? <Loader2 className="w-4 h-4 animate-spin" /> : <Terminal className="w-4 h-4" />}
                    Initialize Automated Playbook
                  </button>
                </div>

                <div className="bg-blue-950/20 border border-blue-500/20 rounded-3xl p-8 flex flex-col h-full shadow-[inset_0_0_30px_rgba(59,130,246,0.05)] hover:border-blue-500/40 transition-colors">
                  <h3 className="text-[11px] uppercase tracking-[0.2em] text-blue-400 font-black mb-4 flex items-center gap-3">
                    <div className="w-6 h-6 rounded-full bg-blue-500/20 flex items-center justify-center"><BarChart3 className="w-3.5 h-3.5 text-blue-300" /></div>
                    Predictive Threat Forecast
                  </h3>
                  {generatingPrediction ? (
                    <div className="flex-1 flex flex-col items-center justify-center gap-4 py-8">
                      <div className="relative">
                        <div className="absolute inset-0 bg-blue-500/20 blur-xl rounded-full" />
                        <Loader2 className="w-8 h-8 text-blue-400 animate-spin relative z-10" />
                      </div>
                      <p className="text-[10px] text-blue-400/70 font-bold uppercase tracking-widest animate-pulse">Running Neural Simulations...</p>
                    </div>
                  ) : prediction ? (
                    <div className="space-y-4">
                      {prediction.split('\n').filter(p => p.trim()).map((paragraph, idx) => (
                        <div key={idx} className="text-slate-200 text-[14px] leading-relaxed border-l-2 border-blue-500/40 pl-4 font-medium bg-gradient-to-r from-blue-500/5 to-transparent py-2 rounded-r-lg text-justify hyphens-auto">
                          {paragraph.trim()}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex-1 flex items-center justify-center">
                      <button onClick={generatePrediction} className="text-[11px] font-black uppercase tracking-widest text-blue-400 hover:text-white transition-all border border-blue-500/30 px-6 py-3 rounded-xl hover:bg-blue-500/20 hover:shadow-[0_0_20px_rgba(59,130,246,0.2)]">Execute Forecast Algorithm</button>
                    </div>
                  )}
                </div>
              </div>

              {/* Relationship Graph */}
              {ThreatGraph && <div className="animate-in slide-in-from-bottom-8 fade-in duration-700 delay-[1100ms] fill-mode-both"><ThreatGraph advisoryId={id} /></div>}

              {/* Action Footer */}
              {advisory.status === 'pending' && isAnalyst && (
                <div className="pt-10 border-t border-white/5 flex flex-wrap items-center gap-4 animate-in fade-in duration-1000 delay-[1200ms] fill-mode-both">
                  <button onClick={publish} className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-[0_0_30px_rgba(6,182,212,0.3)] font-black uppercase tracking-widest text-xs py-4 px-10 rounded-2xl flex items-center gap-3 transition-all hover:scale-105">
                    <CheckCircle className="w-5 h-5" /> Approve & Publish
                  </button>
                  <button onClick={reject} className="bg-dark-900 text-slate-400 border border-white/10 hover:border-red-500/50 hover:bg-red-950/30 hover:text-red-400 py-4 px-10 rounded-2xl font-black uppercase tracking-widest text-xs transition-all">
                    <XCircle className="w-5 h-5" /> Reject
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Collaboration / Notes Section */}
          {isAnalyst && (
            <div className="space-y-6 animate-in slide-in-from-bottom-12 fade-in duration-1000 delay-[1300ms] fill-mode-both">
              <h2 className="text-xs font-black uppercase tracking-[0.2em] text-white flex items-center gap-3 px-2">
                <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center"><MessageSquare className="w-4 h-4 text-cyan-400" /></div>
                Analyst Comments ({annotations.length})
              </h2>
              <div className="bg-dark-900/60 backdrop-blur-2xl border border-white/5 p-8 rounded-3xl shadow-xl space-y-8">
                <div className="flex flex-col md:flex-row gap-4">
                  <textarea
                    className="flex-1 resize-none bg-dark-950/50 border border-white/10 rounded-2xl text-slate-200 text-[15px] p-5 focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all font-medium"
                    rows={2}
                    placeholder="Add an internal comment or update..."
                    value={comment}
                    onChange={e => setComment(e.target.value)}
                  />
                  <button onClick={addAnnotation} disabled={!comment.trim() || submitting}
                    className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-2xl md:w-48 h-[88px] flex flex-col items-center justify-center gap-2 text-[10px] font-black uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(6,182,212,0.2)] hover:scale-105">
                    <Send className="w-5 h-5" /> Post Comment
                  </button>
                </div>
                
                {annotations.length > 0 && (
                  <div className="space-y-4 pt-4 border-t border-white/5">
                    {annotations.map(a => (
                      <div key={a.id} className="bg-dark-950/40 border border-white/5 rounded-2xl p-6 relative group hover:border-white/10 transition-colors">
                        <div className="flex items-center gap-3 text-[10px] uppercase font-black text-slate-500 mb-4 tracking-widest">
                          <div className="flex items-center gap-2 bg-dark-800 px-3 py-1.5 rounded-lg border border-white/5"><User className="w-3.5 h-3.5 text-cyan-500" /><span className="text-slate-300">{a.user?.full_name || a.user?.username}</span></div>
                          <span className="text-dark-600">|</span>
                          <div className="flex items-center gap-2"><Clock className="w-3.5 h-3.5" /><span>{formatDateTime(a.created_at)}</span></div>
                        </div>
                        <p className="text-slate-300 text-[15px] whitespace-pre-line leading-relaxed font-medium pl-2 border-l-2 border-dark-700 group-hover:border-cyan-500/50 transition-colors">{a.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        <WarRoom advisoryId={id} />
      )}

      {playbook && <PlaybookModal playbook={playbook} onClose={() => setPlaybook(null)} />}
    </div>
  )
}
