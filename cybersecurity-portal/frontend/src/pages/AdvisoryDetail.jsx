import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, CheckCircle, XCircle, Edit, Trash2,
  MessageSquare, Send, Shield, ExternalLink, AlertTriangle,
  Tag, Clock, User, Info, Activity, Zap, FileText
} from 'lucide-react'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import ThreatGraph from './ThreatGraph'
import WarRoom from './WarRoom'
import { useAuth } from '../context/AuthContext'
import { formatDateTime, cvssColor, STATUS_CONFIG } from '../utils/helpers'
import toast from 'react-hot-toast'

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
      link.setAttribute('download', `SecureEye_Bulletin_${id}.pdf`)
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
    <div className="flex justify-center py-20">
      <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
    </div>
  )
  if (!advisory) return null

  const status = STATUS_CONFIG[advisory.status]

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Top Nav */}
      <div className="flex items-center justify-between">
        <Link to="/advisories" className="inline-flex items-center gap-2 text-slate-400 hover:text-white text-sm transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Intelligence Feed
        </Link>
        {isAnalyst && (
          <div className="flex items-center gap-2">
            <Link to={`/advisories/${id}/edit`} className="btn-ghost py-1.5 px-3 flex items-center gap-2 text-xs">
              <Edit className="w-3.5 h-3.5" /> Edit
            </Link>
            {isAdmin && (
              <button onClick={deleteAdvisory} className="btn-ghost py-1.5 px-3 text-red-400 hover:text-red-300 flex items-center gap-2 text-xs">
                <Trash2 className="w-3.5 h-3.5" /> Delete
              </button>
            )}
          </div>
        )}
      </div>

      {/* Tab Switcher */}
      <div className="flex border-b border-dark-600 gap-6">
        <button 
          onClick={() => setActiveTab('intel')}
          className={`pb-3 text-sm font-bold uppercase tracking-widest transition-all ${activeTab === 'intel' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-500 hover:text-slate-300'}`}
        >
          Intelligence Analysis
        </button>
        {isAnalyst && (
          <button 
            onClick={() => setActiveTab('warroom')}
            className={`pb-3 text-sm font-bold uppercase tracking-widest transition-all flex items-center gap-2 ${activeTab === 'warroom' ? 'text-red-400 border-b-2 border-red-400' : 'text-slate-500 hover:text-slate-300'}`}
          >
            <div className={`w-2 h-2 rounded-full ${activeTab === 'warroom' ? 'bg-red-500 threat-pulse' : 'bg-slate-600'}`} />
            Incident War Room
          </button>
        )}
      </div>

      {activeTab === 'intel' ? (
        <>
          {/* Critical Pulse Banner */}
          {advisory.is_critical_alert && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-center gap-4 animate-in fade-in slide-in-from-top-4">
              <div className="w-10 h-10 bg-red-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                <AlertTriangle className="w-6 h-6 text-red-500 threat-pulse" />
              </div>
              <div>
                <div className="text-red-400 font-bold uppercase tracking-wider text-sm">Priority 1 Critical Threat</div>
                <div className="text-red-200/70 text-sm">This advisory has been flagged for immediate response and patching.</div>
              </div>
            </div>
          )}

          {/* Primary Intelligence Card */}
          <div className="card overflow-hidden">
            {/* Header Bar */}
            <div className="p-6 border-b border-dark-600 bg-dark-700/30">
              <div className="flex items-start justify-between gap-6">
                <div className="space-y-3 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={advisory.severity} />
                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${status.bg} ${status.color} border-current opacity-80`}>{status.label}</span>
                    {advisory.is_kev && <span className="text-[10px] uppercase font-bold bg-amber-950/40 text-amber-500 border border-amber-500/40 px-2 py-0.5 rounded">CISA KEV</span>}
                    {advisory.is_zero_day && <span className="text-[10px] uppercase font-bold bg-red-950/40 text-red-500 border border-red-500/40 px-2 py-0.5 rounded">Zero-Day</span>}
                  </div>
                  <h1 className="text-2xl font-bold text-white leading-tight tracking-tight">{advisory.title}</h1>
                </div>
                {advisory.cvss_score && (
                  <div className="bg-dark-800 border border-dark-600 rounded-2xl p-4 min-w-[100px] text-center shadow-inner">
                    <div className={`text-4xl font-black ${cvssColor(advisory.cvss_score)}`}>{advisory.cvss_score.toFixed(1)}</div>
                    <div className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mt-1">CVSS V3.1</div>
                  </div>
                )}
              </div>
            </div>

            {/* Intelligence Metadata */}
            <div className="p-6 space-y-8">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="space-y-1">
                  <div className="text-[10px] uppercase font-bold text-slate-500 flex items-center gap-1.5"><Tag className="w-3 h-3" /> Sector</div>
                  <div className="text-sm text-slate-200 font-medium">{advisory.sector?.name || 'Uncategorized'}</div>
                </div>
                <div className="space-y-1">
                  <div className="text-[10px] uppercase font-bold text-slate-500 flex items-center gap-1.5"><Shield className="w-3 h-3" /> Source</div>
                  <div className="text-sm text-slate-200 font-medium capitalize">{advisory.source?.replace('_', ' ')} Intelligence</div>
                </div>
                <div className="space-y-1">
                  <div className="text-[10px] uppercase font-bold text-slate-500 flex items-center gap-1.5"><Clock className="w-3 h-3" /> Published</div>
                  <div className="text-sm text-slate-200 font-medium">{formatDateTime(advisory.published_at || advisory.created_at)}</div>
                </div>
                <div className="space-y-1">
                  <div className="text-[10px] uppercase font-bold text-slate-500 flex items-center gap-1.5"><Zap className="w-3 h-3" /> Zero-Day Status</div>
                  <div className="text-sm text-slate-200 font-medium">{advisory.zero_day_status || 'Stable'}</div>
                </div>
              </div>

              {/* Technical Identification */}
              {advisory.cve_ids?.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-[11px] uppercase tracking-widest text-blue-400 font-bold">Vulnerability Identifiers</h3>
                    <button onClick={downloadReport} className="text-[10px] uppercase font-bold text-slate-400 hover:text-white flex items-center gap-1.5 transition-colors bg-dark-800 px-3 py-1.5 rounded-lg border border-dark-600 shadow-sm">
                      <FileText className="w-3.5 h-3.5" /> Download PDF Bulletin
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {advisory.cve_ids.map(cve => (
                      <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                        className="group font-mono text-sm bg-blue-500/5 text-blue-400 border border-blue-500/20 px-3 py-1.5 rounded-lg hover:bg-blue-500/10 transition-all flex items-center gap-2">
                        {cve} <ExternalLink className="w-3 h-3 opacity-50 group-hover:opacity-100" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Technical Intelligence / Description */}
              {advisory.description && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between border-b border-dark-600 pb-2">
                    <h3 className="text-[11px] uppercase tracking-widest text-slate-400 font-bold">Technical Intelligence</h3>
                    {advisory.description.length > 500 && (
                      <button onClick={() => setIsDescExpanded(!isDescExpanded)} className="text-[10px] uppercase font-black text-blue-400 hover:text-blue-300 transition-colors">
                        {isDescExpanded ? '[-] Concise View' : '[+] Full Disclosure'}
                      </button>
                    )}
                  </div>
                  <div className={isDescExpanded ? "" : "line-clamp-6"}>
                    {advisory.description.includes('<') && advisory.description.includes('>') ? (
                      <div className="text-slate-300 leading-relaxed prose prose-invert max-w-none prose-sm" dangerouslySetInnerHTML={{ __html: advisory.description }} />
                    ) : (
                      <div className="text-slate-300 leading-relaxed whitespace-pre-line text-sm">{advisory.description}</div>
                    )}
                  </div>
                </div>
              )}

              {/* AI Summary Block */}
              {advisory.ai_summary && (
                <div className="bg-gradient-to-br from-purple-500/5 to-blue-500/5 border border-purple-500/20 rounded-2xl p-5 shadow-lg shadow-purple-950/10">
                  <h3 className="text-[11px] uppercase tracking-widest text-purple-400 font-black mb-3 flex items-center gap-2">
                    <Activity className="w-3.5 h-3.5" /> AI Analyst Insights
                  </h3>
                  <div className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">{advisory.ai_summary}</div>
                </div>
              )}

              {/* Remediation Block */}
              {advisory.mitigation && (
                <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-2xl p-5">
                  <h3 className="text-[11px] uppercase tracking-widest text-emerald-400 font-black mb-3 flex items-center gap-2">
                    <CheckCircle className="w-3.5 h-3.5" /> Remediation Strategy
                  </h3>
                  <div className="text-slate-300 text-sm leading-relaxed whitespace-pre-line">{advisory.mitigation}</div>
                </div>
              )}

              {/* Relationship Graph */}
              {ThreatGraph && <ThreatGraph advisoryId={id} />}

              {/* Action Footer */}
              {advisory.status === 'pending' && isAnalyst && (
                <div className="pt-6 border-t border-dark-600 flex items-center gap-3">
                  <button onClick={publish} className="btn-primary py-2.5 px-6 flex items-center gap-2 shadow-lg shadow-blue-900/20">
                    <CheckCircle className="w-4 h-4" /> Authorize & Publish
                  </button>
                  <button onClick={reject} className="bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 py-2.5 px-6 rounded-xl font-bold text-sm transition-all">
                    <XCircle className="w-4 h-4" /> Reject Advisory
                  </button>
                </div>
              )}

              {advisory.source_url && (
                <div className="pt-4 flex justify-end">
                  <a href={advisory.source_url} target="_blank" rel="noopener noreferrer"
                    className="text-[10px] uppercase font-black text-slate-500 hover:text-blue-400 flex items-center gap-1.5 transition-colors">
                    <Info className="w-3 h-3" /> Original OSINT Source
                  </a>
                </div>
              )}
            </div>
          </div>

          {/* Collaboration / Notes Section */}
          {isAnalyst && (
            <div className="space-y-4">
              <h2 className="text-sm font-bold text-white flex items-center gap-2 px-1">
                <MessageSquare className="w-4 h-4 text-blue-400" /> Analyst Collaboration Hub ({annotations.length})
              </h2>
              <div className="card p-5 space-y-4">
                <div className="flex gap-3">
                  <textarea
                    className="input flex-1 resize-none bg-dark-800 border-dark-600 text-sm"
                    rows={2}
                    placeholder="Share technical findings or internal evidence…"
                    value={comment}
                    onChange={e => setComment(e.target.value)}
                  />
                  <button onClick={addAnnotation} disabled={!comment.trim() || submitting}
                    className="btn-primary self-end h-10 px-5 flex items-center gap-2 text-xs">
                    <Send className="w-3.5 h-3.5" /> Submit Note
                  </button>
                </div>
                <div className="space-y-3">
                  {annotations.map(a => (
                    <div key={a.id} className="bg-dark-800/50 rounded-xl p-4 border border-dark-600/50">
                      <div className="flex items-center gap-2 text-[10px] uppercase font-bold text-slate-500 mb-2">
                        <User className="w-3 h-3" />
                        <span className="text-blue-400/80">{a.user?.full_name || a.user?.username}</span>
                        <span className="text-slate-700">|</span>
                        <Clock className="w-3 h-3" />
                        <span>{formatDateTime(a.created_at)}</span>
                      </div>
                      <p className="text-slate-300 text-sm whitespace-pre-line leading-relaxed">{a.content}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      ) : (
        <WarRoom advisoryId={id} />
      )}
    </div>
  )
}
