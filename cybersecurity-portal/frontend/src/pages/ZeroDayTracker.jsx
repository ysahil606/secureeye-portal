import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bug, ExternalLink, ShieldAlert, Target, Shield, Clock, ChevronRight, Search, X, Sparkles, Loader2, AlertTriangle } from 'lucide-react'
import api from '../services/api'
import SeverityBadge from '../components/SeverityBadge'
import { cvssColor, formatDateTime } from '../utils/helpers'

const STATUS_CONFIG = {
  'Exploited in the Wild': { icon: Target,      text: '#ef4444', bg: 'rgba(239,68,68,0.15)', border: 'rgba(239,68,68,0.3)', shadow: '0 0 20px rgba(239,68,68,0.2)' },
  'Patch Available':       { icon: Shield,      text: '#eab308', bg: 'rgba(234,179,8,0.15)', border: 'rgba(234,179,8,0.3)', shadow: '0 0 20px rgba(234,179,8,0.1)' },
  'Mitigated':             { icon: ShieldAlert, text: '#22c55e', bg: 'rgba(34,197,94,0.15)', border: 'rgba(34,197,94,0.3)', shadow: '0 0 20px rgba(34,197,94,0.1)' },
  'Under Investigation':   { icon: Clock,       text: '#3b82f6', bg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.3)', shadow: '0 0 20px rgba(59,130,246,0.2)' },
}

export default function ZeroDayTracker() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  
  // New State for Search & Actively Exploited
  const [activelyExploited, setActivelyExploited] = useState([])
  const [loadingExploited, setLoadingExploited] = useState(true)
  
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResult, setSearchResult] = useState(null)
  const [isSearching, setIsSearching] = useState(false)
  const [searchError, setSearchError] = useState(null)
  const [aiSummary, setAiSummary] = useState(null)
  const [isGenerating, setIsGenerating] = useState(false)

  const loadData = () => {
    // Fetch normal tracked zero-days
    api.get('/advisories', { params: { is_zero_day: true, per_page: 100 } })
      .then(r => setItems(r.data.items || []))
      .catch(() => {})
      .finally(() => setLoading(false))
      
    // Fetch Actively Exploited list
    api.get('/cve/actively-exploited', { params: { limit: 50 } })
      .then(r => {
        let rawData = r.data.data || []
        const MNC_LIST = ["Microsoft", "Apple", "Google", "Cisco", "Fortinet", "Palo Alto", "VMware", "Oracle", "Adobe", "Atlassian", "Ivanti", "Trend Micro"]
        
        rawData.sort((a, b) => {
          const aIsMnc = MNC_LIST.some(m => (a.vendorProject || "").toLowerCase().includes(m.toLowerCase())) ? 1 : 0
          const bIsMnc = MNC_LIST.some(m => (b.vendorProject || "").toLowerCase().includes(m.toLowerCase())) ? 1 : 0
          
          if (aIsMnc !== bIsMnc) return bIsMnc - aIsMnc // MNCs first
          
          if (a.dateAdded === b.dateAdded) {
            return (b.cveID || "").localeCompare(a.cveID || "")
          }
          return new Date(b.dateAdded) - new Date(a.dateAdded)
        })
        setActivelyExploited(rawData)
      })
      .catch(() => {})
      .finally(() => setLoadingExploited(false))
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 300000)
    return () => clearInterval(interval)
  }, [])

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!searchQuery.trim()) return
    
    setIsSearching(true)
    setSearchError(null)
    setSearchResult(null)
    setAiSummary(null)
    
    try {
      const res = await api.get(`/cve/lookup/${searchQuery}`)
      setSearchResult(res.data.data)
    } catch (err) {
      setSearchError(err.response?.data?.detail || "CVE not found or error occurred.")
    } finally {
      setIsSearching(false)
    }
  }

  const generateAiSummary = async () => {
    if (!searchResult) return
    setIsGenerating(true)
    try {
      const content = JSON.stringify(searchResult)
      const res = await api.post(`/cve/lookup/${searchQuery.toUpperCase()}/ai-summary`, { content })
      setAiSummary(res.data.report)
    } catch (err) {
      setAiSummary("Error generating AI summary. Ensure API keys are configured.")
    } finally {
      setIsGenerating(false)
    }
  }

  const closeModal = () => {
    setSearchResult(null)
    setSearchQuery('')
    setAiSummary(null)
    setSearchError(null)
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-32 space-y-4">
        <div className="relative w-16 h-16">
          <div className="absolute inset-0 border-4 border-red-500/20 rounded-full"></div>
          <div className="absolute inset-0 border-4 border-red-500 rounded-full border-t-transparent animate-spin"></div>
          <Bug className="absolute inset-0 m-auto w-6 h-6 text-red-500 animate-pulse" />
        </div>
        <div className="text-sm font-black text-red-400 uppercase tracking-widest animate-pulse">Initializing Zero-Day Intel...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6 relative">
      <style>{`
        @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        .animate-fade-up { animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .glass-panel { background: rgba(10,17,35,0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }
      `}</style>

      {/* Header & Search */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6" style={{ animation: 'slideDown 0.5s ease both' }}>
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center relative group"
            style={{ background: 'linear-gradient(135deg, rgba(239,68,68,0.2), rgba(168,85,247,0.2))', border: '1px solid rgba(239,68,68,0.3)', boxShadow: '0 0 30px rgba(239,68,68,0.2)' }}>
            <Bug className="w-7 h-7 text-red-400 group-hover:scale-110 transition-transform" />
            <div className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-red-500 rounded-full border-2 border-slate-950 animate-ping" />
            <div className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-red-500 rounded-full border-2 border-slate-950" />
          </div>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tight">Zero-Day Tracker</h1>
            <p className="text-xs text-slate-400 font-medium uppercase tracking-widest mt-1 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
              Live threat intelligence & CISA KEV Sync
            </p>
          </div>
        </div>
        
        {/* CVE Search Bar */}
        <form onSubmit={handleSearch} className="relative flex-1 max-w-md">
          <div className="relative flex items-center">
            <Search className="absolute left-4 w-5 h-5 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search CVE ID (e.g., CVE-2024-3094)"
              className="w-full bg-slate-900/50 border border-slate-700 rounded-full py-3 pl-12 pr-32 text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-slate-500"
            />
            <button
              type="submit"
              disabled={isSearching}
              className="absolute right-1.5 top-1.5 bottom-1.5 px-4 bg-blue-600 hover:bg-blue-500 text-white rounded-full text-sm font-bold transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              {isSearching ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Lookup'}
            </button>
          </div>
          {searchError && <p className="absolute top-full mt-2 left-4 text-xs text-red-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3"/> {searchError}</p>}
        </form>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {['Exploited in the Wild', 'Patch Available', 'Mitigated', 'Under Investigation'].map((status, idx) => {
          const count = status === 'Exploited in the Wild' && activelyExploited.length > 0
            ? activelyExploited.length 
            : items.filter(i => i.zero_day_status === status).length;
          const cfg = STATUS_CONFIG[status] || { icon: Bug, text: '#94a3b8', bg: 'rgba(255,255,255,0.05)', border: 'rgba(255,255,255,0.1)', shadow: 'none' }
          const Icon = cfg.icon
          return (
            <div key={status} className="rounded-2xl p-5 relative overflow-hidden group transition-all hover:-translate-y-1"
              style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, boxShadow: cfg.shadow, animation: `fadeUp 0.5s ease both ${idx * 0.1}s` }}>
              <div className="absolute -right-4 -bottom-4 opacity-10 group-hover:scale-125 group-hover:opacity-20 transition-all duration-500">
                <Icon className="w-24 h-24" style={{ color: cfg.text }} />
              </div>
              <div className="relative z-10">
                <div className="text-4xl font-black mb-1" style={{ color: cfg.text }}>{count}</div>
                <div className="text-[11px] font-bold uppercase tracking-widest text-slate-300">{status}</div>
              </div>
            </div>
          )
        })}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Left Column: Tracked Advisories */}
        <div className="space-y-4">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-blue-400" />
            Internally Tracked Zero-Days
          </h2>
          {items.length === 0 ? (
            <div className="glass-panel rounded-3xl p-10 text-center animate-fade-up">
              <Target className="w-10 h-10 text-slate-600 mx-auto mb-3 opacity-50" />
              <h3 className="text-md font-bold text-slate-300 mb-1">No Zero-Days Tracked</h3>
              <p className="text-xs text-slate-500">Tag internal advisories as 'Zero-Day' to monitor them.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {items.map((adv, idx) => {
                const statusCfg = STATUS_CONFIG[adv.zero_day_status] || { text: '#94a3b8', bg: 'rgba(255,255,255,0.05)', border: 'rgba(255,255,255,0.1)' }
                const cvss = adv.cvss_score || 0
                return (
                  <Link key={adv.id} to={`/advisories/${adv.id}`}
                    className="block glass-panel rounded-2xl p-4 hover:bg-slate-900/50 transition-all duration-300 hover:scale-[1.01] group relative overflow-hidden">
                    <div className="absolute left-0 top-0 bottom-0 w-1 transition-all group-hover:w-1.5" style={{ background: statusCfg.text }} />
                    <div className="flex flex-col items-start gap-3 pl-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={adv.severity} />
                        {adv.zero_day_status && (
                          <span className="text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-md border"
                            style={{ background: statusCfg.bg, color: statusCfg.text, borderColor: statusCfg.border }}>
                            {adv.zero_day_status}
                          </span>
                        )}
                        {adv.is_kev && <span className="text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-md bg-red-500/20 text-red-400 border border-red-500/30">CISA KEV</span>}
                      </div>
                      <h3 className="font-bold text-white text-sm group-hover:text-blue-400 transition-colors line-clamp-2">{adv.title}</h3>
                      <div className="flex items-center justify-between w-full mt-1">
                        <div className="text-xs text-slate-500 flex items-center gap-1.5"><Clock className="w-3 h-3"/> {formatDateTime(adv.created_at)}</div>
                        {cvss > 0 && <div className={`text-lg font-black ${cvssColor(cvss)} drop-shadow-md`}>{cvss.toFixed(1)}</div>}
                      </div>
                    </div>
                  </Link>
                )
              })}
            </div>
          )}
        </div>

        {/* Right Column: Actively Exploited (MNC) */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Target className="w-5 h-5 text-red-500" />
              Actively Exploited
            </h2>
            <div className="text-[10px] uppercase tracking-widest text-slate-500 font-bold bg-slate-800/50 px-2 py-1 rounded">Top 50 • 6hr Sync</div>
          </div>
          
          {loadingExploited ? (
            <div className="glass-panel rounded-3xl p-10 flex justify-center"><Loader2 className="w-8 h-8 text-red-500 animate-spin" /></div>
          ) : activelyExploited.length === 0 ? (
            <div className="glass-panel rounded-3xl p-10 text-center"><p className="text-slate-500 text-sm">No actively exploited data available.</p></div>
          ) : (
            <div className="space-y-3">
              {activelyExploited.map((vuln, idx) => (
                <div key={idx} className="glass-panel rounded-2xl p-4 relative overflow-hidden hover:border-red-500/30 transition-colors"
                  style={{ animation: `fadeUp 0.5s ease both ${0.3 + (idx * 0.05)}s` }}>
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-red-500" />
                  <div className="pl-2">
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <span className="text-xs font-mono font-bold bg-red-500/10 text-red-400 px-2 py-0.5 rounded border border-red-500/20">
                        {vuln.cveID}
                      </span>
                      {vuln.is_project_zero && (
                        <span className="text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-md bg-blue-500/20 text-blue-400 border border-blue-500/30 flex items-center gap-1" title="Tracked by Google Project Zero">
                          <Shield className="w-2.5 h-2.5" /> Project Zero
                        </span>
                      )}
                      {vuln.has_public_exploit && (
                        <span className="text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-md bg-orange-500/20 text-orange-400 border border-orange-500/30 flex items-center gap-1" title="Public Exploit Available in Exploit-DB">
                          <Target className="w-2.5 h-2.5" /> PoC Exploit
                        </span>
                      )}
                      <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider ml-auto">
                        {vuln.dateAdded}
                      </span>
                    </div>
                    <h3 className="font-bold text-sm text-slate-200 mb-1">{vuln.vulnerabilityName}</h3>
                    <p className="text-xs text-slate-400 mb-2 line-clamp-2">{vuln.shortDescription}</p>
                    <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-800/50">
                      <div className="text-[10px] font-bold text-slate-300 uppercase tracking-wider bg-slate-800 px-2 py-1 rounded">
                        Vendor: <span className="text-blue-400">{vuln.vendorProject}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cveID}`} target="_blank" rel="noopener noreferrer"
                          className="text-[10px] font-bold text-slate-400 hover:text-white flex items-center gap-1 uppercase tracking-wider">
                          <ExternalLink className="w-3 h-3" /> Source
                        </a>
                        <button onClick={() => { setSearchQuery(vuln.cveID); handleSearch({preventDefault: () => {}}); }} 
                          className="text-[10px] font-bold text-blue-400 hover:text-blue-300 flex items-center gap-1 uppercase tracking-wider">
                          <Search className="w-3 h-3" /> Analyze
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* CVE Lookup Modal */}
      {searchResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-up">
          <div className="bg-slate-900 border border-slate-700 rounded-3xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-900/50">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center border border-blue-500/30">
                  <Bug className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-xl font-black text-white">{searchQuery.toUpperCase()}</h2>
                  <p className="text-xs text-slate-400 font-medium uppercase tracking-widest">Vulnerability Dossier</p>
                </div>
              </div>
              <button onClick={closeModal} className="w-8 h-8 rounded-full hover:bg-slate-800 flex items-center justify-center transition-colors text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto flex-1 space-y-6 custom-scrollbar">
              
              {/* AI Summary Section */}
              <div className="p-6 rounded-2xl bg-gradient-to-br from-indigo-900/20 to-purple-900/20 border border-indigo-500/20 relative overflow-hidden">
                <div className="absolute -right-10 -top-10 w-32 h-32 bg-indigo-500/10 rounded-full blur-3xl"></div>
                
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-black text-indigo-400 uppercase tracking-widest flex items-center gap-2">
                    <Sparkles className="w-4 h-4" /> AI Professional Summary
                  </h3>
                  {!aiSummary && !isGenerating && (
                    <button onClick={generateAiSummary} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-lg transition-colors flex items-center gap-2 shadow-lg shadow-indigo-900/50">
                      <Sparkles className="w-3.5 h-3.5" /> Generate Executive Brief
                    </button>
                  )}
                </div>

                {isGenerating ? (
                  <div className="flex items-center gap-3 text-indigo-300 py-4">
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span className="text-sm font-medium">Synthesizing intelligence from multiple sources...</span>
                  </div>
                ) : aiSummary ? (
                  <div className="text-[13px] text-justify text-slate-300 font-medium leading-relaxed max-w-none whitespace-pre-wrap">
                    {aiSummary.replace(/\[ANALYST ESTIMATE\]\s*/g, '').split(/(https?:\/\/[^\s]+)/g).map((part, i) => 
                      part.match(/https?:\/\/[^\s]+/) ? (
                        <a key={i} href={part} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 underline break-all">
                          {part}
                        </a>
                      ) : (
                        part
                      )
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500 italic">Click generate to produce a board-ready intelligence brief covering impact, attribution, and remediation.</p>
                )}
              </div>

              {/* Raw Data */}
              <div>
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3">Raw Technical Data</h3>
                <div className="bg-slate-950 rounded-xl p-4 border border-slate-800 overflow-x-auto text-xs text-slate-400 font-mono custom-scrollbar">
                  <pre>{JSON.stringify(searchResult, null, 2)}</pre>
                </div>
              </div>

            </div>
          </div>
        </div>
      )}

    </div>
  )
}
