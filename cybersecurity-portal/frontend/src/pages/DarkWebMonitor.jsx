import { useState } from 'react'
import {
  Activity, AlertTriangle, CheckCircle2, Copy, Database, Download, Eye,
  ExternalLink, Ghost, Globe, Loader2, Lock, Mail, Plus, Search, ShieldCheck, ShieldAlert, Trash2, X
} from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'
import clsx from 'clsx'

export default function DarkWebMonitor() {
  const [domain, setDomain] = useState('')
  const [watchInput, setWatchInput] = useState('')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState(null)
  const [activeTab, setActiveTab] = useState('leaks')
  const [selectedLeak, setSelectedLeak] = useState(null)
  const [watchlist, setWatchlist] = useState(() => {
    try { return JSON.parse(localStorage.getItem('darkweb_watchlist') || '[]') } catch { return [] }
  })
  const [resolvedLeaks, setResolvedLeaks] = useState(() => {
    try { return JSON.parse(localStorage.getItem('darkweb_resolved') || '[]') } catch { return [] }
  })

  const saveWatchlist = (next) => {
    setWatchlist(next)
    localStorage.setItem('darkweb_watchlist', JSON.stringify(next))
  }

  const addWatchItem = (e) => {
    e.preventDefault()
    const item = watchInput.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase()
    if (!item || watchlist.includes(item)) return
    saveWatchlist([item, ...watchlist].slice(0, 12))
    setWatchInput('')
    toast.success('Watchlist updated')
  }

  const removeWatchItem = (item) => {
    saveWatchlist(watchlist.filter(value => value !== item))
  }

  const runScan = async (target) => {
    const normalized = target.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase()
    if (!normalized) return
    setDomain(normalized)
    setScanning(true)
    setResults(null)

    try {
      const res = await api.get('/darkweb/scan', { params: { q: normalized } })
      setResults(res.data)
    } catch (error) {
      toast.error('Dark web scan failed. Backend may be unavailable.')
    } finally {
      setScanning(false)
    }
  }

  const handleScan = (e) => {
    e.preventDefault()
    runScan(domain)
  }

  const markResolved = (leak) => {
    const id = leak.id || leak.email
    const next = [...new Set([...resolvedLeaks, id])]
    setResolvedLeaks(next)
    localStorage.setItem('darkweb_resolved', JSON.stringify(next))
    toast.success('Marked resolved')
  }

  const copyEmails = async () => {
    const emails = (results?.leaks || []).map(item => item.email).filter(Boolean).join('\n')
    if (!emails) return
    await navigator.clipboard.writeText(emails)
    toast.success('Emails copied')
  }

  const exportCsv = () => {
    if (!results) return
    const rows = [
      ['type', 'value', 'source', 'date', 'severity', 'status'],
      ...(results.leaks || []).map(item => ['leak', item.email, item.source, item.date, item.severity || '', resolvedLeaks.includes(item.id || item.email) ? 'resolved' : 'open']),
      ...(results.mentions || []).map(item => ['mention', item.title, item.onion_site, '', item.severity || '', 'open']),
    ]
    const csv = rows.map(row => row.map(value => `"${String(value || '').replaceAll('"', '""')}"`).join(',')).join('\n')
    const objectUrl = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = `darkweb-${results.query || domain || 'scan'}.csv`
    a.click()
    URL.revokeObjectURL(objectUrl)
  }

  const leakCount = results?.leaks?.length || 0
  const mentionCount = results?.mentions?.length || 0
  const resolvedCount = (results?.leaks || []).filter(item => resolvedLeaks.includes(item.id || item.email)).length

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 pb-4 border-b border-white/5">
        <div className="relative">
          <div className="absolute -inset-4 bg-purple-500/10 blur-2xl rounded-full" />
          <h1 className="relative text-3xl md:text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-red-400 flex items-center gap-4">
            <div className="p-3 bg-gradient-to-br from-purple-600 to-pink-600 rounded-2xl shadow-neon-purple text-white">
              <Ghost className="w-8 h-8" />
            </div>
            Dark Web Surveillance
          </h1>
          <p className="relative text-slate-400 mt-2 text-sm max-w-xl leading-relaxed">
            Real-time credential leak detection, hacker forum tracking, and exposure triage powered by SecureEye intelligence networks.
          </p>
        </div>
      </div>

      <div className="relative z-10 p-[2px] rounded-3xl bg-gradient-to-r from-purple-500/30 via-transparent to-pink-500/30">
        <div className="bg-dark-900/90 backdrop-blur-2xl rounded-[22px] p-8 shadow-glass">
          <form onSubmit={handleScan} className="flex flex-col md:flex-row gap-6 relative">
            <div className="relative flex-1 group">
              <div className="absolute -inset-1 bg-gradient-to-r from-purple-600 to-pink-600 rounded-2xl blur opacity-25 group-hover:opacity-40 transition duration-1000 group-hover:duration-200" />
              <div className="relative flex items-center">
                <Globe className="absolute left-6 w-6 h-6 text-purple-400 animate-pulse" />
                <input
                  type="text"
                  placeholder="Target domain (e.g., target.com) or email address..."
                  className="w-full bg-dark-950/80 border border-white/5 text-white rounded-2xl pl-16 pr-6 py-5 text-lg placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 shadow-inner transition-all"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  disabled={scanning}
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={scanning || !domain.trim()}
              className="md:w-auto w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 disabled:opacity-50 text-white font-black px-10 py-5 rounded-2xl transition-all shadow-neon-purple flex items-center justify-center gap-3 text-lg uppercase tracking-wider group"
            >
              {scanning ? (
                <Loader2 className="w-6 h-6 animate-spin" />
              ) : (
                <Search className="w-6 h-6 group-hover:scale-110 transition-transform" />
              )}
              Initiate Scan
            </button>
          </form>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="card card-hover p-6 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/10 rounded-full blur-3xl -mr-10 -mt-10 group-hover:bg-red-500/20 transition-all" />
          <div className="text-sm font-bold text-slate-400 uppercase tracking-widest">Exposed Credentials</div>
          <div className="mt-2 text-4xl font-black text-transparent bg-clip-text bg-gradient-to-br from-red-400 to-rose-600">{leakCount}</div>
        </div>
        <div className="card card-hover p-6 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-purple-500/10 rounded-full blur-3xl -mr-10 -mt-10 group-hover:bg-purple-500/20 transition-all" />
          <div className="text-sm font-bold text-slate-400 uppercase tracking-widest">Dark Web Mentions</div>
          <div className="mt-2 text-4xl font-black text-transparent bg-clip-text bg-gradient-to-br from-purple-400 to-fuchsia-600">{mentionCount}</div>
        </div>
        <div className="card card-hover p-6 relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-green-500/10 rounded-full blur-3xl -mr-10 -mt-10 group-hover:bg-green-500/20 transition-all" />
          <div className="text-sm font-bold text-slate-400 uppercase tracking-widest">Resolved Leaks</div>
          <div className="mt-2 text-4xl font-black text-transparent bg-clip-text bg-gradient-to-br from-green-400 to-emerald-600">{resolvedCount}</div>
        </div>
      </div>

      <div className="card p-5 space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-sm font-bold text-white">Domain watchlist</h2>
          <form onSubmit={addWatchItem} className="flex gap-2">
            <input className="input text-sm" placeholder="example.com" value={watchInput} onChange={e => setWatchInput(e.target.value)} />
            <button className="btn-primary flex items-center gap-2 text-sm" type="submit"><Plus className="w-4 h-4" /> Add</button>
          </form>
        </div>
        {watchlist.length === 0 ? (
          <div className="text-sm text-slate-500">Add domains you want to re-check quickly.</div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {watchlist.map(item => (
              <div key={item} className="flex items-center gap-1 rounded-lg border border-dark-600 bg-dark-800 px-2 py-1">
                <button onClick={() => runScan(item)} className="text-sm text-slate-300 hover:text-purple-300">{item}</button>
                <button onClick={() => removeWatchItem(item)} className="text-slate-600 hover:text-red-400" title="Remove"><Trash2 className="w-3.5 h-3.5" /></button>
              </div>
            ))}
          </div>
        )}
      </div>

      {!results && !scanning && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pt-8">
          {[
            [Mail, 'Credential Dumps', 'Search for leaked employee emails and passwords in data breaches.'],
            [Database, 'Paste Monitoring', 'Scan public repositories and paste sites for internal secrets.'],
            [Eye, 'Forum Mentions', 'Detect discussions and listings targeting your organization.'],
          ].map(([Icon, title, copy], idx) => (
            <div key={title} className="group relative card p-8 border border-white/5 bg-gradient-to-b from-dark-800/40 to-transparent flex flex-col items-center text-center space-y-4 hover:border-purple-500/30 transition-all animate-fade-in-up" style={{ animationDelay: `${idx * 150}ms` }}>
              <div className="absolute inset-0 bg-gradient-to-t from-purple-900/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl" />
              <div className="w-16 h-16 bg-gradient-to-br from-dark-700 to-dark-900 rounded-2xl flex items-center justify-center shadow-lg group-hover:shadow-neon-purple transition-all">
                <Icon className="w-8 h-8 text-purple-400 group-hover:scale-110 transition-transform" />
              </div>
              <h3 className="font-extrabold text-white text-lg">{title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed max-w-[200px]">{copy}</p>
            </div>
          ))}
        </div>
      )}

      {scanning && (
        <div className="py-32 flex flex-col items-center justify-center space-y-8 animate-in zoom-in duration-700">
          <div className="relative">
            <div className="absolute inset-0 bg-purple-500/20 blur-3xl rounded-full" />
            <div className="w-32 h-32 border-[6px] border-dark-700 border-t-purple-500 rounded-full animate-spin shadow-neon-purple" />
            <div className="absolute inset-0 m-auto w-24 h-24 border-[4px] border-dark-700 border-b-pink-500 rounded-full animate-radar-spin" style={{ animationDirection: 'reverse' }} />
            <Ghost className="absolute inset-0 m-auto w-10 h-10 text-purple-400 animate-pulse" />
          </div>
          <div className="text-center space-y-2">
            <h3 className="text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400 tracking-[0.2em] uppercase animate-pulse">Deep Crawling Network...</h3>
            <p className="text-sm text-slate-400 font-mono">Querying intelligence sources: HIBP, EmailRep, SecureDB</p>
          </div>
        </div>
      )}

      {results && (
        <div className="space-y-6 animate-in slide-in-from-bottom-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-dark-600 bg-dark-800/70 p-4">
            <div>
              <div className="text-sm font-bold text-white">{results.exposure_level || 'Watch'} exposure for {results.query || domain}</div>
              <div className="text-xs text-slate-500">{results.scanned_at ? new Date(results.scanned_at).toLocaleString() : 'Scan complete'}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={copyEmails} className="btn-ghost flex items-center gap-2 text-sm"><Copy className="w-4 h-4" /> Copy emails</button>
              <button onClick={exportCsv} className="btn-ghost flex items-center gap-2 text-sm"><Download className="w-4 h-4" /> Export CSV</button>
            </div>
          </div>

          <div className="flex border-b border-dark-600 gap-6 overflow-x-auto">
            <button onClick={() => setActiveTab('leaks')} className={clsx('pb-3 text-sm font-bold uppercase tracking-widest transition-all', activeTab === 'leaks' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-slate-500')}>Exposed Credentials ({leakCount})</button>
            <button onClick={() => setActiveTab('mentions')} className={clsx('pb-3 text-sm font-bold uppercase tracking-widest transition-all', activeTab === 'mentions' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-slate-500')}>Mentions ({mentionCount})</button>
            <button onClick={() => setActiveTab('osint')} className={clsx('pb-3 text-sm font-bold uppercase tracking-widest transition-all', activeTab === 'osint' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-slate-500')}>OSINT Engines</button>
            <button onClick={() => setActiveTab('actions')} className={clsx('pb-3 text-sm font-bold uppercase tracking-widest transition-all', activeTab === 'actions' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-slate-500')}>Actions</button>
          </div>

          {activeTab === 'leaks' && (
            <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
              {leakCount > 0 ? (
                <>
                  <div className="overflow-x-auto rounded-xl border border-dark-600 bg-dark-800/50 backdrop-blur-sm shadow-xl mt-2">
                    <table className="w-full text-left text-sm whitespace-nowrap">
                      <thead className="bg-dark-700/80 text-slate-400 text-xs font-bold uppercase tracking-wider border-b border-dark-600">
                        <tr>
                          <th className="p-4 w-8 text-center"></th>
                          <th className="p-4">Source URL / Breach</th>
                          <th className="p-4">Type</th>
                          <th className="p-4">Email / Username</th>
                          <th className="p-4">Details</th>
                          <th className="p-4">Indexed At</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-dark-600/50">
                        {results.leaks.map((leak, i) => {
                          return (
                            <tr 
                              key={leak.id || i} 
                              className="hover:bg-white/5 transition-colors group cursor-pointer"
                              onClick={() => setSelectedLeak(leak)}
                            >
                              <td className="p-4 align-middle">
                                <div className="w-4 h-4 rounded border border-slate-600 group-hover:border-purple-500 transition-colors mx-auto flex items-center justify-center">
                                  {resolvedLeaks.includes(leak.id || leak.email) && <CheckCircle2 className="w-3 h-3 text-green-400" />}
                                </div>
                              </td>
                              <td className="p-4 font-mono text-slate-300">
                                <span className="flex items-center gap-2 hover:text-blue-400 cursor-pointer transition-colors"><Globe className="w-3.5 h-3.5 text-slate-500 group-hover:text-blue-400" /> {leak.source || 'Dark Web Dump'}</span>
                              </td>
                              <td className="p-4">
                                <span className="px-2.5 py-1 rounded-full border border-green-500/30 text-green-400 text-[10px] font-bold tracking-widest uppercase bg-green-500/10">Email</span>
                              </td>
                              <td className="p-4 font-mono text-white font-bold">
                                {leak.email}
                              </td>
                              <td className="p-4 text-slate-300">
                                <span className="flex items-center gap-2"><ShieldAlert className="w-3.5 h-3.5 text-red-400" /> {leak.hint || 'Exposed in data breach'}</span>
                              </td>
                              <td className="p-4">
                                <div className="flex flex-col items-start">
                                  <div className="flex items-center gap-1.5 text-slate-300 text-xs"><Database className="w-3.5 h-3.5 text-slate-500" /> {leak.date}</div>
                                  {leak.date !== "Unknown" && (
                                    <span className="text-[9px] font-bold text-orange-400 mt-1 uppercase bg-orange-500/10 px-1.5 py-0.5 rounded">Recent</span>
                                  )}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <div className="py-12 text-center card bg-green-500/5 border-green-500/20">
                  <ShieldCheck className="w-12 h-12 text-green-500 mx-auto mb-3" />
                  <h3 className="text-white font-bold">No Leaked Credentials</h3>
                  <p className="text-sm text-slate-500">Domain is currently clean across indexed signals.</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'mentions' && (
            <div className="grid grid-cols-1 gap-4">
              {mentionCount > 0 ? results.mentions.map((mention, i) => (
                <div key={mention.id || i} className="card p-5 border-l-4 border-l-purple-500 bg-purple-500/5 hover:bg-purple-500/10 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2 flex-1">
                      <div className="flex items-center gap-2"><Ghost className="w-4 h-4 text-purple-400" /><span className="text-white font-bold text-sm tracking-tight">{mention.title}</span></div>
                      <p className="text-xs text-slate-400 leading-relaxed italic">"{mention.snippet}"</p>
                      <div className="text-[10px] text-slate-600 font-mono uppercase font-bold">{mention.onion_site}</div>
                    </div>
                    <div className="flex flex-col items-end gap-3">
                      <AlertTriangle className="w-5 h-5 text-purple-400 animate-pulse" />
                      {mention.url && (
                        <a href={mention.url} target="_blank" rel="noreferrer" className="flex items-center gap-1.5 text-[10px] font-bold text-purple-400 hover:text-white bg-purple-500/10 hover:bg-purple-500/30 px-3 py-1.5 rounded-lg border border-purple-500/20 transition-all uppercase tracking-widest">
                          <ExternalLink className="w-3.5 h-3.5" /> View Source
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              )) : (
                <div className="py-12 text-center card bg-dark-800/50">
                  <Activity className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                  <h3 className="text-white font-bold">No Active Mentions</h3>
                  <p className="text-sm text-slate-500">No organizational mentions found.</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'osint' && (
            <div className="space-y-4">
              <div className="card p-5 bg-dark-800">
                <h3 className="text-white font-bold mb-4 flex items-center gap-2"><Globe className="w-5 h-5 text-blue-400" /> Connected Open Sources</h3>
                <div className="flex flex-wrap gap-2">
                  {(results.sources_checked || []).map(src => (
                    <span key={src} className="px-3 py-1 bg-blue-500/10 border border-blue-500/30 text-blue-400 rounded-full text-xs font-bold">{src}</span>
                  ))}
                </div>
              </div>
              {(results.premium_sources_skipped || []).length > 0 && (
                <div className="card p-5 bg-orange-500/5 border-orange-500/20">
                  <h3 className="text-orange-400 font-bold mb-3 flex items-center gap-2"><AlertTriangle className="w-5 h-5" /> Freemium Engines Skipped</h3>
                  <p className="text-sm text-slate-400 mb-4">The following APIs were skipped. Register for a free account on their platform and add the API Key to <code className="text-orange-300">backend/.env</code> to activate them:</p>
                  <div className="flex flex-wrap gap-2">
                    {results.premium_sources_skipped.map(src => (
                      <span key={src} className="px-3 py-1 bg-orange-500/10 border border-orange-500/30 text-orange-400 rounded-full text-xs font-bold">{src}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'actions' && (
            <div className="card p-5 space-y-3">
              {(results.recommendations || []).map((item, index) => (
                <div key={index} className="flex items-start gap-3 rounded-lg bg-dark-800 p-3 text-sm text-slate-300">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-green-400" />
                  <span>{item}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {selectedLeak && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="w-full max-w-2xl bg-dark-900 border border-purple-500/30 rounded-2xl shadow-neon-purple p-6 relative flex flex-col gap-6 animate-in zoom-in-95 duration-200">
            
            <button 
              onClick={() => setSelectedLeak(null)}
              className="absolute top-4 right-4 p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-full transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-4 border-b border-white/10 pb-4 pr-10">
              <div className="w-12 h-12 rounded-xl bg-purple-500/20 flex items-center justify-center border border-purple-500/40">
                <ShieldAlert className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white leading-tight">{selectedLeak.source}</h2>
                <div className="text-sm text-slate-400 flex items-center gap-2 mt-1">
                  <Database className="w-3.5 h-3.5" /> 
                  Indexed: {selectedLeak.date}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Target Identity</div>
                <div className="font-mono text-white text-sm">{selectedLeak.email}</div>
              </div>
              <div className="bg-dark-800 rounded-xl p-4 border border-dark-600">
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Threat Level</div>
                <div className="flex items-center gap-2">
                  <span className={clsx(
                    "px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-widest",
                    selectedLeak.severity === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                  )}>
                    {selectedLeak.severity}
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-dark-800 rounded-xl p-5 border border-dark-600">
              <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Exposed Information</div>
              <p className="text-sm text-slate-300 leading-relaxed">
                {selectedLeak.hint || "Raw breach data has been partially redacted to prevent abuse. General credential exposure is confirmed."}
              </p>
              
              <div className="mt-4 flex flex-wrap gap-2">
                {selectedLeak.has_password && (
                  <span className="px-3 py-1.5 bg-red-500/10 border border-red-500/20 text-red-400 rounded-md text-xs font-bold font-mono flex items-center gap-2">
                    <Lock className="w-3.5 h-3.5" /> Password Exposed
                  </span>
                )}
                {selectedLeak.email && (
                  <span className="px-3 py-1.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-md text-xs font-bold font-mono flex items-center gap-2">
                    <Mail className="w-3.5 h-3.5" /> Identity Exposed
                  </span>
                )}
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setSelectedLeak(null)} className="btn-ghost px-6">Close</button>
              {!resolvedLeaks.includes(selectedLeak.id || selectedLeak.email) && (
                <button 
                  onClick={() => {
                    markResolved(selectedLeak);
                    setSelectedLeak(null);
                  }} 
                  className="bg-green-500/20 hover:bg-green-500/30 text-green-400 border border-green-500/40 font-bold px-6 py-2 rounded-lg transition-colors flex items-center gap-2 text-sm"
                >
                  <CheckCircle2 className="w-4 h-4" /> Mark Resolved
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
