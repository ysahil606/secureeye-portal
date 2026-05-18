import { useState } from 'react'
import {
  Activity, AlertTriangle, CheckCircle2, Copy, Database, Download, Eye,
  Ghost, Globe, Loader2, Lock, Mail, Plus, Search, ShieldCheck, Trash2
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
    } catch {
      await new Promise(resolve => setTimeout(resolve, 1200))
      setResults({
        query: normalized,
        scanned_at: new Date().toISOString(),
        exposure_level: 'Simulation',
        recommendations: [
          'Force password reset for exposed identities.',
          'Review MFA enrollment and recent sign-in logs.',
          'Search SIEM, DNS, EDR, and proxy logs for related indicators.',
        ],
        leaks: [
          { id: `admin-${normalized}`, email: `admin@${normalized}`, source: 'Credential stuffing list', date: '2024-03-12', severity: 'critical' },
          { id: `devops-${normalized}`, email: `devops@${normalized}`, source: 'Stealer log index', date: '2024-04-10', severity: 'high' },
          { id: `hr-${normalized}`, email: `hr@${normalized}`, source: 'Public paste archive', date: '2023-11-05', severity: 'medium' },
        ],
        mentions: [
          { id: `infra-${normalized}`, title: `Discussion regarding ${normalized} infrastructure`, snippet: 'Potential external exposure mentioned in a simulated source.', onion_site: 'simulation', severity: 'high' },
          { id: `dump-${normalized}`, title: `Database dump claim for ${normalized}`, snippet: 'Unverified marketplace claim detected in demo mode.', onion_site: 'simulation', severity: 'critical' },
        ],
      })
      toast.success('Simulation loaded because backend scan was unavailable')
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
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-purple-600/20 border border-purple-500/30 rounded-lg">
              <Ghost className="w-6 h-6 text-purple-400" />
            </div>
            Dark Web Monitor
          </h1>
          <p className="text-slate-400 mt-1">Leak detection, watchlists, and exposure triage for monitored domains.</p>
        </div>
      </div>

      <div className="bg-dark-800 border border-dark-600 rounded-2xl p-6 shadow-xl">
        <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
            <input
              type="text"
              placeholder="Enter domain or organization, e.g. target.com"
              className="input pl-12 py-3.5 text-base"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              disabled={scanning}
            />
          </div>
          <button
            type="submit"
            disabled={scanning || !domain.trim()}
            className="bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold px-8 py-3.5 rounded-xl transition-all shadow-lg shadow-purple-900/20 flex items-center justify-center gap-2"
          >
            {scanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
            Start Surveillance
          </button>
        </form>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="card p-4"><div className="text-xs text-slate-500">Exposed credentials</div><div className="mt-1 text-2xl font-bold text-red-400">{leakCount}</div></div>
        <div className="card p-4"><div className="text-xs text-slate-500">Mentions</div><div className="mt-1 text-2xl font-bold text-purple-400">{mentionCount}</div></div>
        <div className="card p-4"><div className="text-xs text-slate-500">Resolved leaks</div><div className="mt-1 text-2xl font-bold text-green-400">{resolvedCount}</div></div>
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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            [Mail, 'Credential Dumps', 'Search for leaked employee emails and passwords in data breaches.'],
            [Database, 'Paste Monitoring', 'Scan public repositories and paste sites for internal secrets.'],
            [Eye, 'Forum Mentions', 'Detect discussions and listings targeting your organization.'],
          ].map(([Icon, title, copy]) => (
            <div key={title} className="card p-6 border-dashed border-dark-600 flex flex-col items-center text-center space-y-3">
              <div className="w-12 h-12 bg-dark-700 rounded-full flex items-center justify-center"><Icon className="w-6 h-6 text-slate-500" /></div>
              <h3 className="font-bold text-white">{title}</h3>
              <p className="text-xs text-slate-500 leading-relaxed">{copy}</p>
            </div>
          ))}
        </div>
      )}

      {scanning && (
        <div className="py-20 flex flex-col items-center justify-center space-y-4">
          <div className="relative">
            <div className="w-20 h-20 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin" />
            <Ghost className="absolute inset-0 m-auto w-8 h-8 text-purple-500 animate-pulse" />
          </div>
          <div className="text-center">
            <h3 className="text-lg font-bold text-white tracking-widest uppercase">Deep Crawling...</h3>
            <p className="text-sm text-slate-500">Querying exposure sources and local threat intelligence</p>
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
            <button onClick={() => setActiveTab('actions')} className={clsx('pb-3 text-sm font-bold uppercase tracking-widest transition-all', activeTab === 'actions' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-slate-500')}>Actions</button>
          </div>

          {activeTab === 'leaks' && (
            <div className="grid grid-cols-1 gap-4">
              {leakCount > 0 ? results.leaks.map((leak, i) => (
                <div key={leak.id || i} className="card p-5 border-l-4 border-l-red-500 bg-red-500/5 flex items-center justify-between gap-4">
                  <div className="flex min-w-0 items-center gap-4">
                    <div className="w-10 h-10 bg-red-500/20 rounded-lg flex items-center justify-center"><Lock className="w-5 h-5 text-red-500" /></div>
                    <div className="min-w-0">
                      <div className="text-white font-mono font-bold text-sm break-all">{leak.email}</div>
                      <div className="text-[10px] text-slate-500 uppercase font-bold mt-1">Breach: {leak.source} | Date: {leak.date}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] bg-red-500 text-white px-2 py-0.5 rounded-full font-bold uppercase tracking-tighter">{leak.severity || 'exposed'}</span>
                    {resolvedLeaks.includes(leak.id || leak.email) ? (
                      <CheckCircle2 className="w-5 h-5 text-green-400" />
                    ) : (
                      <button onClick={() => markResolved(leak)} className="text-slate-500 hover:text-green-400" title="Mark resolved"><CheckCircle2 className="w-5 h-5" /></button>
                    )}
                  </div>
                </div>
              )) : (
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
                <div key={mention.id || i} className="card p-5 border-l-4 border-l-purple-500 bg-purple-500/5">
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2"><Ghost className="w-4 h-4 text-purple-400" /><span className="text-white font-bold text-sm tracking-tight">{mention.title}</span></div>
                      <p className="text-xs text-slate-400 leading-relaxed italic">"{mention.snippet}"</p>
                      <div className="text-[10px] text-slate-600 font-mono uppercase font-bold">{mention.onion_site}</div>
                    </div>
                    <AlertTriangle className="w-5 h-5 text-purple-400 animate-pulse" />
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
    </div>
  )
}
