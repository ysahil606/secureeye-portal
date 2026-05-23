import { useState, useCallback, useRef, useEffect } from 'react'
import {
  Search as SearchIcon, Globe, ExternalLink, Shield, Radar, Mic, MicOff,
  History, Trash2, Star
} from 'lucide-react'
import api from '../services/api'
import AdvisoryCard from '../components/AdvisoryCard'
import SeverityBadge from '../components/SeverityBadge'
import { formatDateTime, truncate } from '../utils/helpers'
import toast from 'react-hot-toast'
import clsx from 'clsx'

function ExternalResultCard({ item, index = 0 }) {
  // Compute animation delay based on index for staggered entrance
  const delay = Math.min(index * 150 + 200, 1500)
  
  return (
    <div 
      className="group relative overflow-hidden bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 shadow-xl transition-all duration-500 hover:shadow-[0_0_40px_rgba(59,130,246,0.15)] hover:border-blue-500/40 hover:-translate-y-1 animate-in slide-in-from-bottom-8 fade-in fill-mode-both"
      style={{ animationDelay: `${delay}ms`, animationDuration: '700ms' }}
    >
      {/* Dynamic Hover Gradient Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-600/5 via-transparent to-purple-600/5 opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none" />
      
      {/* Left accent border */}
      <div className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-blue-500 to-purple-500 opacity-50 group-hover:opacity-100 transition-opacity duration-500" />

      <div className="relative z-10 flex flex-col md:flex-row md:items-start justify-between gap-5">
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            {item.severity && <SeverityBadge severity={item.severity} />}
            <span className="inline-flex items-center gap-1.5 text-[10px] uppercase font-black tracking-[0.2em] text-slate-300 bg-white/5 px-3 py-1.5 rounded-lg border border-white/10 shadow-sm">
              <Globe className="w-3 h-3 text-blue-400" />
              {item.source_name || 'Threat Intel'}
            </span>
            {item.is_kev && (
              <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest bg-purple-500/10 text-purple-300 border border-purple-500/30 shadow-[0_0_15px_rgba(168,85,247,0.15)]">
                KEV Match
              </span>
            )}
          </div>
          
          <h3 className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-300 group-hover:from-white group-hover:via-blue-100 group-hover:to-cyan-200 transition-all duration-500 leading-snug">
            {item.title}
          </h3>
          
          {item.display_url && (
            <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-400/80 mt-1 truncate">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              {item.display_url}
            </div>
          )}
          
          {item.cve_ids?.length > 0 && (
            <div className="flex flex-wrap gap-2 pt-1">
              {item.cve_ids.slice(0, 4).map((cve) => (
                <span key={cve} className="inline-flex items-center text-[11px] font-black tracking-wider text-cyan-300 bg-cyan-950/40 px-2.5 py-1 rounded-md border border-cyan-800/50 shadow-inner">
                  {cve}
                </span>
              ))}
            </div>
          )}
          
          {item.description && (
            <div className="text-[14px] text-slate-300 leading-relaxed font-medium pl-4 border-l-2 border-white/10 text-justify hyphens-auto mt-3">
              {truncate(item.description.replace(/<[^>]+>/g, ' '), 280)}
            </div>
          )}
        </div>
        
        {item.cvss_score ? (
          <div className="flex-shrink-0 flex flex-col items-center justify-center bg-dark-950/80 border border-white/5 rounded-2xl p-4 shadow-inner group-hover:border-orange-500/30 group-hover:shadow-[0_0_20px_rgba(249,115,22,0.15)] transition-all">
            <div className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-b from-orange-300 to-orange-600">
              {Number(item.cvss_score).toFixed(1)}
            </div>
            <div className="text-[9px] font-black uppercase tracking-widest text-slate-500 mt-1">
              Threat Score
            </div>
          </div>
        ) : null}
      </div>
      
      <div className="relative z-10 flex flex-wrap items-center justify-between gap-4 mt-6 pt-5 border-t border-white/5 text-[11px] font-bold uppercase tracking-widest text-slate-500">
        <div className="flex items-center gap-5">
          {item.published_at && (
            <span className="flex items-center gap-1.5">
              <History className="w-3.5 h-3.5 text-slate-400" />
              {formatDateTime(item.published_at)}
            </span>
          )}
          {item.affected_vendors?.length > 0 && (
            <span className="flex items-center gap-1.5 text-blue-400/70">
              <Shield className="w-3.5 h-3.5" /> 
              {item.affected_vendors.slice(0, 2).join(', ')}
            </span>
          )}
        </div>
        
        {item.source_url && (
          <a href={item.source_url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-cyan-500 hover:text-cyan-300 hover:scale-105 transition-all">
            Open Intel Report <ExternalLink className="w-3.5 h-3.5" />
          </a>
        )}
      </div>
    </div>
  )
}

export default function SmartSearch() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [isListening, setIsListening] = useState(false)
  const [savedSearches, setSavedSearches] = useState(() => {
    try { return JSON.parse(localStorage.getItem('secureeye_saved_searches') || '[]') } catch { return [] }
  })
  const [recentSearches, setRecentSearches] = useState(() => {
    try { return JSON.parse(localStorage.getItem('secureeye_recent_searches') || '[]') } catch { return [] }
  })
  const recognitionRef = useRef(null)

  const doSearch = useCallback(async (q) => {
    const cleanQuery = q.trim()
    if (!cleanQuery) return
    setLoading(true)
    try {
      const r = await api.get('/advisories/search', { params: { q: cleanQuery, per_page: 50 } })
      setResults(r.data)
      setRecentSearches(prev => {
        const next = [cleanQuery, ...prev.filter(item => item !== cleanQuery)].slice(0, 8)
        localStorage.setItem('secureeye_recent_searches', JSON.stringify(next))
        return next
      })
    } catch (error) {
      toast.error(error?.response?.data?.detail || 'Search failed')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
      const SpeechRecognition = window.webkitSpeechRecognition || window.SpeechRecognition
      recognitionRef.current = new SpeechRecognition()
      recognitionRef.current.continuous = false
      recognitionRef.current.interimResults = false
      recognitionRef.current.lang = 'en-US'
      recognitionRef.current.onresult = (event) => {
        const transcript = event.results[0][0].transcript
        setQuery(transcript)
        setIsListening(false)
        doSearch(transcript)
      }
      recognitionRef.current.onerror = () => {
        setIsListening(false)
        toast.error('Voice recognition failed')
      }
      recognitionRef.current.onend = () => setIsListening(false)
    }
  }, [doSearch])

  const toggleListening = () => {
    if (isListening) {
      recognitionRef.current?.stop()
      return
    }
    if (!recognitionRef.current) {
      toast.error('Speech recognition not supported')
      return
    }
    setQuery('')
    recognitionRef.current.start()
    setIsListening(true)
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    doSearch(query)
  }

  const saveCurrentSearch = () => {
    const cleanQuery = query.trim()
    if (!cleanQuery || savedSearches.includes(cleanQuery)) return
    const next = [cleanQuery, ...savedSearches].slice(0, 12)
    setSavedSearches(next)
    localStorage.setItem('secureeye_saved_searches', JSON.stringify(next))
    toast.success('Search saved')
  }

  const removeSavedSearch = (item) => {
    const next = savedSearches.filter(value => value !== item)
    setSavedSearches(next)
    localStorage.setItem('secureeye_saved_searches', JSON.stringify(next))
  }

  const suggestions = ['CVE-2024-3400', 'Apache', 'BFSI', 'RCE', 'Palo Alto', 'Fortinet', 'Microsoft', 'zero-day']
  const isGoogleMode = results?.search_mode === 'google_web'
  const isThreatIntelMode = results?.search_mode === 'threat_intel'
  const webResultsHeading = isGoogleMode ? 'Google Web Results' : (isThreatIntelMode ? 'Threat Intel Results' : 'Web Search Results')
  const webResultsEmpty = isGoogleMode ? 'No Google web results found.' : (isThreatIntelMode ? 'No threat-intel matches found.' : 'No web results found.')
  const savedAndRecent = [...savedSearches, ...recentSearches.filter(item => !savedSearches.includes(item))].slice(0, 8)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <div className="relative flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-500/20 to-purple-500/20 border border-white/10 shadow-[0_0_30px_rgba(59,130,246,0.15)]">
            <SearchIcon className="w-6 h-6 text-blue-400" />
            <div className="absolute inset-0 bg-blue-400/20 blur-xl rounded-2xl opacity-50" />
          </div>
          <div>
            <h1 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-blue-100 to-cyan-300 tracking-tight">
              Smart Search
            </h1>
            <div className="h-1 w-1/3 bg-gradient-to-r from-blue-500 to-transparent mt-1 rounded-full opacity-50" />
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="relative group animate-in slide-in-from-top-4 fade-in duration-700">
        <div className="absolute -inset-1 bg-gradient-to-r from-blue-600 via-cyan-500 to-purple-600 rounded-[2rem] blur-md opacity-25 group-hover:opacity-40 transition duration-1000 group-focus-within:opacity-60" />
        
        {/* Animated Border Container */}
        <div className="relative p-[1.5px] rounded-[2rem] overflow-hidden shadow-2xl">
          {/* Spinning Gradient */}
          <div 
            className="absolute inset-[-100%] animate-spin bg-[conic-gradient(from_0deg_at_50%_50%,#3b82f6_0%,#06b6d4_25%,#a855f7_50%,#3b82f6_75%,#3b82f6_100%)] opacity-30 group-hover:opacity-100 transition-opacity duration-500" 
            style={{ animationDuration: '4s' }} 
          />
          
          {/* Inner Content */}
          <div className="relative flex flex-col sm:flex-row gap-3 bg-dark-950 p-2 rounded-[calc(2rem-1.5px)] z-10">
            <div className="relative flex-1 flex items-center">
              <SearchIcon className={clsx("absolute left-5 w-5 h-5 transition-colors duration-300", isListening ? "text-red-400" : "text-blue-400 group-focus-within:text-cyan-400")} />
              <input
                className="w-full bg-transparent border-none text-slate-200 text-[15px] font-medium pl-14 pr-14 py-4 focus:outline-none focus:ring-0 placeholder:text-slate-500/80"
                placeholder={isListening ? 'Listening for target intel...' : 'Search CVE-2024-3400, Apache, BFSI, zero-day...'}
                value={query}
                onChange={e => setQuery(e.target.value)}
                autoFocus
              />
              <button
                type="button"
                onClick={toggleListening}
                className={clsx(
                  'absolute right-4 p-2 rounded-full transition-all duration-300', 
                  isListening ? 'bg-red-500/20 text-red-400 shadow-[0_0_20px_rgba(239,68,68,0.4)] animate-pulse scale-110' : 'bg-white/5 text-slate-400 hover:text-white hover:bg-white/10'
                )}
              >
                {isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
              </button>
            </div>
            <div className="flex gap-2 px-2 sm:px-0 pb-2 sm:pb-0 pr-2">
              <button type="button" onClick={saveCurrentSearch} disabled={!query.trim()} className="bg-dark-900/50 hover:bg-dark-800 disabled:opacity-50 text-slate-300 px-5 rounded-2xl flex items-center justify-center transition-all border border-white/5 hover:border-blue-500/30 relative z-20">
                <Star className="w-4 h-4" />
              </button>
              <button type="submit" disabled={!query.trim() || loading} className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:opacity-50 text-white font-black uppercase tracking-widest text-xs px-8 py-4 rounded-2xl shadow-[0_0_20px_rgba(59,130,246,0.3)] hover:shadow-[0_0_30px_rgba(6,182,212,0.5)] transition-all hover:scale-[1.02] active:scale-[0.98] relative z-20">
                {loading ? <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin inline-block" /> : 'Search'}
              </button>
            </div>
          </div>
        </div>
      </form>

      {!results && (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3 animate-in fade-in duration-1000 delay-300 fill-mode-both">
          <div className="xl:col-span-2 space-y-4">
            <p className="text-[11px] font-black uppercase tracking-widest text-slate-500 flex items-center gap-2">
              <Radar className="w-4 h-4 text-cyan-500" /> High Priority Hunts
            </p>
            <div className="flex flex-wrap gap-3">
              {suggestions.map((s, i) => (
                <button 
                  key={s} 
                  onClick={() => { setQuery(s); doSearch(s) }} 
                  className="group relative overflow-hidden bg-dark-900/40 hover:bg-dark-800 text-slate-300 text-sm font-medium border border-white/5 hover:border-cyan-500/30 px-5 py-2.5 rounded-xl transition-all hover:-translate-y-0.5 hover:shadow-[0_0_15px_rgba(6,182,212,0.1)] animate-in slide-in-from-bottom-4 fade-in fill-mode-both"
                  style={{ animationDelay: `${i * 50 + 500}ms` }}
                >
                  <span className="relative z-10">{s}</span>
                  <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/0 via-cyan-500/10 to-blue-500/0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700" />
                </button>
              ))}
            </div>
          </div>
          <div className="bg-dark-950/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 shadow-inner animate-in slide-in-from-right-8 fade-in fill-mode-both delay-700">
            <h2 className="flex items-center gap-3 text-[11px] font-black uppercase tracking-widest text-white mb-6">
              <div className="w-6 h-6 rounded-full bg-blue-500/20 flex items-center justify-center"><History className="w-3.5 h-3.5 text-blue-400" /></div>
              Saved & Recent
            </h2>
            {savedAndRecent.length === 0 ? (
              <p className="text-sm text-slate-500 italic">No search history recorded.</p>
            ) : (
              <div className="space-y-3">
                {savedAndRecent.map((item, i) => (
                  <div key={item} className="group flex items-center justify-between gap-3 bg-dark-900/50 border border-white/5 hover:border-blue-500/20 rounded-xl px-4 py-2.5 transition-colors animate-in fade-in fill-mode-both" style={{ animationDelay: `${i * 50 + 900}ms` }}>
                    <button onClick={() => { setQuery(item); doSearch(item) }} className="flex-1 truncate text-left text-[13px] font-medium text-slate-400 group-hover:text-blue-300 transition-colors">
                      {item}
                    </button>
                    {savedSearches.includes(item) && (
                      <button onClick={() => removeSavedSearch(item)} className="text-slate-600 hover:text-red-400 transition-colors bg-white/5 hover:bg-red-500/10 p-1.5 rounded-lg" title="Remove saved search">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {results && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-slate-400">
              <span className="text-white font-semibold">{results.total}</span> results for "{query}"
            </p>
            <button onClick={() => { setResults(null); setQuery('') }} className="text-sm text-slate-500 hover:text-slate-300 transition-colors">Clear</button>
          </div>

          {results.configuration_hint && (
            <div className="card p-4 text-sm text-amber-300 border border-amber-700/30 bg-amber-950/20 mb-4">{results.configuration_hint}</div>
          )}

          {(results.local_total === 0 && results.external_total === 0) ? (
            <div className="card p-12 text-center text-slate-500">No local or online matches found for "{query}"</div>
          ) : (
            <div className="space-y-6">
              <section>
                <div className="flex items-center gap-2 mb-3">
                  <Radar className="w-4 h-4 text-blue-400" />
                  <h2 className="text-sm font-semibold text-white">{webResultsHeading}</h2>
                  <span className="text-xs text-slate-500">({results.external_total})</span>
                </div>
                {(results.external_items || []).length === 0 ? (
                  <div className="card p-6 text-sm text-slate-500">{webResultsEmpty}</div>
                ) : (
                  <div className="space-y-4">
                    {results.external_items.map((item, index) => <ExternalResultCard key={`${item.source_type}-${item.source_url || item.title}`} item={item} index={index} />)}
                  </div>
                )}
              </section>

              <section>
                <div className="flex items-center gap-2 mb-3">
                  <SearchIcon className="w-4 h-4 text-emerald-400" />
                  <h2 className="text-sm font-semibold text-white">Your Advisory Database</h2>
                  <span className="text-xs text-slate-500">({results.local_total})</span>
                </div>
                {(results.local_items || []).length === 0 ? (
                  <div className="card p-6 text-sm text-slate-500">No internal advisories matched this query.</div>
                ) : (
                  <div className="space-y-3">
                    {results.local_items.map(a => <AdvisoryCard key={a.id} advisory={a} />)}
                  </div>
                )}
              </section>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
