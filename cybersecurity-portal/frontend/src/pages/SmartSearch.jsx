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

function ExternalResultCard({ item }) {
  return (
    <div className="card p-4 border border-dark-600 hover:border-blue-500/40 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            {item.severity && <SeverityBadge severity={item.severity} />}
            <span className="text-xs text-slate-300 bg-dark-800 px-2 py-0.5 rounded-full border border-dark-600">
              {item.source_name || 'Threat intel'}
            </span>
            {item.is_kev && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-purple-900/60 text-purple-300 border border-purple-700/50">
                KEV
              </span>
            )}
          </div>
          <h3 className="font-semibold text-white leading-snug">{item.title}</h3>
          {item.display_url && <div className="text-xs text-emerald-400 mt-1 truncate">{item.display_url}</div>}
          {item.cve_ids?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {item.cve_ids.slice(0, 4).map((cve) => (
                <span key={cve} className="text-xs font-mono text-blue-400 bg-blue-950/40 px-1.5 py-0.5 rounded border border-blue-800/50">{cve}</span>
              ))}
            </div>
          )}
          {item.description && (
            <p className="text-sm text-slate-400 mt-2 leading-relaxed">
              {truncate(item.description.replace(/<[^>]+>/g, ' '), 220)}
            </p>
          )}
        </div>
        {item.cvss_score ? (
          <div className="text-center flex-shrink-0">
            <div className="text-2xl font-bold text-orange-400">{Number(item.cvss_score).toFixed(1)}</div>
            <div className="text-xs text-slate-500">CVSS</div>
          </div>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center gap-4 mt-3 pt-3 border-t border-dark-600 text-xs text-slate-500">
        <span className="flex items-center gap-1">
          <Globe className="w-3 h-3" /> {(item.source_type || 'web').replace('_', ' ')}
        </span>
        {item.published_at && <span>{formatDateTime(item.published_at)}</span>}
        {item.affected_vendors?.length > 0 && (
          <span className="flex items-center gap-1">
            <Shield className="w-3 h-3" /> {item.affected_vendors.slice(0, 2).join(', ')}
          </span>
        )}
        {item.source_url && (
          <a href={item.source_url} target="_blank" rel="noopener noreferrer" className="ml-auto flex items-center gap-1 hover:text-blue-400 transition-colors">
            <ExternalLink className="w-3 h-3" /> Open Source
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
      <div>
        <h1 className="text-2xl font-bold text-white">Smart Search</h1>
        <p className="text-slate-400 max-w-2xl">
          Search your advisories plus live web results. Save frequent hunts and re-run recent searches quickly.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="relative flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <SearchIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            className="input pl-12 pr-12 py-3.5 text-base"
            placeholder={isListening ? 'Listening...' : 'Search CVE-2024-3400, Apache, BFSI, RCE...'}
            value={query}
            onChange={e => setQuery(e.target.value)}
            autoFocus
          />
          <button
            type="button"
            onClick={toggleListening}
            className={clsx('absolute right-4 top-1/2 -translate-y-1/2 p-1.5 rounded-full transition-colors', isListening ? 'text-red-500 animate-pulse bg-red-500/10' : 'text-slate-500 hover:text-blue-400')}
          >
            {isListening ? <MicOff className="w-5 h-5" /> : <Mic className="w-5 h-5" />}
          </button>
        </div>
        <button type="submit" disabled={!query.trim() || loading} className="btn-primary py-3.5 px-8 font-bold shadow-lg shadow-blue-600/20 whitespace-nowrap">
          {loading ? <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin inline-block" /> : 'Search Now'}
        </button>
        <button type="button" onClick={saveCurrentSearch} disabled={!query.trim()} className="btn-ghost flex items-center justify-center gap-2 py-3.5 px-4 text-sm">
          <Star className="w-4 h-4" /> Save
        </button>
      </form>

      {!results && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <p className="text-xs text-slate-500 mb-2">Quick searches:</p>
            <div className="flex flex-wrap gap-2">
              {suggestions.map(s => (
                <button key={s} onClick={() => { setQuery(s); doSearch(s) }} className="text-sm bg-dark-800 hover:bg-dark-700 text-slate-300 border border-dark-600 px-3 py-1.5 rounded-lg transition-colors">
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="card p-4 space-y-3">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-white">
              <History className="w-4 h-4 text-blue-400" /> Saved and recent
            </h2>
            {savedAndRecent.length === 0 ? (
              <p className="text-xs text-slate-500">Your saved and recent searches will appear here.</p>
            ) : (
              <div className="space-y-2">
                {savedAndRecent.map(item => (
                  <div key={item} className="flex items-center gap-2 rounded-lg border border-dark-600 bg-dark-800 px-2 py-1.5">
                    <button onClick={() => { setQuery(item); doSearch(item) }} className="min-w-0 flex-1 truncate text-left text-xs text-slate-300 hover:text-blue-300">{item}</button>
                    {savedSearches.includes(item) && (
                      <button onClick={() => removeSavedSearch(item)} className="text-slate-600 hover:text-red-400" title="Remove saved search">
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
                  <div className="space-y-3">
                    {results.external_items.map((item) => <ExternalResultCard key={`${item.source_type}-${item.source_url || item.title}`} item={item} />)}
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
