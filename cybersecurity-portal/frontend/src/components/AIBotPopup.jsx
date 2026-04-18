import { useState } from 'react'
import { Bot, Send, X, Loader2, Maximize2, Minimize2 } from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'

export default function AIBotPopup() {
  const [isOpen, setIsOpen] = useState(false)
  const [isExpanded, setIsExpanded] = useState(false)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [summary, setSummary] = useState('')

  const handleAnalyze = async (e) => {
    e.preventDefault()
    if (!input.trim()) return

    setLoading(true)
    setSummary('')
    try {
      const isUrl = input.startsWith('http')
      const payload = isUrl ? { url: input } : { text: input }
      
      const r = await api.post('/ai/analyze', payload)
      setSummary(r.data.summary)
      setIsOpen(true)
      setIsExpanded(true)
    } catch (err) {
      toast.error(err.response?.data?.detail || 'AI Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end">
      {/* Trigger Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="w-14 h-14 bg-blue-600 hover:bg-blue-500 text-white rounded-full shadow-lg shadow-blue-900/40 flex items-center justify-center transition-all hover:scale-110 group"
        >
          <Bot className="w-7 h-7" />
          <span className="absolute right-16 bg-dark-800 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap border border-dark-600">
            Ask Secure AI
          </span>
        </button>
      )}

      {/* Chat Window */}
      {isOpen && (
        <div className={`bg-dark-800 border border-dark-600 rounded-2xl shadow-2xl transition-all duration-300 flex flex-col overflow-hidden ${isExpanded ? 'w-[500px] h-[600px]' : 'w-80 h-96'}`}>
          {/* Header */}
          <div className="bg-dark-700 px-4 py-3 flex items-center justify-between border-b border-dark-600">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-blue-600/20 rounded-lg flex items-center justify-center">
                <Bot className="w-4 h-4 text-blue-400" />
              </div>
              <span className="font-semibold text-white text-sm">Secure AI Assistant</span>
            </div>
            <div className="flex items-center gap-1">
              <button onClick={() => setIsExpanded(!isExpanded)} className="p-1.5 text-slate-400 hover:text-white transition-colors">
                {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
              </button>
              <button onClick={() => { setIsOpen(false); setSummary(''); setInput('') }} className="p-1.5 text-slate-400 hover:text-red-400 transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
            {!summary && !loading && (
              <div className="text-center py-10 space-y-3">
                <div className="w-12 h-12 bg-dark-700 rounded-full flex items-center justify-center mx-auto">
                  <Bot className="w-6 h-6 text-slate-500" />
                </div>
                <p className="text-slate-400 text-sm px-6">
                  Paste an advisory link, CVE ID, or vulnerability text to get a 20-25 line AI summary.
                </p>
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center py-20 gap-3">
                <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
                <p className="text-xs text-slate-500 animate-pulse">Analyzing threat intelligence...</p>
              </div>
            )}

            {summary && (
              <div className="bg-dark-900/50 border border-blue-500/20 rounded-xl p-4 animate-in fade-in slide-in-from-bottom-2">
                <div className="flex items-center gap-2 mb-3">
                  <div className="h-1.5 w-1.5 rounded-full bg-blue-500" />
                  <span className="text-[10px] uppercase tracking-widest text-blue-400 font-bold">Analysis Report</span>
                </div>
                <pre className="text-slate-300 text-xs leading-relaxed whitespace-pre-wrap font-sans">
                  {summary}
                </pre>
              </div>
            )}
          </div>

          {/* Footer Input */}
          <form onSubmit={handleAnalyze} className="p-4 bg-dark-700/50 border-t border-dark-600">
            <div className="relative">
              <input
                className="w-full bg-dark-900 border border-dark-600 rounded-xl pl-4 pr-10 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors"
                placeholder="Enter link or text..."
                value={input}
                onChange={e => setInput(e.target.value)}
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading || !input.trim()}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-blue-500 hover:text-blue-400 disabled:opacity-30 transition-colors"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
