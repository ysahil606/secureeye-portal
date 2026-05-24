import { useState, useEffect, useRef } from 'react'
import { Play, Pause, Volume2, VolumeX, Radio, RefreshCw, AlertTriangle } from 'lucide-react'
import api from '../services/api'

export default function CyberBriefingPlayer() {
  const [isPlaying, setIsPlaying] = useState(false)
  const [isMuted, setIsMuted] = useState(false)
  const [advisories, setAdvisories] = useState([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState(new Date())
  const [currentText, setCurrentText] = useState('')
  const [voiceAvailable, setVoiceAvailable] = useState(true)
  
  const synthRef = useRef(window.speechSynthesis)
  const utteranceRef = useRef(null)

  const fetchAdvisories = async () => {
    try {
      setLoading(true)
      const res = await api.get('/advisories', {
        params: { status: 'published', per_page: 5, is_critical: true }
      })
      
      // If no critical, just get top 5
      let items = res.data.items
      if (!items || items.length === 0) {
        const fallback = await api.get('/advisories', {
          params: { status: 'published', per_page: 5 }
        })
        items = fallback.data.items
      }
      
      setAdvisories(items || [])
      setLastUpdated(new Date())
    } catch (e) {
      console.error('Failed to fetch advisories for briefing:', e)
    } finally {
      setLoading(false)
    }
  }

  // Initial load and 10-minute interval
  useEffect(() => {
    fetchAdvisories()
    const interval = setInterval(fetchAdvisories, 10 * 60 * 1000)
    return () => clearInterval(interval)
  }, [])

  // Check if speech synthesis is available
  useEffect(() => {
    if (!('speechSynthesis' in window)) {
      setVoiceAvailable(false)
    }
  }, [])

  const stripHtml = (html) => {
    if (!html) return ''
    const doc = new DOMParser().parseFromString(html, 'text/html')
    return doc.body.textContent || ''
  }

  const buildScript = () => {
    if (advisories.length === 0) {
      return "Good morning. There are currently no major security advisories to report. All systems appear nominal."
    }

    const timeString = lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    let script = `Secure Eye Daily Briefing. Current time is ${timeString}. We are tracking ${advisories.length} priority advisories today. `

    advisories.forEach((adv, index) => {
      const isCritical = adv.is_critical_alert || adv.severity === 'critical'
      const sevString = isCritical ? 'Critical Alert.' : 'High Priority.'
      script += `Item ${index + 1}: ${sevString} ${adv.title}. `
      
      if (adv.ai_summary) {
        script += `Summary: ${stripHtml(adv.ai_summary)}. `
      } else if (adv.description) {
        // Just read the first sentence or two of the description
        const desc = stripHtml(adv.description).split('.')[0]
        script += `Overview: ${desc}. `
      }
      
      if (adv.affected_vendors && adv.affected_vendors.length > 0) {
        script += `Affected vendors include ${adv.affected_vendors.join(', ')}. `
      }
      script += "Pause. "
    })

    script += "End of briefing. Stay secure."
    return script.replace(/Pause\./g, '... ') // Add slight pauses
  }

  const togglePlay = () => {
    if (!voiceAvailable) return

    if (isPlaying) {
      synthRef.current.pause()
      setIsPlaying(false)
    } else {
      if (synthRef.current.paused) {
        synthRef.current.resume()
        setIsPlaying(true)
      } else {
        // Start fresh
        synthRef.current.cancel()
        const text = buildScript()
        setCurrentText(text)
        
        const utterance = new SpeechSynthesisUtterance(text)
        
        // Try to find a good English voice
        const voices = synthRef.current.getVoices()
        const preferredVoice = voices.find(v => v.lang.startsWith('en-') && (v.name.includes('Google') || v.name.includes('Premium') || v.name.includes('Siri')))
        if (preferredVoice) utterance.voice = preferredVoice

        utterance.rate = 0.95 // Slightly slower for better comprehension
        utterance.pitch = 1.0
        utterance.volume = isMuted ? 0 : 1

        utterance.onend = () => {
          setIsPlaying(false)
          setCurrentText('')
        }
        
        utterance.onerror = () => {
          setIsPlaying(false)
        }

        utteranceRef.current = utterance
        synthRef.current.speak(utterance)
        setIsPlaying(true)
      }
    }
  }

  const toggleMute = () => {
    const newMuted = !isMuted
    setIsMuted(newMuted)
    if (utteranceRef.current && isPlaying) {
      // Browsers don't let you dynamically change volume while speaking easily,
      // but we can try setting the ref or restarting. For simplicity, just cancel and restart if muted
      synthRef.current.cancel()
      setIsPlaying(false)
    }
  }

  // Ensure voices are loaded
  useEffect(() => {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.getVoices()
    }
    
    return () => {
      if (synthRef.current) {
        synthRef.current.cancel()
      }
    }
  }, [])

  if (!voiceAvailable) return null

  return (
    <div className="mb-6 rounded-3xl overflow-hidden relative"
      style={{
        background: 'linear-gradient(135deg, rgba(15,23,42,0.95), rgba(10,17,35,0.95))',
        border: '1px solid rgba(168,85,247,0.2)',
        boxShadow: '0 10px 40px rgba(0,0,0,0.5), inset 0 2px 20px rgba(168,85,247,0.05)',
        backdropFilter: 'blur(20px)'
      }}>
      
      {/* Animated glow background when playing */}
      <div className={`absolute inset-0 transition-opacity duration-1000 ${isPlaying ? 'opacity-100' : 'opacity-0'}`}
        style={{
          background: 'radial-gradient(circle at 20% 50%, rgba(168,85,247,0.15) 0%, transparent 60%)',
          animation: isPlaying ? 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite' : 'none'
        }}
      />

      <div className="relative p-5 sm:p-6 flex flex-col sm:flex-row items-center gap-6">
        
        {/* Album Art / Radar */}
        <div className="relative flex-shrink-0 w-20 h-20 sm:w-24 sm:h-24 rounded-2xl flex items-center justify-center overflow-hidden"
          style={{ background: 'rgba(2,6,23,0.8)', border: '1px solid rgba(255,255,255,0.05)' }}>
          {/* Radar sweeping effect */}
          <div className={`absolute inset-0 border-2 border-purple-500/20 rounded-full transition-transform duration-[3s] linear ${isPlaying ? 'animate-[spin_3s_linear_infinite]' : ''}`}
            style={{ width: '200%', height: '200%', top: '-50%', left: '-50%', clipPath: 'polygon(50% 50%, 100% 0, 100% 100%)', background: 'linear-gradient(90deg, rgba(168,85,247,0.2), transparent)' }} 
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <Radio className={`w-8 h-8 ${isPlaying ? 'text-purple-400 animate-pulse' : 'text-slate-500'}`} />
          </div>
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm">
              <RefreshCw className="w-5 h-5 text-purple-400 animate-spin" />
            </div>
          )}
        </div>

        {/* Info & Controls */}
        <div className="flex-1 w-full flex flex-col justify-center">
          <div className="flex items-center justify-between mb-2">
            <div>
              <div className="text-[10px] font-black uppercase tracking-widest text-purple-400 mb-1 flex items-center gap-1.5">
                {isPlaying && <span className="w-2 h-2 rounded-full bg-purple-500 animate-pulse" />}
                Daily Cyber Briefing
              </div>
              <h3 className="text-lg font-black text-white leading-tight truncate">
                {advisories.length > 0 ? `Top ${advisories.length} Priority Threats` : 'No Critical Threats'}
              </h3>
            </div>
            
            <div className="flex items-center gap-2">
              <button onClick={toggleMute} className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-colors">
                {isMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="text-xs text-slate-500 mb-4 line-clamp-1">
            {isPlaying ? (
              <span className="text-purple-300 italic">Listening to automated advisory briefing...</span>
            ) : (
              <span>Last synced at {lastUpdated.toLocaleTimeString()} · Updates every 10m</span>
            )}
          </div>

          {/* Player Bar */}
          <div className="flex items-center gap-4">
            <button 
              onClick={togglePlay}
              disabled={loading}
              className="w-12 h-12 flex-shrink-0 rounded-full flex items-center justify-center transition-all hover:scale-105 disabled:opacity-50 disabled:hover:scale-100"
              style={{ background: 'linear-gradient(135deg, #a855f7, #7c3aed)', boxShadow: '0 0 20px rgba(168,85,247,0.4)' }}
            >
              {isPlaying ? (
                <Pause className="w-5 h-5 text-white" fill="currentColor" />
              ) : (
                <Play className="w-5 h-5 text-white ml-1" fill="currentColor" />
              )}
            </button>

            {/* Audio Waveform visualizer (fake) */}
            <div className="flex-1 h-8 flex items-center gap-1 opacity-80 overflow-hidden">
              {[...Array(30)].map((_, i) => (
                <div 
                  key={i} 
                  className="w-1.5 bg-purple-500/50 rounded-full origin-bottom"
                  style={{ 
                    height: isPlaying ? `${Math.max(20, Math.random() * 100)}%` : '20%',
                    transition: 'height 0.2s ease',
                    animation: isPlaying ? `waveform 0.5s ease infinite alternate ${i * 0.05}s` : 'none'
                  }} 
                />
              ))}
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}
