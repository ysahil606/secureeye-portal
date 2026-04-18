import { useState, useEffect } from 'react'
import { Volume2, VolumeX, Mic, Play, Square } from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'

export default function MorningBriefing() {
  const [script, setScript] = useState('')
  const [isSpeaking, setIsSpeaking] = useState(false)
  const [loading, setLoading] = useState(false)

  const fetchBriefing = async () => {
    setLoading(true)
    try {
      const r = await api.get('/dashboard/briefing')
      setScript(r.data.script)
      return r.data.script
    } catch {
      toast.error('Failed to generate briefing')
      return null
    } finally {
      setLoading(false)
    }
  }

  const speak = (text) => {
    if (!window.speechSynthesis) {
      toast.error('Audio briefing not supported in this browser')
      return
    }

    // Stop any current speech
    window.speechSynthesis.cancel()

    const utterance = new SpeechSynthesisUtterance(text)
    
    // Choose a professional sounding voice if available
    const voices = window.speechSynthesis.getVoices()
    const preferredVoice = voices.find(v => 
        v.name.includes('Google US English') || 
        v.name.includes('Male') || 
        v.name.includes('Samantha')
    )
    if (preferredVoice) utterance.voice = preferredVoice

    utterance.rate = 0.95 // Slightly slower for clarity
    utterance.pitch = 1.0

    utterance.onstart = () => setIsSpeaking(true)
    utterance.onend = () => setIsSpeaking(false)
    utterance.onerror = () => setIsSpeaking(false)

    window.speechSynthesis.speak(utterance)
  }

  const handleToggle = async () => {
    if (isSpeaking) {
      window.speechSynthesis.cancel()
      setIsSpeaking(false)
      return
    }

    let textToSpeak = script
    if (!textToSpeak) {
      textToSpeak = await fetchBriefing()
    }

    if (textToSpeak) {
      speak(textToSpeak)
    }
  }

  // Pre-fetch on mount so it's ready
  useEffect(() => {
    fetchBriefing()
  }, [])

  return (
    <div className="bg-gradient-to-r from-blue-600/10 to-purple-600/10 border border-blue-500/20 rounded-2xl p-4 flex items-center justify-between gap-4">
      <div className="flex items-center gap-4">
        <div className={`w-12 h-12 rounded-full flex items-center justify-center transition-all ${isSpeaking ? 'bg-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.5)]' : 'bg-dark-800 border border-dark-600'}`}>
          {isSpeaking ? (
            <div className="flex gap-0.5 items-end h-4">
                <div className="w-1 bg-white animate-audio-bar-1" />
                <div className="w-1 bg-white animate-audio-bar-2" />
                <div className="w-1 bg-white animate-audio-bar-3" />
            </div>
          ) : (
            <Mic className="w-5 h-5 text-slate-400" />
          )}
        </div>
        
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">AI Executive Briefing</h3>
          <p className="text-xs text-slate-400 max-w-md line-clamp-1">
            {loading ? 'Preparing your morning threat report...' : script || 'Ready to summarize the current landscape.'}
          </p>
        </div>
      </div>

      <button
        onClick={handleToggle}
        disabled={loading}
        className={`px-6 py-2.5 rounded-xl font-bold text-xs uppercase tracking-widest flex items-center gap-2 transition-all ${isSpeaking ? 'bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20' : 'bg-blue-600 text-white hover:bg-blue-500 shadow-lg shadow-blue-900/20'}`}
      >
        {isSpeaking ? (
          <><Square className="w-3.5 h-3.5 fill-current" /> Stop Briefing</>
        ) : (
          <><Play className="w-3.5 h-3.5 fill-current" /> {loading ? 'Loading...' : 'Start Briefing'}</>
        )}
      </button>
    </div>
  )
}
