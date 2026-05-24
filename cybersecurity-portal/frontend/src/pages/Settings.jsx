import React, { useState, useEffect } from 'react'
import { useTheme } from '../context/ThemeContext'
import { useAuth } from '../context/AuthContext'
import api from '../services/api'
import { Sun, Moon, Sparkles, Monitor, Sliders, Cpu, Activity, Server } from 'lucide-react'

const themes = [
  { id: 'cyber-default', name: 'Cyber Default', color: '#3b82f6' },
  { id: 'neon-hacker', name: 'Neon Hacker', color: '#39ff14' },
  { id: 'red-team', name: 'Red Team', color: '#ff003c' },
  { id: 'blue-team', name: 'Blue Team', color: '#00bfff' },
  { id: 'vaporwave', name: 'Vaporwave', color: '#ff00ff' },
  { id: 'stealth-mode', name: 'Stealth Mode', color: '#a3a3a3' },
  { id: 'midnight-gold', name: 'Midnight Gold', color: '#ffc107' },
  { id: 'cyberpunk-city', name: 'Cyberpunk City', color: '#fcee21' },
]

export default function Settings() {
  const { theme, setTheme, lighting, setLighting } = useTheme()
  const { isAdmin } = useAuth()
  
  const [metrics, setMetrics] = useState({ cpu_load: 0, ram_usage_percent: 0, ram_total_gb: 0, ram_used_gb: 0, os: 'Unknown' })

  useEffect(() => {
    if (!isAdmin) return
    
    const fetchMetrics = async () => {
      try {
        const res = await api.get('/admin/system/metrics')
        setMetrics(res.data)
      } catch (err) {
        // Silently fail if endpoint isn't ready
      }
    }
    
    fetchMetrics()
    const interval = setInterval(fetchMetrics, 5000)
    return () => clearInterval(interval)
  }, [isAdmin])

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-fade-in-up">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-accent-primary to-accent-secondary flex items-center gap-3">
          <Sliders className="w-8 h-8 text-accent-primary" />
          System Settings
        </h1>
        <p className="text-slate-400 mt-2">Customize your portal experience and aesthetics.</p>
      </header>

      {/* Theme Selection */}
      <div className="card p-6">
        <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
          <Monitor className="w-5 h-5 text-accent-primary" />
          Theme Selection
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {themes.map(t => (
            <button
              key={t.id}
              onClick={() => setTheme(t.id)}
              className={`p-4 rounded-xl border transition-all duration-300 text-left flex flex-col gap-3 relative overflow-hidden group ${
                theme === t.id 
                  ? 'border-accent-primary bg-accent-primary/10 shadow-[0_0_15px_var(--neon-glow-pri)]' 
                  : 'border-white/10 hover:border-white/30 hover:bg-white/5'
              }`}
            >
              <div 
                className="w-full h-24 rounded-lg border border-white/10 mb-2 relative overflow-hidden"
                style={{ 
                  background: `linear-gradient(135deg, var(--bg-app) 0%, var(--bg-card) 100%)`,
                }}
              >
                 <div className="absolute inset-4 rounded flex items-center justify-center border border-dashed border-white/20 bg-dark-950/50 backdrop-blur-sm">
                    <span className="font-bold text-lg tracking-wider" style={{ color: t.color, textShadow: `0 0 10px ${t.color}80` }}>{t.name}</span>
                 </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="font-medium text-white">{t.name}</span>
                {theme === t.id && (
                  <Sparkles className="w-4 h-4 text-accent-primary" />
                )}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Lighting Control */}
      <div className="card p-6">
        <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
          <Sun className="w-5 h-5 text-accent-primary" />
          Global Lighting & Brightness
        </h2>
        
        <div className="max-w-xl">
          <div className="flex items-center gap-4 mb-2">
            <Moon className="w-5 h-5 text-slate-500" />
            <input 
              type="range" 
              min="0.5" 
              max="1.5" 
              step="0.05"
              value={lighting}
              onChange={(e) => setLighting(parseFloat(e.target.value))}
              className="flex-1 h-2 bg-dark-900 rounded-lg appearance-none cursor-pointer"
              style={{
                accentColor: 'var(--accent-primary)'
              }}
            />
            <Sun className="w-5 h-5 text-yellow-400" />
          </div>
          <div className="flex justify-between text-xs text-slate-400">
            <span>Dim (0.5)</span>
            <span>Default (1.0)</span>
            <span>Bright (1.5)</span>
          </div>
          
          <div className="mt-8 p-4 bg-dark-900/50 rounded-lg border border-white/5">
             <p className="text-sm text-slate-300">
               Lighting changes the global brightness filter applied to the entire application. 
               This setting is saved directly to your browser so it persists across sessions.
             </p>
          </div>
        </div>
      </div>

      {/* Admin System Telemetry */}
      {isAdmin && (
        <div className="card p-6 border-accent-secondary/30 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10">
            <Server className="w-32 h-32 text-accent-secondary" />
          </div>
          <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2 relative z-10">
            <Activity className="w-5 h-5 text-accent-secondary" />
            Live Server Telemetry (Admin Only)
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 relative z-10">
            {/* CPU Metric */}
            <div className="bg-dark-900/60 p-5 rounded-xl border border-white/5 flex flex-col justify-between">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2 text-slate-300 font-medium">
                  <Cpu className="w-4 h-4 text-cyan-400" /> CPU Load (1m Avg)
                </div>
                <span className="text-2xl font-black text-cyan-400">{metrics.cpu_load.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-dark-950 rounded-full h-3 mb-1 overflow-hidden border border-white/5">
                <div 
                  className="h-full rounded-full transition-all duration-1000 ease-out"
                  style={{ 
                    width: `${metrics.cpu_load}%`,
                    background: metrics.cpu_load > 80 ? '#ef4444' : metrics.cpu_load > 50 ? '#f59e0b' : '#22d3ee',
                    boxShadow: `0 0 10px ${metrics.cpu_load > 80 ? '#ef4444' : metrics.cpu_load > 50 ? '#f59e0b' : '#22d3ee'}`
                  }}
                ></div>
              </div>
            </div>

            {/* RAM Metric */}
            <div className="bg-dark-900/60 p-5 rounded-xl border border-white/5 flex flex-col justify-between">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2 text-slate-300 font-medium">
                  <Server className="w-4 h-4 text-purple-400" /> RAM Usage ({metrics.os})
                </div>
                <div className="text-right">
                  <span className="text-2xl font-black text-purple-400">{metrics.ram_usage_percent.toFixed(1)}%</span>
                  <div className="text-xs text-slate-500">{metrics.ram_used_gb.toFixed(1)}GB / {metrics.ram_total_gb.toFixed(1)}GB</div>
                </div>
              </div>
              <div className="w-full bg-dark-950 rounded-full h-3 mb-1 overflow-hidden border border-white/5">
                <div 
                  className="h-full rounded-full transition-all duration-1000 ease-out bg-gradient-to-r from-purple-500 to-fuchsia-500 shadow-[0_0_10px_rgba(168,85,247,0.5)]"
                  style={{ width: `${metrics.ram_usage_percent}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
