import React from 'react'
import { useTheme } from '../context/ThemeContext'
import { Sun, Moon, Sparkles, Monitor, Sliders } from 'lucide-react'

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
    </div>
  )
}
