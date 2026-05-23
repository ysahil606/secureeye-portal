import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps'
import { scaleLinear } from 'd3-scale'
import api from '../services/api'

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

export default function ThreatHeatmap() {
  const [stats, setStats] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    const fetchStats = () => {
      api.get('/dashboard/geo-stats')
        .then(r => setStats(r.data))
        .catch(() => {})
        .finally(() => setLoading(false))
    }
    
    fetchStats()
    const interval = setInterval(fetchStats, 10000)
    return () => clearInterval(interval)
  }, [])

  const maxCount = stats.length > 0 ? Math.max(...stats.map(s => s.count)) : 1
  const colorScale = scaleLinear()
    .domain([0, maxCount])
    .range(["#3b82f6", "#ef4444"])

  if (loading) return (
    <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 md:p-8 shadow-2xl relative overflow-hidden h-[480px] flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
    </div>
  )

  return (
    <div className="bg-dark-900/60 backdrop-blur-xl border border-white/5 rounded-3xl p-6 md:p-8 shadow-2xl relative overflow-hidden animate-in slide-in-from-bottom-8 fade-in duration-1000 delay-700 fill-mode-both">
      <div className="absolute top-0 left-0 w-40 h-40 bg-red-500/10 blur-3xl rounded-full" />
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-8 relative z-10 gap-4">
        <h2 className="text-xs font-black uppercase tracking-[0.2em] text-slate-400 flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-red-500/20 flex items-center justify-center border border-red-500/30">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
          </div>
          Global Threat Heatmap
        </h2>
        <div className="flex gap-4 text-[10px] font-bold uppercase tracking-widest bg-dark-950/80 px-4 py-2 rounded-xl border border-white/5 shadow-inner">
            <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_8px_#3b82f6]"/> Low Density</div>
            <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_#ef4444]"/> High Density</div>
        </div>
      </div>

      <div className="h-[400px] bg-dark-950/40 rounded-xl border border-dark-600 overflow-hidden relative shadow-inner">
        <ComposableMap 
            projection="geoEqualEarth"
            projectionConfig={{ scale: 170, center: [0, 10] }}
            width={800}
            height={400}
            style={{ width: "100%", height: "100%" }}
        >
          <Geographies geography={geoUrl}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#111827"
                  stroke="#1e293b"
                  strokeWidth={0.5}
                  style={{
                    default: { outline: "none" },
                    hover: { fill: "#1f2937", outline: "none" },
                    pressed: { outline: "none" },
                  }}
                />
              ))
            }
          </Geographies>
          {stats.map(({ country, code, lat, lon, count }) => (
            <Marker 
              key={code} 
              coordinates={[lon, lat]}
              onClick={() => navigate('/iocs', { state: { search: country } })}
              className="cursor-pointer group"
            >
              <circle 
                r={Math.min(4 + (count * 2), 15)} 
                fill={colorScale(count)} 
                fillOpacity={0.4}
                stroke={colorScale(count)}
                strokeWidth={1}
                className="animate-pulse group-hover:fillOpacity-[0.8] transition-all" 
              />
              <circle 
                r={2} 
                fill={colorScale(count)} 
              />
              <title>{`${country}: ${count} IOCs`}</title>
            </Marker>
          ))}
        </ComposableMap>
        
        {/* Subtle decorative grid overlay */}
        <div className="absolute inset-0 pointer-events-none opacity-[0.03]" 
             style={{ backgroundImage: 'radial-gradient(#3b82f6 1px, transparent 1px)', backgroundSize: '20px 20px' }} />
      </div>
    </div>
  )
}
