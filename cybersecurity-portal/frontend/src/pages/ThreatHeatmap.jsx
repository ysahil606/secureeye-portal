import { useEffect, useState } from 'react'
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps'
import { scaleLinear } from 'd3-scale'
import api from '../services/api'

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

export default function ThreatHeatmap() {
  const [stats, setStats] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/dashboard/geo-stats')
      .then(r => setStats(r.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const maxCount = stats.length > 0 ? Math.max(...stats.map(s => s.count)) : 1
  const colorScale = scaleLinear()
    .domain([0, maxCount])
    .range(["#3b82f6", "#ef4444"])

  if (loading) return (
    <div className="card p-6 h-[480px] flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
    </div>
  )

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            Global Threat Heatmap
          </h2>
          <p className="text-xs text-slate-500 mt-1">Origin of active indicators based on automated geo-enrichment</p>
        </div>
        <div className="flex gap-4 text-[10px] font-bold uppercase tracking-widest bg-dark-800/50 px-3 py-1.5 rounded-lg border border-dark-600">
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-blue-500"/> Low Density</div>
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-500"/> High Density</div>
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
            <Marker key={code} coordinates={[lon, lat]}>
              <circle 
                r={Math.min(4 + (count * 2), 15)} 
                fill={colorScale(count)} 
                fillOpacity={0.4}
                stroke={colorScale(count)}
                strokeWidth={1}
                className="animate-pulse" 
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
