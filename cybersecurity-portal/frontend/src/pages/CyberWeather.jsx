import { useState, useEffect, useRef, useMemo } from 'react'
import Globe from 'react-globe.gl'
import { Activity, Radio, Crosshair, AlertTriangle } from 'lucide-react'
import api from '../services/api'

// Fake HQ location (e.g. New York)
const HQ_COORD = { lat: 40.7128, lng: -74.0060 }

// Some realistic rough coordinates for threat origins
const THREAT_REGIONS = [
  { name: 'Moscow, Russia', lat: 55.7558, lng: 37.6173 },
  { name: 'St. Petersburg, Russia', lat: 59.9311, lng: 30.3609 },
  { name: 'Beijing, China', lat: 39.9042, lng: 116.4074 },
  { name: 'Shanghai, China', lat: 31.2304, lng: 121.4737 },
  { name: 'Pyongyang, North Korea', lat: 39.0392, lng: 125.7625 },
  { name: 'Tehran, Iran', lat: 35.6892, lng: 51.3890 },
  { name: 'Bucharest, Romania', lat: 44.4268, lng: 26.1025 },
  { name: 'Kyiv, Ukraine', lat: 50.4501, lng: 30.5234 },
  { name: 'Sao Paulo, Brazil', lat: -23.5505, lng: -46.6333 },
  { name: 'Lagos, Nigeria', lat: 6.5244, lng: 3.3792 },
  { name: 'Jakarta, Indonesia', lat: -6.2088, lng: 106.8456 },
  { name: 'Mumbai, India', lat: 19.0760, lng: 72.8777 },
  { name: 'Frankfurt, Germany', lat: 50.1109, lng: 8.6821 },
  { name: 'Amsterdam, Netherlands', lat: 52.3676, lng: 4.9041 },
]

export default function CyberWeather() {
  const globeRef = useRef()
  const [windowSize, setWindowSize] = useState({ width: window.innerWidth, height: window.innerHeight })
  const [arcs, setArcs] = useState([])
  const [logs, setLogs] = useState([])
  const [feedQueue, setFeedQueue] = useState([])
  
  useEffect(() => {
    const handleResize = () => setWindowSize({ width: window.innerWidth, height: window.innerHeight })
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  // Auto-rotate the globe slowly
  useEffect(() => {
    if (globeRef.current) {
      globeRef.current.controls().autoRotate = true
      globeRef.current.controls().autoRotateSpeed = 0.5
      globeRef.current.pointOfView({ lat: 20, lng: 0, altitude: 2.5 })
    }
  }, [])

  // 1. Fetch raw feed data
  useEffect(() => {
    const fetchFeeds = async () => {
      try {
        const r = await api.get('/admin/iocs/raw-feed', { params: { limit: 100 } })
        if (r.data && r.data.iocs) {
          // Shuffle the IOCs to randomize the feed
          const shuffled = [...r.data.iocs].sort(() => 0.5 - Math.random())
          setFeedQueue(shuffled)
        }
      } catch (e) {
        console.error("Failed to load global threats", e)
      }
    }
    fetchFeeds()
    // Re-fetch every 5 minutes
    const fetchInterval = setInterval(fetchFeeds, 5 * 60 * 1000)
    return () => clearInterval(fetchInterval)
  }, [])

  // 2. Process feed queue one by one to create a live streaming effect
  useEffect(() => {
    if (feedQueue.length === 0) return

    const processNextThreat = () => {
      setFeedQueue(prev => {
        if (prev.length === 0) return prev
        const threat = prev[0]
        // Push the item to the back of the queue so it infinitely loops
        const remaining = [...prev.slice(1), threat]

        // Assign random origin
        const region = THREAT_REGIONS[Math.floor(Math.random() * THREAT_REGIONS.length)]
        
        // Jitter the coordinates slightly so they don't all stack perfectly
        const jitterLat = region.lat + (Math.random() - 0.5) * 5
        const jitterLng = region.lng + (Math.random() - 0.5) * 5

        const newArc = {
          startLat: jitterLat,
          startLng: jitterLng,
          endLat: HQ_COORD.lat,
          endLng: HQ_COORD.lng,
          color: threat.severity === 'critical' ? '#ef4444' : (threat.severity === 'high' ? '#f97316' : '#a855f7'),
          value: threat.value,
          feed: threat.feed,
          type: threat.ioc_type
        }

        setArcs(currentArcs => {
          const next = [...currentArcs, newArc]
          // Keep only last 50 arcs on screen to maintain performance
          if (next.length > 50) return next.slice(next.length - 50)
          return next
        })

        setLogs(currentLogs => {
          const newLog = {
            id: Date.now(),
            time: new Date().toLocaleTimeString([], { hour12: false }),
            text: `[${threat.feed.toUpperCase()}] ${threat.ioc_type.toUpperCase()} DETECTED: ${threat.value}`,
            severity: threat.severity
          }
          const next = [newLog, ...currentLogs]
          if (next.length > 30) return next.slice(0, 30)
          return next
        })

        return remaining
      })
    }

    // Process a new threat every 1.5 to 3 seconds for dramatic effect
    const delay = Math.random() * 1500 + 1500
    const timeoutId = setTimeout(processNextThreat, delay)

    return () => clearTimeout(timeoutId)
  }, [feedQueue])


  return (
    <div className="relative w-full overflow-hidden rounded-3xl border border-white/5 bg-[#020617] shadow-2xl" style={{ height: 'calc(100vh - 120px)' }}>
      
      {/* 3D Globe Canvas */}
      <div className="absolute inset-0 z-0">
        <Globe
          ref={globeRef}
          width={windowSize.width}
          height={windowSize.height - 120}
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          backgroundColor="#020617"
          arcsData={arcs}
          arcStartLat={d => d.startLat}
          arcStartLng={d => d.startLng}
          arcEndLat={d => d.endLat}
          arcEndLng={d => d.endLng}
          arcColor={d => [d.color, d.color]}
          arcDashLength={0.4}
          arcDashGap={0.2}
          arcDashAnimateTime={1500}
          arcStroke={0.7}
          ringsData={[HQ_COORD]}
          ringLat={d => d.lat}
          ringLng={d => d.lng}
          ringColor={() => '#3b82f6'}
          ringMaxRadius={5}
          ringPropagationSpeed={3}
          ringRepeatPeriod={1000}
        />
      </div>

      {/* Overlays / UI */}
      <div className="absolute inset-0 z-10 pointer-events-none">
        {/* HUD Top Left */}
        <div className="absolute top-6 left-6 flex items-center gap-4">
          <div className="w-12 h-12 bg-dark-900/80 backdrop-blur-md rounded-xl border border-blue-500/30 flex items-center justify-center shadow-[0_0_20px_rgba(59,130,246,0.3)]">
            <Crosshair className="w-6 h-6 text-blue-400 animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400 uppercase tracking-widest">Global Threat Map</h1>
            <div className="flex items-center gap-2 mt-1">
              <div className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
              <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">Live Orbital Feed</span>
            </div>
          </div>
        </div>

        {/* Live Attack Feed Sidebar */}
        <div className="absolute top-6 right-6 bottom-6 w-80 bg-dark-900/70 backdrop-blur-xl border border-white/10 rounded-2xl p-4 flex flex-col shadow-2xl pointer-events-auto">
          <div className="flex items-center gap-2 mb-4 pb-3 border-b border-white/5">
            <Radio className="w-4 h-4 text-red-400 animate-pulse" />
            <h2 className="text-sm font-black text-white uppercase tracking-wider">Attack Log</h2>
            <span className="ml-auto text-[10px] font-bold text-slate-500 bg-dark-800 px-2 py-1 rounded-lg">Real-Time</span>
          </div>

          <div className="flex-1 overflow-y-auto pr-2 space-y-2 custom-scrollbar">
            {logs.length === 0 && (
              <div className="text-xs text-slate-500 italic text-center mt-10 flex flex-col items-center">
                <Activity className="w-6 h-6 text-slate-600 mb-2 animate-spin" />
                Initializing Threat Sensors...
              </div>
            )}
            
            {logs.map(log => {
              const isCritical = log.severity === 'critical'
              return (
                <div key={log.id} 
                  className="flex flex-col p-2.5 rounded-xl border animate-in slide-in-from-right-4 fade-in duration-300"
                  style={{
                    background: isCritical ? 'rgba(239,68,68,0.1)' : 'rgba(255,255,255,0.03)',
                    borderColor: isCritical ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)'
                  }}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono text-slate-400">{log.time}</span>
                    {isCritical && <AlertTriangle className="w-3 h-3 text-red-500" />}
                  </div>
                  <div className="text-[11px] font-mono leading-relaxed break-all" 
                    style={{ color: isCritical ? '#fca5a5' : '#cbd5e1' }}>
                    {log.text}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Global Statistics Footer */}
        <div className="absolute bottom-6 left-6 bg-dark-900/80 backdrop-blur-md border border-white/10 rounded-2xl p-4 shadow-xl flex gap-6">
          <div>
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Active Arcs</div>
            <div className="text-xl font-black text-blue-400 font-mono">{arcs.length}</div>
          </div>
          <div className="w-px bg-white/10" />
          <div>
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Queue</div>
            <div className="text-xl font-black text-purple-400 font-mono">{feedQueue.length}</div>
          </div>
          <div className="w-px bg-white/10" />
          <div>
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Defense Node</div>
            <div className="text-sm font-bold text-green-400 mt-1">ONLINE</div>
          </div>
        </div>
      </div>

    </div>
  )
}
