import { useEffect, useState, useRef } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import api from '../services/api'

export default function ThreatGraph({ advisoryId }) {
  const [data, setData] = useState({ nodes: [], links: [] })
  const [loading, setLoading] = useState(true)
  const fgRef = useRef()
  const containerRef = useRef()
  const [dimensions, setDimensions] = useState({ width: 800, height: 400 })

  useEffect(() => {
    if (!containerRef.current) return
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth - 48, // accounting for padding
          height: 400
        })
      }
    }
    
    handleResize()
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  useEffect(() => {
    const endpoint = advisoryId ? `/advisories/${advisoryId}` : '/dashboard/stats'
    
    api.get(endpoint)
      .then(r => {
        const nodes = []
        const links = []
        
        if (advisoryId) {
          const adv = r.data
          // Root node
          nodes.push({ id: 'ADV', label: 'ADVISORY', name: 'Current Advisory', color: '#3b82f6', val: 8 })
          
          if (adv.sector) {
            nodes.push({ id: 'SEC', label: 'SECTOR', name: adv.sector.name, color: '#22c55e', val: 6 })
            links.push({ source: 'ADV', target: 'SEC' })
          }

          (adv.cve_ids || []).forEach((cve, i) => {
            const id = `cve-${i}`
            nodes.push({ id, label: 'CVE', name: cve, color: '#ef4444', val: 5 })
            links.push({ source: 'ADV', target: id })
          });

          (adv.mitre_ttps || []).forEach((ttp, i) => {
            const id = `ttp-${i}`
            nodes.push({ id, label: 'TTP', name: ttp, color: '#a855f7', val: 5 })
            links.push({ source: 'ADV', target: id })
          });

          (adv.apt_groups || []).forEach((apt, i) => {
            const id = `apt-${i}`
            nodes.push({ id, label: 'APT', name: apt, color: '#facc15', val: 6 })
            links.push({ source: 'ADV', target: id })
          });

          (adv.attack_types || []).forEach((at, i) => {
            const id = `at-${i}`
            nodes.push({ id, label: 'ATTACK', name: at, color: '#f97316', val: 4 })
            links.push({ source: 'ADV', target: id })
          })
        }
        
        setData({ nodes, links })
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [advisoryId])

  useEffect(() => {
    if (fgRef.current && data.nodes.length > 0) {
      fgRef.current.d3Force('link').distance(80)
      setTimeout(() => fgRef.current.zoomToFit(400, 80), 300)
    }
  }, [data])

  if (loading) return null

  return (
    <div className="card p-6" ref={containerRef}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-bold text-white">Threat Relationship Graph</h2>
          <p className="text-xs text-slate-500 mt-1">Structural view of threat components</p>
        </div>
        <div className="flex gap-4 text-[9px] font-bold uppercase tracking-widest">
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-blue-500"/> Advisory</div>
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-red-500"/> CVE</div>
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-green-500"/> Sector</div>
        </div>
      </div>
      
      <div className="h-[400px] bg-dark-900/40 rounded-xl border border-dark-600 overflow-hidden relative">
        {data.nodes.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center text-slate-600 text-sm">
                No relationship data available
            </div>
        ) : (
            <ForceGraph2D
                ref={fgRef}
                graphData={data}
                width={dimensions.width}
                height={400}
                backgroundColor="rgba(0,0,0,0)"
                nodeColor={n => n.color}
                nodeRelSize={4}
                nodeVal={n => n.val}
                linkColor={() => "#334155"}
                linkWidth={1.5}
                linkDirectionalParticles={2}
                linkDirectionalParticleSpeed={0.005}
                nodeCanvasObject={(node, ctx, globalScale) => {
                  const label = node.name;
                  const fontSize = 12/globalScale;
                  ctx.font = `${fontSize}px Inter, sans-serif`;
                  ctx.textAlign = 'center';
                  ctx.textBaseline = 'middle';
                  ctx.fillStyle = node.color;
                  
                  // Draw circle
                  const r = Math.sqrt(node.val || 1) * 4;
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false);
                  ctx.fill();

                  // Draw text
                  if (globalScale > 1.5) {
                    ctx.fillStyle = '#f1f5f9';
                    ctx.fillText(label, node.x, node.y + r + fontSize + 2);
                  }
                }}
                nodeCanvasObjectMode={() => 'replace'}
            />
        )}
      </div>
    </div>
  )
}
