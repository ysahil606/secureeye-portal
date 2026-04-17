import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../services/api'

// Simple mock of the MITRE Matrix structure
const TACTICS = [
  { id: 'initial-access', name: 'Initial Access', techniques: ['T1190', 'T1566', 'T1133', 'T1078', 'T1189', 'T1195'] },
  { id: 'execution', name: 'Execution', techniques: ['T1059', 'T1204', 'T1053', 'T1106', 'T1047', 'T1569'] },
  { id: 'persistence', name: 'Persistence', techniques: ['T1098', 'T1136', 'T1543', 'T1547', 'T1037', 'T1137'] },
  { id: 'defense-evasion', name: 'Defense Evasion', techniques: ['T1562', 'T1070', 'T1202', 'T1036', 'T1027', 'T1218'] },
  { id: 'credential-access', name: 'Credential Access', techniques: ['T1110', 'T1003', 'T1555', 'T1212', 'T1552', 'T1558'] },
  { id: 'exfiltration', name: 'Exfiltration', techniques: ['T1020', 'T1041', 'T1011', 'T1052', 'T1048', 'T1567'] },
]

export default function MITREMatrix() {
  const navigate = useNavigate()
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/apt/mitre/heatmap')
      .then(r => setStats(r.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const getIntensity = (techId) => {
    const count = stats[techId] || 0
    if (count === 0) return 'bg-dark-800 text-slate-600 border-dark-700'
    if (count < 35)  return 'bg-blue-600/40 text-blue-100 border-blue-500/50'
    return 'bg-red-600/40 text-white border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]'
  }

  if (loading) return null

  return (
    <div className="card p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white uppercase tracking-tight">MITRE ATT&CK Matrix Heatmap</h2>
          <p className="text-xs text-slate-500 mt-1">Real-time technique coverage based on active advisories</p>
        </div>
        <div className="flex gap-4 text-[9px] font-bold uppercase tracking-widest">
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-sm bg-dark-800 border border-dark-600"/> Inactive</div>
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-sm bg-blue-600/40 border border-blue-500/50"/> Emerging</div>
            <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-sm bg-red-600/40 border border-red-500/50"/> Highly Active</div>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {TACTICS.map(tactic => (
          <div key={tactic.id} className="space-y-2">
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest border-b border-dark-600 pb-1.5 mb-2">
                {tactic.name}
            </div>
            <div className="space-y-2">
              {tactic.techniques.map(tech => (
                <button key={tech} 
                  onClick={() => navigate(`/advisories?mitre_ttp=${tech}`)}
                  className={`w-full text-left p-2 rounded border text-[10px] font-mono flex flex-col transition-all hover:scale-[1.02] active:scale-[0.98] ${getIntensity(tech)}`}
                  title={`${stats[tech] || 0} occurrences`}>
                  <span className="font-bold">{tech}</span>
                  {stats[tech] > 0 && <span className="mt-1 opacity-70">{stats[tech]} hits</span>}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
