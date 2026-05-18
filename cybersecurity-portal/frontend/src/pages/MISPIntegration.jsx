import { Shield, ExternalLink, RefreshCw, Database, Terminal } from 'lucide-react'

export default function MISPIntegration() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">MISP Integration</h1>
          <p className="text-slate-400 mt-1">Malware Information Sharing Platform & Open Threat Exchange</p>
        </div>
        <button className="btn-primary flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Sync All Instances
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card p-6 border-l-4 border-blue-500">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-blue-500" />
            </div>
            <div>
              <h3 className="font-bold text-white">CIRCL MISP OSINT</h3>
              <p className="text-xs text-slate-500">Public OSINT Feed</p>
            </div>
            <span className="ml-auto px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/10 text-green-500 uppercase">Connected</span>
          </div>
          <p className="text-sm text-slate-400 mb-6">
            Pulls high-fidelity IOCs including malicious IPs, domains, and file hashes from the Computer Incident Response Center Luxembourg.
          </p>
          <div className="flex items-center justify-between text-xs">
            <div className="flex gap-4">
              <span className="text-slate-500"><Database className="w-3 h-3 inline mr-1" /> 2.4k IOCs</span>
              <span className="text-slate-500"><RefreshCw className="w-3 h-3 inline mr-1" /> 15m interval</span>
            </div>
            <a href="https://www.circl.lu/" target="_blank" rel="noreferrer" className="text-blue-400 hover:underline flex items-center gap-1">
              Source <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>

        <div className="card p-6 border-l-4 border-purple-500">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 bg-purple-500/10 rounded-lg flex items-center justify-center">
              <Network className="w-5 h-5 text-purple-500" />
            </div>
            <div>
              <h3 className="font-bold text-white">AlienVault OTX</h3>
              <p className="text-xs text-slate-500">Open Threat Exchange</p>
            </div>
            <span className="ml-auto px-2 py-0.5 rounded text-[10px] font-bold bg-green-500/10 text-green-500 uppercase">Connected</span>
          </div>
          <p className="text-sm text-slate-400 mb-6">
            Synchronizes with AlienVault OTX pulses to ingest community-sourced indicators of compromise and threat actor patterns.
          </p>
          <div className="flex items-center justify-between text-xs">
            <div className="flex gap-4">
              <span className="text-slate-500"><Database className="w-3 h-3 inline mr-1" /> 5.1k IOCs</span>
              <span className="text-slate-500"><RefreshCw className="w-3 h-3 inline mr-1" /> 15m interval</span>
            </div>
            <a href="https://otx.alienvault.com/" target="_blank" rel="noreferrer" className="text-blue-400 hover:underline flex items-center gap-1">
              Portal <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="bg-dark-700/50 px-6 py-4 border-b border-dark-600 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-bold text-white uppercase tracking-wider">Live MISP Log Stream</span>
        </div>
        <div className="p-6 font-mono text-xs space-y-2 bg-black/20">
          <div className="flex gap-3">
            <span className="text-slate-600">[2026-05-18 15:15:02]</span>
            <span className="text-blue-400">INFO</span>
            <span className="text-slate-300">Synchronizing CIRCL manifest...</span>
          </div>
          <div className="flex gap-3 text-green-400/80">
            <span className="text-slate-600">[2026-05-18 15:15:05]</span>
            <span className="text-green-400">SUCCESS</span>
            <span className="text-slate-300">Ingested 142 new attributes from event 5f2a1...</span>
          </div>
          <div className="flex gap-3">
            <span className="text-slate-600">[2026-05-18 15:15:10]</span>
            <span className="text-blue-400">INFO</span>
            <span className="text-slate-300">Polling AlienVault OTX API...</span>
          </div>
        </div>
      </div>
    </div>
  )
}
