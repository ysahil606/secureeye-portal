import { useState, useCallback } from 'react'
import { 
  Cpu, Globe, ShieldAlert, ShieldCheck, Terminal, Upload, 
  Link as LinkIcon, AlertTriangle, Info, Loader2, Scan, 
  ExternalLink, Activity, Server, Database, Lock, Download,
  Copy, History, Trash2
} from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'
import clsx from 'clsx'

export default function DeepScan() {
  const [activeTab, setActiveTab] = useState('link')
  const [url, setUrl] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [scanningStatus, setScanningStatus] = useState('')
  const [sandboxMode, setSandboxMode] = useState('basic') // 'basic' or 'advanced'
  const [scanHistory, setScanHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('deepscan_history') || '[]') } catch { return [] }
  })

  const rememberScan = useCallback((entry) => {
    setScanHistory(prev => {
      const next = [entry, ...prev].slice(0, 8)
      localStorage.setItem('deepscan_history', JSON.stringify(next))
      return next
    })
  }, [])

  const normalizeUrl = (value) => {
    const trimmed = value.trim()
    if (!trimmed) return ''
    return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  }

  const copyReport = async () => {
    if (!result) return
    await navigator.clipboard.writeText(JSON.stringify(result.data, null, 2))
    toast.success('Report copied')
  }

  const downloadReport = () => {
    if (!result) return
    const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' })
    const objectUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = `deepscan-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(objectUrl)
  }

  const clearHistory = () => {
    localStorage.removeItem('deepscan_history')
    setScanHistory([])
    toast.success('Scan history cleared')
  }

  const handleScanUrl = async (e) => {
    e.preventDefault()
    const targetUrl = normalizeUrl(url)
    if (!targetUrl) return
    setUrl(targetUrl)
    setLoading(true)
    setResult(null)
    setScanningStatus(sandboxMode === 'advanced' ? 'Initializing Virtual Box...' : 'Starting Static Analysis...')
    
    try {
      if (sandboxMode === 'advanced') {
        setTimeout(() => setScanningStatus('Analyzing DNS & IP Reputation...'), 1000)
        setTimeout(() => setScanningStatus('Checking SSL/TLS Certificate...'), 2000)
        setTimeout(() => setScanningStatus('Scanning for Phishing Patterns...'), 3000)
        setTimeout(() => setScanningStatus('Generating AI Verdict...'), 4500)
      } else {
        setTimeout(() => setScanningStatus('Fetching Domain Info...'), 1000)
        setTimeout(() => setScanningStatus('Quick Static Check...'), 2500)
      }

      const formData = new FormData()
      formData.append('url', targetUrl)
      formData.append('mode', sandboxMode)
      
      const res = await api.post('/sandbox/scan-url', formData)
      setResult({ type: 'url', data: res.data })
      rememberScan({
        type: 'url',
        label: targetUrl,
        verdict: res.data.verdict || 'Unknown',
        mode: sandboxMode,
        scannedAt: new Date().toISOString(),
      })
    } catch (err) {
      toast.error('Scan failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setLoading(false)
      setScanningStatus('')
    }
  }

  const handleScanFile = async (e) => {
    e.preventDefault()
    if (!file) return
    setLoading(true)
    setResult(null)
    setScanningStatus(sandboxMode === 'advanced' ? 'Spinning up Isolated Sandbox...' : 'Running Fast Static Scan...')

    try {
      if (sandboxMode === 'advanced') {
        setTimeout(() => setScanningStatus('Extracting Static Metadata...'), 1000)
        setTimeout(() => setScanningStatus('Computing SHA256 Signature...'), 2000)
        setTimeout(() => setScanningStatus('Searching Threat Intel Databases...'), 3000)
        setTimeout(() => setScanningStatus('Analyzing Suspicious Strings...'), 4500)
      } else {
        setTimeout(() => setScanningStatus('Calculating Hashes...'), 1000)
        setTimeout(() => setScanningStatus('Static Signature Check...'), 2500)
      }

      const formData = new FormData()
      formData.append('file', file)
      formData.append('mode', sandboxMode)
      
      const res = await api.post('/sandbox/scan-file', formData)
      setResult({ type: 'file', data: res.data })
      rememberScan({
        type: 'file',
        label: file.name,
        verdict: res.data.local_analysis?.verdict || 'Unknown',
        mode: sandboxMode,
        scannedAt: new Date().toISOString(),
      })
    } catch (err) {
      toast.error('File scan failed')
    } finally {
      setLoading(false)
      setScanningStatus('')
    }
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-blue-600/20 border border-blue-500/30 rounded-lg">
              <Cpu className="w-6 h-6 text-blue-400" />
            </div>
            DeepScan Lab
          </h1>
              <p className="text-slate-400 mt-1">Advanced multi-engine sandbox for suspicious links and files.</p>
        </div>
      </div>

      {/* Sandbox Mode Selector */}
      <div className="flex p-1 bg-dark-800 border border-dark-600 rounded-xl w-full sm:w-fit">
        <button
          onClick={() => setSandboxMode('basic')}
          className={clsx(
            "flex-1 sm:flex-none px-6 py-2 rounded-lg text-sm font-bold transition-all flex items-center gap-2",
            sandboxMode === 'basic' ? "bg-blue-600 text-white shadow-lg" : "text-slate-500 hover:text-slate-300"
          )}
        >
          <Activity className="w-4 h-4" />
          Basic Sandbox
        </button>
        <button
          onClick={() => setSandboxMode('advanced')}
          className={clsx(
            "flex-1 sm:flex-none px-6 py-2 rounded-lg text-sm font-bold transition-all flex items-center gap-2",
            sandboxMode === 'advanced' ? "bg-purple-600 text-white shadow-lg" : "text-slate-500 hover:text-slate-300"
          )}
        >
          <Server className="w-4 h-4" />
          Advanced Sandbox
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Input Section */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-dark-800 border border-dark-600 rounded-xl overflow-hidden shadow-xl">
            <div className="flex border-b border-dark-600">
              <button
                onClick={() => setActiveTab('link')}
                className={clsx(
                  'flex-1 py-3 px-4 text-sm font-medium transition-colors flex items-center justify-center gap-2',
                  activeTab === 'link' ? 'bg-blue-600/10 text-blue-400 border-b-2 border-blue-500' : 'text-slate-400 hover:text-white hover:bg-dark-700'
                )}
              >
                <LinkIcon className="w-4 h-4" />
                Scan Link
              </button>
              <button
                onClick={() => setActiveTab('file')}
                className={clsx(
                  'flex-1 py-3 px-4 text-sm font-medium transition-colors flex items-center justify-center gap-2',
                  activeTab === 'file' ? 'bg-blue-600/10 text-blue-400 border-b-2 border-blue-500' : 'text-slate-400 hover:text-white hover:bg-dark-700'
                )}
              >
                <Upload className="w-4 h-4" />
                Scan File
              </button>
            </div>

            <div className="p-6">
              {activeTab === 'link' ? (
                <form onSubmit={handleScanUrl} className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Target URL</label>
                    <div className="relative">
                      <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                      <input
                        type="text"
                        placeholder="https://suspicious-site.com/login"
                        className="w-full bg-dark-900 border border-dark-500 rounded-lg py-2.5 pl-10 pr-4 text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        disabled={loading}
                      />
                    </div>
                  </div>
                  <button
                    type="submit"
                    disabled={loading || !url}
                    className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-3 rounded-lg flex items-center justify-center gap-2 transition-all shadow-lg shadow-blue-600/20"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Scan className="w-5 h-5" />}
                    Deep Analysis
                  </button>
                </form>
              ) : (
                <form onSubmit={handleScanFile} className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Source File</label>
                    <div 
                      className={clsx(
                        "border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center gap-3 transition-all cursor-pointer",
                        file ? "border-blue-500/50 bg-blue-500/5" : "border-dark-500 hover:border-blue-500/50 hover:bg-blue-500/5"
                      )}
                      onClick={() => document.getElementById('file-upload').click()}
                      onDragOver={(e) => e.preventDefault()}
                      onDrop={(e) => {
                        e.preventDefault()
                        const dropped = e.dataTransfer.files?.[0]
                        if (dropped) setFile(dropped)
                      }}
                    >
                      <input
                        id="file-upload"
                        type="file"
                        className="hidden"
                        onChange={(e) => setFile(e.target.files[0])}
                        disabled={loading}
                      />
                      {file ? (
                        <>
                          <div className="w-12 h-12 bg-blue-600/20 rounded-full flex items-center justify-center">
                            <ShieldCheck className="w-6 h-6 text-blue-400" />
                          </div>
                          <div className="text-center">
                            <p className="text-sm font-medium text-white truncate max-w-[150px]">{file.name}</p>
                            <p className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB</p>
                          </div>
                        </>
                      ) : (
                        <>
                          <div className="w-12 h-12 bg-dark-700 rounded-full flex items-center justify-center">
                            <Upload className="w-6 h-6 text-slate-500" />
                          </div>
                          <p className="text-sm text-slate-400">Click or drag to upload</p>
                        </>
                      )}
                    </div>
                  </div>
                  <button
                    type="submit"
                    disabled={loading || !file}
                    className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-3 rounded-lg flex items-center justify-center gap-2 transition-all shadow-lg shadow-blue-600/20"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <ShieldAlert className="w-5 h-5" />}
                    Sandbox Run
                  </button>
                </form>
              )}
            </div>
          </div>

          <div className="bg-dark-800/50 border border-dark-600 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Info className="w-4 h-4 text-blue-400" />
              Scan checklist
            </h3>
            <ul className="space-y-3 text-xs text-slate-400">
              <li className="flex gap-2">
                <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-1 shrink-0" />
                <span>Isolated analysis avoids exposing your browser/machine.</span>
              </li>
              <li className="flex gap-2">
                <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-1 shrink-0" />
                <span>Heuristic engines detect phishing and malicious payloads.</span>
              </li>
              <li className="flex gap-2">
                <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-1 shrink-0" />
                <span>AI-powered verdict explains the risk in plain English.</span>
              </li>
            </ul>
          </div>

          {scanHistory.length > 0 && (
            <div className="bg-dark-800/50 border border-dark-600 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <History className="w-4 h-4 text-cyan-400" />
                  Recent scans
                </h3>
                <button onClick={clearHistory} className="text-slate-500 hover:text-red-400" title="Clear history">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
              <div className="space-y-2">
                {scanHistory.map((item, index) => (
                  <button
                    key={`${item.scannedAt}-${index}`}
                    onClick={() => item.type === 'url' ? setUrl(item.label) : null}
                    className="w-full rounded-lg border border-dark-600 bg-dark-900/60 p-3 text-left transition-colors hover:border-blue-500/40"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="truncate text-xs font-medium text-slate-200">{item.label}</span>
                      <span className="text-[10px] uppercase text-slate-500">{item.mode}</span>
                    </div>
                    <div className="mt-1 text-[10px] text-slate-500">{item.verdict}</div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Console / Result Section */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-black border border-dark-600 rounded-xl overflow-hidden shadow-2xl min-h-[500px] flex flex-col">
            <div className="bg-dark-800 px-4 py-2 border-b border-dark-600 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-500/50" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
                  <div className="w-3 h-3 rounded-full bg-green-500/50" />
                </div>
                <span className="text-[10px] font-mono text-slate-500 ml-4">VIRTUAL_BOX_v2.0 // DEEP_SCAN_PRO</span>
              </div>
              <div className="flex items-center gap-3">
                {result && !loading && (
                  <>
                    <button onClick={copyReport} className="text-slate-500 hover:text-blue-400" title="Copy JSON report">
                      <Copy className="w-4 h-4" />
                    </button>
                    <button onClick={downloadReport} className="text-slate-500 hover:text-blue-400" title="Download JSON report">
                      <Download className="w-4 h-4" />
                    </button>
                  </>
                )}
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-green-500">
                  <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                  SECURE_INSTANCE: RUNNING
                </div>
              </div>
            </div>

            <div className="flex-1 p-6 font-mono text-sm relative overflow-y-auto max-h-[600px]">
              {loading ? (
                <div className="absolute inset-0 flex flex-col items-center justify-center bg-black/60 z-10">
                  <div className="w-16 h-16 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mb-4" />
                  <p className="text-blue-400 animate-pulse text-lg">{scanningStatus}</p>
                </div>
              ) : !result ? (
                <div className="flex flex-col items-center justify-center h-full text-center space-y-4 opacity-40">
                  <Terminal className="w-12 h-12 text-slate-500" />
                  <div>
                    <p className="text-white">Awaiting Input...</p>
                    <p className="text-xs text-slate-500">Submit a link or file to start behavioral analysis.</p>
                  </div>
                </div>
              ) : (
                <div className="space-y-8 animate-in slide-in-from-bottom-4 duration-700">
                  {/* Verdict Badge */}
                  <div className={clsx(
                    "inline-flex items-center gap-3 px-6 py-3 rounded-xl border-2 text-xl font-black uppercase tracking-widest",
                    (result.data.verdict || result.data.local_analysis?.verdict) === 'Malicious' 
                      ? "bg-red-500/10 border-red-500 text-red-500" 
                      : (result.data.verdict || result.data.local_analysis?.verdict) === 'Suspicious' || (result.data.verdict || result.data.local_analysis?.verdict) === 'Review Required'
                        ? "bg-yellow-500/10 border-yellow-500 text-yellow-500"
                        : "bg-green-500/10 border-green-500 text-green-500"
                  )}>
                    {result.data.verdict || result.data.local_analysis?.verdict || 'Review Required'}
                  </div>

                  {/* AI Report */}
                  {result.data.ai_report && (
                    <div className="bg-blue-600/10 border border-blue-500/30 rounded-xl p-5 space-y-3">
                      <div className="flex items-center gap-2 text-blue-400 font-bold">
                        <Activity className="w-4 h-4" />
                        AI THREAT INTEL VERDICT
                      </div>
                      <p className="text-slate-300 leading-relaxed italic italic">
                        "{result.data.ai_report}"
                      </p>
                    </div>
                  )}

                  {/* Detailed Stats */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {result.type === 'url' ? (
                      <>
                        <div className="bg-dark-900/50 border border-dark-600 rounded-lg p-4 space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase">Target Domain</p>
                          <p className="text-white font-bold">{result.data.domain}</p>
                        </div>
                        <div className="bg-dark-900/50 border border-dark-600 rounded-lg p-4 space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase">Resolved IP</p>
                          <p className="text-white font-bold">{result.data.ip}</p>
                        </div>
                        <div className="bg-dark-900/50 border border-dark-600 rounded-lg p-4 space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase">SSL Issuer</p>
                          <p className="text-white font-bold truncate">{result.data.ssl_issuer || 'None'}</p>
                        </div>
                        <div className="bg-dark-900/50 border border-dark-600 rounded-lg p-4 space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase">Phishing Score</p>
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-dark-600 rounded-full overflow-hidden">
                              <div className="h-full bg-blue-500" style={{ width: `${result.data.phishing_score}%` }} />
                            </div>
                            <span className="text-white font-bold">{result.data.phishing_score ?? 0}/100</span>
                          </div>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="bg-dark-900/50 border border-dark-600 rounded-lg p-4 space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase">File Size</p>
                          <p className="text-white font-bold">{result.data.local_analysis.size_kb} KB</p>
                        </div>
                        <div className="bg-dark-900/50 border border-dark-600 rounded-lg p-4 space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase">Local Static Health</p>
                          <p className={clsx("font-bold", result.data.local_analysis.verdict.includes('Clean') ? 'text-green-400' : 'text-yellow-400')}>
                            {result.data.local_analysis.verdict}
                          </p>
                        </div>
                        <div className="md:col-span-2 bg-dark-900/50 border border-dark-600 rounded-lg p-4 space-y-1">
                          <p className="text-[10px] text-slate-500 uppercase">SHA256 Hash</p>
                          <p className="text-white font-mono text-[10px] break-all">{result.data.local_analysis.sha256}</p>
                        </div>
                      </>
                    )}
                  </div>

                  {/* Patterns / Strings */}
                  <div className="space-y-3">
                    <h4 className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">
                      {result.type === 'url' ? 'Detected Suspicious Patterns' : 'Suspicious Features / Strings'}
                    </h4>
                    <div className="space-y-2">
                      {(result.type === 'url' ? (result.data.suspicious_patterns || []) : (result.data.local_analysis?.suspicious_features || [])).map((p, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs text-yellow-500/80">
                          <AlertTriangle className="w-3 h-3" />
                          <span>{p}</span>
                        </div>
                      ))}
                      {result.type === 'file' && (result.data.local_analysis?.strings_sample || []).length > 0 && (
                        <div className="mt-4 p-3 bg-dark-900 rounded-lg border border-dark-600">
                           <p className="text-[10px] text-slate-500 mb-2 uppercase">Strings Extraction (ASCII)</p>
                           <div className="flex flex-wrap gap-2">
                             {(result.data.local_analysis?.strings_sample || []).map((s, i) => (
                               <span key={i} className="text-[10px] bg-dark-600 px-1.5 py-0.5 rounded text-slate-300">{s}</span>
                             ))}
                           </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Cloud Report Link */}
                  {result.data.cloud_analysis?.found && (
                    <div className="bg-blue-600/20 border border-blue-500/50 rounded-xl p-4 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center">
                          <Database className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <p className="text-sm font-bold text-white">Cloud Report Found</p>
                          <p className="text-xs text-blue-300">Detailed behavioral analysis available on Hybrid Analysis</p>
                        </div>
                      </div>
                      <a 
                        href={result.data.cloud_analysis.report_url} 
                        target="_blank" 
                        rel="noreferrer"
                        className="p-2 hover:bg-blue-500/30 rounded-lg transition-colors"
                      >
                        <ExternalLink className="w-5 h-5 text-blue-400" />
                      </a>
                    </div>
                  )}

                  {!result.data.cloud_analysis?.found && result.type === 'file' && (
                     <div className="p-4 bg-dark-800/50 rounded-lg text-xs text-slate-500 italic">
                       No existing cloud reports found for this file hash. local analysis only.
                     </div>
                  )}
                </div>
              )}
            </div>
            
            <div className="bg-dark-800 px-4 py-3 border-t border-dark-600 flex items-center justify-between text-[10px] font-mono">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-1.5">
                  <Server className="w-3 h-3 text-slate-500" />
                  <span className="text-slate-500">CPU_0_IDLE: 98%</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Database className="w-3 h-3 text-slate-500" />
                  <span className="text-slate-500">MEM_ALLOC: 412MB</span>
                </div>
              </div>
              <div className="flex items-center gap-1.5 text-blue-500">
                <Lock className="w-3 h-3" />
                <span>SANDBOX_ISOLATION: ACTIVE</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
