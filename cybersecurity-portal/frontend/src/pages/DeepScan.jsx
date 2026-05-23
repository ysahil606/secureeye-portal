import { useState, useCallback, useEffect } from 'react'
import { 
  Cpu, Globe, ShieldAlert, ShieldCheck, Terminal, Upload, 
  Link as LinkIcon, AlertTriangle, Info, Loader2, Scan, 
  ExternalLink, Activity, Server, Database, Lock, Download,
  Copy, History, Trash2, ChevronRight, CheckCircle2, Zap
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
  const [smartMode, setSmartMode] = useState(true) // The new Smart Switch feature
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
    toast.success('Report copied to clipboard', { style: { background: '#1e293b', color: '#fff' }})
  }

  const downloadReport = () => {
    if (!result) return
    const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' })
    const objectUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = `deepscan-intel-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(objectUrl)
  }

  const clearHistory = () => {
    localStorage.removeItem('deepscan_history')
    setScanHistory([])
    toast.success('History cleared', { style: { background: '#1e293b', color: '#fff' }})
  }

  const handleScanUrl = async (e) => {
    e.preventDefault()
    
    // Check if it's a hash (MD5, SHA-1, SHA-256)
    const isHash = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(url.trim())
    
    let targetUrl = url.trim()
    if (!isHash) {
       targetUrl = normalizeUrl(url)
    }
    
    if (!targetUrl) return
    setUrl(targetUrl)
    setLoading(true)
    setResult(null)
    setScanningStatus(smartMode ? 'Initializing Smart VM...' : 'Starting Static Analysis...')
    
    try {
      if (smartMode) {
        setTimeout(() => setScanningStatus(isHash ? 'Querying Threat Intelligence...' : 'Analyzing DNS & IP Reputation...'), 1000)
        setTimeout(() => setScanningStatus(isHash ? 'Checking Malware Signatures...' : 'Checking SSL/TLS Handshake...'), 2000)
        setTimeout(() => setScanningStatus(isHash ? 'Cross-referencing Cloud Sandboxes...' : 'Scanning for Phishing & Payloads...'), 3000)
        setTimeout(() => setScanningStatus('Synthesizing Threat Intel Verdict...'), 4500)
      } else {
        setTimeout(() => setScanningStatus(isHash ? 'Looking up basic reputation...' : 'Fetching Domain Info...'), 1000)
        setTimeout(() => setScanningStatus('Quick Static Check...'), 2500)
      }

      const formData = new FormData()
      formData.append('mode', smartMode ? 'advanced' : 'basic')
      
      let res;
      let resultType = 'url';
      
      if (isHash) {
        formData.append('hash', targetUrl)
        res = await api.post('/sandbox/scan-hash', formData)
        resultType = 'file' // Hash results share the same data structure as files
      } else {
        formData.append('url', targetUrl)
        res = await api.post('/sandbox/scan-url', formData)
        resultType = 'url'
      }
      
      setResult({ type: resultType, data: res.data })
      rememberScan({
        type: isHash ? 'hash' : 'url',
        label: targetUrl,
        verdict: (isHash ? res.data.cloud_analysis?.verdict : res.data.verdict) || 'Unknown',
        mode: smartMode ? 'advanced' : 'basic',
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
    setScanningStatus(smartMode ? 'Spinning up Smart Sandbox...' : 'Running Fast Static Scan...')

    try {
      if (smartMode) {
        setTimeout(() => setScanningStatus('Extracting Static Metadata...'), 1000)
        setTimeout(() => setScanningStatus('Computing Cryptographic Hashes...'), 2000)
        setTimeout(() => setScanningStatus('Querying Global Threat DBs...'), 3000)
        setTimeout(() => setScanningStatus('Dissecting File Signatures...'), 4500)
      } else {
        setTimeout(() => setScanningStatus('Calculating Hashes...'), 1000)
        setTimeout(() => setScanningStatus('Static Signature Check...'), 2500)
      }

      const formData = new FormData()
      formData.append('file', file)
      formData.append('mode', smartMode ? 'advanced' : 'basic')
      
      const res = await api.post('/sandbox/scan-file', formData)
      setResult({ type: 'file', data: res.data })
      rememberScan({
        type: 'file',
        label: file.name,
        verdict: res.data.local_analysis?.verdict || 'Unknown',
        mode: smartMode ? 'advanced' : 'basic',
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
    <div className="space-y-6 animate-in fade-in duration-700 min-h-screen text-slate-200">
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes scanline {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100%); }
        }
        .crt-overlay {
          background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
          background-size: 100% 4px, 3px 100%;
          pointer-events: none;
        }
        .radar-sweep {
          background: conic-gradient(from 0deg at 50% 50%, rgba(6, 182, 212, 0) 0%, rgba(6, 182, 212, 0) 60%, rgba(6, 182, 212, 0.8) 100%);
          animation: spin 2s linear infinite;
        }
        .glass-panel {
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border: 1px solid rgba(255, 255, 255, 0.05);
          box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
        }
      `}} />

      {/* Hero Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative overflow-hidden glass-panel rounded-3xl p-6">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none"></div>
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-purple-500/10 rounded-full blur-[80px] pointer-events-none"></div>
        
        <div className="relative z-10">
          <h1 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500 flex items-center gap-4 tracking-tight">
            <div className="p-3 bg-cyan-950/50 border border-cyan-500/30 rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.2)]">
              <Cpu className="w-8 h-8 text-cyan-400" />
            </div>
            DeepScan Lab
          </h1>

        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
        
        {/* Left Column: Controls */}
        <div className="xl:col-span-4 space-y-6">
          
          {/* Main Input Panel */}
          <div className="glass-panel rounded-2xl overflow-hidden relative">
            {/* Tab Header with Smart Toggle */}
            <div className="flex border-b border-slate-700/50 bg-slate-900/50">
              <button
                onClick={() => setActiveTab('link')}
                className={clsx(
                  'flex-1 py-4 px-4 text-sm font-bold transition-all flex items-center justify-center gap-2 relative',
                  activeTab === 'link' ? 'text-cyan-400 bg-cyan-950/20' : 'text-slate-500 hover:text-slate-300'
                )}
              >
                <LinkIcon className="w-4 h-4" />
                Text / IoC
                {activeTab === 'link' && <div className="absolute bottom-0 left-0 w-full h-0.5 bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.5)]"></div>}
              </button>
              <button
                onClick={() => setActiveTab('file')}
                className={clsx(
                  'flex-1 py-4 px-4 text-sm font-bold transition-all flex items-center justify-center gap-2 relative',
                  activeTab === 'file' ? 'text-cyan-400 bg-cyan-950/20' : 'text-slate-500 hover:text-slate-300'
                )}
              >
                <Upload className="w-4 h-4" />
                File Upload
                {activeTab === 'file' && <div className="absolute bottom-0 left-0 w-full h-0.5 bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.5)]"></div>}
              </button>
            </div>

            <div className="p-6">
              {/* Smart Switch */}
              <div className="flex items-center justify-between mb-6 p-3 bg-slate-900/60 rounded-xl border border-slate-700/50">
                <div className="flex items-center gap-2">
                  <div className={clsx("p-1.5 rounded-lg", smartMode ? "bg-cyan-500/20 text-cyan-400" : "bg-slate-800 text-slate-500")}>
                    <Activity className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-200">Smart Cloud Scan</p>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider">{smartMode ? 'Deep Analysis Active' : 'Local Static Only'}</p>
                  </div>
                </div>
                <button
                  onClick={() => setSmartMode(!smartMode)}
                  className={clsx(
                    "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-slate-900",
                    smartMode ? "bg-cyan-500" : "bg-slate-700"
                  )}
                >
                  <span
                    className={clsx(
                      "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                      smartMode ? "translate-x-6" : "translate-x-1"
                    )}
                  />
                </button>
              </div>
              {activeTab === 'link' ? (
                <form onSubmit={handleScanUrl} className="space-y-5">
                  <div className="space-y-3">
                    <label className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                      <Globe className="w-3.5 h-3.5 text-cyan-500" /> Target IoC (URL, IP, Hash)
                    </label>
                    <div className="relative group overflow-hidden rounded-xl">
                      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 h-[2px] w-0 bg-cyan-400 group-hover:w-full group-focus-within:w-full transition-all duration-500 ease-out pointer-events-none z-20 shadow-[0_0_10px_rgba(34,211,238,0.8)]"></div>
                      <input
                        type="text"
                        placeholder="https://site.com, 1.1.1.1, or e3b0c44..."
                        className="w-full relative bg-slate-900/80 border border-slate-700/80 rounded-xl py-3.5 pl-4 pr-4 text-white placeholder:text-slate-600 focus:outline-none focus:border-slate-700/80 transition-all font-mono text-sm z-10"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        disabled={loading}
                      />
                    </div>
                  </div>
                  <button
                    type="submit"
                    disabled={loading || !url}
                    className="w-full relative overflow-hidden bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-4 rounded-xl flex items-center justify-center gap-3 transition-all transform hover:scale-[1.02] active:scale-95 shadow-[0_0_20px_rgba(6,182,212,0.3)]"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Scan className="w-5 h-5" />}
                    INITIATE SCAN
                  </button>
                </form>
              ) : (
                <form onSubmit={handleScanFile} className="space-y-5">
                  <div className="space-y-3">
                    <label className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-cyan-500" /> Suspicious Payload
                    </label>
                    <div 
                      className={clsx(
                        "relative group border-2 border-dashed rounded-2xl p-10 flex flex-col items-center justify-center gap-4 transition-all cursor-pointer overflow-hidden",
                        file ? "border-cyan-500/50 bg-cyan-900/10" : "border-slate-700 hover:border-cyan-500/50 hover:bg-slate-800/50"
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
                          <div className="w-16 h-16 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 rounded-2xl flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.2)]">
                            <ShieldCheck className="w-8 h-8 text-cyan-400" />
                          </div>
                          <div className="text-center z-10">
                            <p className="text-base font-bold text-white truncate max-w-[200px]">{file.name}</p>
                            <p className="text-xs text-slate-400 mt-1 font-mono">{(file.size / 1024).toFixed(1)} KB</p>
                          </div>
                        </>
                      ) : (
                        <>
                          <div className="w-16 h-16 bg-slate-800/80 rounded-2xl flex items-center justify-center group-hover:scale-110 transition-transform">
                            <Upload className="w-8 h-8 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                          </div>
                          <p className="text-sm font-medium text-slate-400 group-hover:text-slate-300">Drag & drop or click to browse</p>
                        </>
                      )}
                    </div>
                  </div>
                  <button
                    type="submit"
                    disabled={loading || !file}
                    className="w-full relative overflow-hidden bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-4 rounded-xl flex items-center justify-center gap-3 transition-all transform hover:scale-[1.02] active:scale-95 shadow-[0_0_20px_rgba(6,182,212,0.3)]"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5" />}
                    DETONATE IN SANDBOX
                  </button>
                </form>
              )}
            </div>
          </div>

          {/* History Panel */}
          {scanHistory.length > 0 && (
            <div className="glass-panel rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest flex items-center gap-2">
                  <History className="w-4 h-4 text-cyan-500" /> Scan Log
                </h3>
                <button onClick={clearHistory} className="p-1.5 rounded-md hover:bg-slate-800 text-slate-500 hover:text-red-400 transition-colors" title="Clear history">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
              <div className="space-y-2 max-h-[250px] overflow-y-auto custom-scrollbar pr-1">
                {scanHistory.map((item, index) => (
                  <button
                    key={`${item.scannedAt}-${index}`}
                    onClick={() => item.type === 'url' ? setUrl(item.label) : null}
                    className="w-full group rounded-xl border border-slate-700/50 bg-slate-900/40 p-3 text-left transition-all hover:border-cyan-500/40 hover:bg-slate-800/60"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="truncate text-xs font-mono font-medium text-slate-300 group-hover:text-white transition-colors">{item.label}</span>
                      <span className="text-[9px] font-black tracking-widest uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">{item.mode}</span>
                    </div>
                    <div className="mt-2 flex items-center gap-2 text-[10px] uppercase font-bold tracking-wider">
                      <div className={clsx("w-2 h-2 rounded-full shadow-lg", 
                        item.verdict === 'Malicious' ? "bg-red-500 shadow-red-500/50" : 
                        item.verdict === 'Clean' ? "bg-green-500 shadow-green-500/50" : "bg-yellow-500 shadow-yellow-500/50")} />
                      <span className={clsx(
                        item.verdict === 'Malicious' ? "text-red-400" : 
                        item.verdict === 'Clean' ? "text-green-400" : "text-yellow-400"
                      )}>{item.verdict}</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Virtual Box Terminal HUD */}
        <div className="xl:col-span-8 flex flex-col min-h-[700px] relative rounded-3xl overflow-hidden border border-slate-700/60 shadow-[0_0_50px_rgba(0,0,0,0.5)] bg-[#050914]">
          {/* CRT Overlay Effect */}
          <div className="crt-overlay absolute inset-0 z-20"></div>

          {/* HUD Header */}
          <div className="bg-[#0a0f1c] px-5 py-3 border-b border-slate-700/60 flex items-center justify-between z-30 relative shadow-md">
            <div className="flex items-center gap-4">
            </div>
            <div className="flex items-center gap-4">
              {result && !loading && (
                <div className="flex items-center gap-2 mr-4">
                  <button onClick={copyReport} className="p-1.5 bg-slate-800/80 hover:bg-cyan-900/50 text-slate-400 hover:text-cyan-400 rounded transition-colors" title="Copy JSON">
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                  <button onClick={downloadReport} className="p-1.5 bg-slate-800/80 hover:bg-cyan-900/50 text-slate-400 hover:text-cyan-400 rounded transition-colors" title="Download JSON">
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

            </div>
          </div>

          {/* HUD Body */}
          <div className="flex-1 p-6 font-mono relative overflow-y-auto custom-scrollbar z-10 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-[#0a1128] to-[#03050a]">
            {loading ? (
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <div className="relative w-40 h-40 flex items-center justify-center">
                  <div className="absolute inset-0 rounded-full border border-cyan-500/20"></div>
                  <div className="absolute inset-4 rounded-full border border-cyan-500/30 border-dashed animate-[spin_10s_linear_infinite]"></div>
                  <div className="absolute inset-0 rounded-full radar-sweep"></div>
                  <ShieldAlert className="w-8 h-8 text-cyan-400 animate-pulse relative z-10" />
                </div>
                <div className="mt-8 text-center space-y-2">
                  <p className="text-cyan-400 text-sm font-bold tracking-widest uppercase animate-pulse">{scanningStatus}</p>
                  <p className="text-[10px] text-cyan-700 tracking-[0.2em]">BYPASSING ANTI-ANALYSIS... INJECTING HOOKS...</p>
                </div>
              </div>
            ) : !result ? (
              <div className="flex flex-col items-center justify-center h-full opacity-30 select-none">
                <Terminal className="w-16 h-16 text-cyan-500/50 mb-6" />

              </div>
            ) : (
              <div className="space-y-8 animate-in fade-in slide-in-from-bottom-8 duration-700 pb-10 max-w-4xl mx-auto">
                
                {/* HUD Verdict Header */}
                <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 border-b border-slate-700/50 pb-6">
                  <div className="space-y-2">
                    <p className="text-[10px] text-slate-500 tracking-widest uppercase">Final Intelligence Verdict</p>
                    <div className={clsx(
                      "inline-flex items-center gap-3 px-5 py-2.5 rounded-xl border-2 text-xl font-black uppercase tracking-[0.2em] shadow-lg",
                      (result.data.verdict || result.data.local_analysis?.verdict || result.data.cloud_analysis?.verdict) === 'Malicious' 
                        ? "bg-red-500/10 border-red-500 text-red-400 shadow-red-900/30" 
                        : (result.data.verdict || result.data.local_analysis?.verdict || result.data.cloud_analysis?.verdict)?.includes('Suspicious') || (result.data.verdict || result.data.local_analysis?.verdict || result.data.cloud_analysis?.verdict) === 'Review Required'
                          ? "bg-yellow-500/10 border-yellow-500 text-yellow-400 shadow-yellow-900/30"
                          : "bg-green-500/10 border-green-500 text-green-400 shadow-green-900/30"
                    )}>
                      {(result.data.verdict || result.data.local_analysis?.verdict || result.data.cloud_analysis?.verdict || 'Review Required')}
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-[10px] text-slate-500 tracking-widest uppercase mb-1">Target</p>
                    <p className="text-sm font-bold text-white max-w-xs truncate" title={result.type === 'url' ? result.data.domain : (file?.name || url)}>
                      {result.type === 'url' ? result.data.domain : (file?.name || url)}
                    </p>
                  </div>
                </div>

                {/* AI Threat Intel Summary */}
                {result.data.ai_report && (
                  <div className="relative overflow-hidden bg-gradient-to-br from-indigo-900/30 to-blue-900/10 border border-indigo-500/30 rounded-2xl p-6 shadow-xl">
                    <div className="absolute top-0 left-0 w-1 h-full bg-indigo-500 shadow-[0_0_15px_rgba(99,102,241,1)]"></div>
                    <div className="flex items-center gap-3 text-indigo-400 font-bold mb-3 tracking-widest uppercase text-xs">
                      <Activity className="w-4 h-4" /> AI Threat Intelligence Synthesis
                    </div>
                    <p className="text-slate-300 text-sm leading-relaxed tracking-wide">
                      {result.data.ai_report}
                    </p>
                  </div>
                )}

                {/* HUD Data Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {result.type === 'url' ? (
                    <>
                      <div className="group bg-slate-900/40 border border-slate-700/50 hover:border-cyan-500/50 rounded-xl p-5 transition-all">
                        <p className="text-[10px] text-cyan-600 font-bold uppercase tracking-widest mb-1 group-hover:text-cyan-400 transition-colors">Resolved IP</p>
                        <p className="text-lg text-white font-light">{result.data.ip}</p>
                      </div>
                      <div className="group bg-slate-900/40 border border-slate-700/50 hover:border-cyan-500/50 rounded-xl p-5 transition-all">
                        <p className="text-[10px] text-cyan-600 font-bold uppercase tracking-widest mb-1 group-hover:text-cyan-400 transition-colors">SSL Handshake</p>
                        <div className="flex items-center gap-2">
                          {result.data.ssl_issuer ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <AlertTriangle className="w-4 h-4 text-red-500" />}
                          <p className="text-sm text-white font-medium truncate">{result.data.ssl_issuer || 'Missing / Invalid'}</p>
                        </div>
                      </div>
                      <div className="md:col-span-2 group bg-slate-900/40 border border-slate-700/50 hover:border-cyan-500/50 rounded-xl p-5 transition-all">
                        <div className="flex justify-between items-end mb-3">
                          <p className="text-[10px] text-cyan-600 font-bold uppercase tracking-widest group-hover:text-cyan-400 transition-colors">Heuristic Phishing Score</p>
                          <span className="text-xl text-white font-black">{result.data.phishing_score ?? 0}<span className="text-sm text-slate-500 font-normal">/100</span></span>
                        </div>
                        <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden border border-slate-700/50">
                          <div 
                            className={clsx(
                              "h-full transition-all duration-1000 relative",
                              (result.data.phishing_score || 0) > 70 ? "bg-red-500" : (result.data.phishing_score || 0) > 40 ? "bg-yellow-500" : "bg-green-500"
                            )} 
                            style={{ width: `${result.data.phishing_score}%` }} 
                          >
                            <div className="absolute inset-0 bg-white/20 w-full animate-[scanline_2s_linear_infinite]"></div>
                          </div>
                        </div>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="group bg-slate-900/40 border border-slate-700/50 hover:border-cyan-500/50 rounded-xl p-5 transition-all">
                        <p className="text-[10px] text-cyan-600 font-bold uppercase tracking-widest mb-1 group-hover:text-cyan-400 transition-colors">Payload Size</p>
                        <p className="text-lg text-white font-light">{result.data.local_analysis?.size_kb || 'N/A'} KB</p>
                      </div>
                      <div className="group bg-slate-900/40 border border-slate-700/50 hover:border-cyan-500/50 rounded-xl p-5 transition-all">
                        <p className="text-[10px] text-cyan-600 font-bold uppercase tracking-widest mb-1 group-hover:text-cyan-400 transition-colors">Local Signature Engine</p>
                        <p className={clsx("text-sm font-bold", result.data.local_analysis?.verdict?.includes('Clean') ? 'text-green-400' : 'text-yellow-400')}>
                          {result.data.local_analysis?.verdict || 'N/A (Cloud Scan Only)'}
                        </p>
                      </div>
                      <div className="md:col-span-2 group bg-slate-900/40 border border-slate-700/50 hover:border-cyan-500/50 rounded-xl p-5 transition-all">
                        <p className="text-[10px] text-cyan-600 font-bold uppercase tracking-widest mb-2 group-hover:text-cyan-400 transition-colors">Cryptographic Hash</p>
                        <div className="bg-slate-950/80 border border-slate-800 p-3 rounded-lg flex items-center justify-between">
                          <p className="text-cyan-300 font-mono text-[11px] break-all tracking-wider">{result.data.local_analysis?.sha256 || result.data.cloud_analysis?.sha256 || result.data.cloud_analysis?.hash || 'Unknown Hash'}</p>
                        </div>
                      </div>
                    </>
                  )}
                </div>

                {/* Behavioral Patterns */}
                {((result.type === 'url' ? (result.data.suspicious_patterns || []) : (result.data.local_analysis?.suspicious_features || [])).length > 0 || (result.type === 'file' && (result.data.local_analysis?.strings_sample || []).length > 0)) && (
                  <div className="space-y-4 bg-slate-900/20 border border-slate-700/30 rounded-2xl p-6">
                    <h4 className="text-[11px] text-cyan-500 uppercase font-black tracking-[0.2em] flex items-center gap-2 border-b border-slate-800 pb-3">
                      <Activity className="w-4 h-4" />
                      {result.type === 'url' ? 'Network & DOM Anomalies' : 'Static Feature Extraction'}
                    </h4>
                    
                    <div className="space-y-3 pt-2">
                      {/* Render Suspicious Patterns */}
                      {(result.type === 'url' ? (result.data.suspicious_patterns || []) : (result.data.local_analysis?.suspicious_features || [])).map((p, i) => (
                        <div key={i} className="flex items-start gap-3 text-xs text-slate-300 bg-red-900/10 border border-red-500/20 p-3 rounded-lg">
                          <AlertTriangle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                          <span className="leading-relaxed font-medium">{p}</span>
                        </div>
                      ))}
                      
                      {/* Render Extracted Strings for Files */}
                      {result.type === 'file' && (result.data.local_analysis?.strings_sample || []).length > 0 && (
                        <div className="mt-4">
                           <p className="text-[10px] text-slate-500 mb-3 uppercase font-bold tracking-widest">Hex/ASCII String Dump Segment</p>
                           <div className="flex flex-wrap gap-2">
                             {(result.data.local_analysis?.strings_sample || []).map((s, i) => (
                               <span key={i} className="text-[10px] bg-[#050914] border border-slate-700/80 px-2 py-1 rounded text-cyan-200/70 font-mono shadow-inner shadow-black">{s}</span>
                             ))}
                           </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Global Cloud Report Int */}
                {result.data.cloud_analysis?.found && (
                  <div className="relative overflow-hidden bg-gradient-to-r from-blue-900/40 to-cyan-900/20 border border-blue-500/40 rounded-2xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-lg shadow-blue-900/20">
                    <div className="absolute right-0 top-0 w-64 h-full bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-10 pointer-events-none mix-blend-overlay"></div>
                    <div className="flex items-center gap-4 relative z-10">
                      <div className="w-12 h-12 bg-blue-500/20 border border-blue-400/50 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
                        <Globe className="w-6 h-6 text-blue-400" />
                      </div>
                      <div>
                        <p className="text-base font-black text-white tracking-wide uppercase">Global Threat Intel Match</p>
                        <p className="text-xs text-blue-200/70 mt-1 font-medium">Deep behavioral telemetry available via Hybrid Analysis.</p>
                      </div>
                    </div>
                    <a 
                      href={result.data.cloud_analysis.report_url} 
                      target="_blank" 
                      rel="noreferrer"
                      className="relative z-10 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-widest rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-600/30 whitespace-nowrap"
                    >
                      View Full Report <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  </div>
                )}

                {!result.data.cloud_analysis?.found && result.type === 'file' && (
                   <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl text-xs text-slate-500 italic font-mono flex items-center gap-2">
                     <Info className="w-4 h-4 text-slate-600" />
                     NO GLOBAL CLOUD INTELLIGENCE MATCH. RELYING ON LOCAL HEURISTICS.
                   </div>
                )}
              </div>
            )}
          </div>
          

        </div>
      </div>
    </div>
  )
}
