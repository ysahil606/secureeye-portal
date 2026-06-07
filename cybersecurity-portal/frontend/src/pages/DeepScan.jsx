import { useCallback, useMemo, useState } from 'react'
import {
  AlertTriangle, CheckCircle2, Clipboard, Database, Download, ExternalLink,
  FileWarning, Globe2, History, Link as LinkIcon, Loader2, Lock, Radar,
  ScanLine, ShieldAlert, ShieldCheck, Trash2, Upload, XCircle, Zap
} from 'lucide-react'
import clsx from 'clsx'
import api from '../services/api'
import toast from 'react-hot-toast'

const verdictStyle = {
  Malicious: 'border-red-500/40 bg-red-500/10 text-red-300',
  Suspicious: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  'Review Required': 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  Clean: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
  'Clean (Local Only)': 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
}

function Pill({ children, tone = 'slate' }) {
  const tones = {
    slate: 'border-slate-700 bg-slate-900 text-slate-300',
    red: 'border-red-500/30 bg-red-500/10 text-red-300',
    amber: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
    emerald: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
    sky: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  }
  return <span className={clsx('inline-flex items-center rounded-md border px-2 py-1 text-xs font-bold', tones[tone])}>{children}</span>
}

function Panel({ title, icon: Icon, children, action }) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-950/70">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <div className="flex items-center gap-2 text-sm font-bold text-white">
          <Icon className="h-4 w-4 text-cyan-300" />
          {title}
        </div>
        {action}
      </div>
      <div className="p-4">{children}</div>
    </section>
  )
}

function getVerdict(data, type) {
  if (!data) return 'Review Required'
  if (type === 'url') return data.verdict || 'Review Required'
  return data.cloud_analysis?.verdict || data.local_analysis?.verdict || 'Review Required'
}

function getScore(data, type) {
  if (!data) return 0
  if (type === 'url') return Math.max(data.phishing_score || 0, data.threat_score || 0)
  return Math.max(data.cloud_analysis?.threat_score || 0, data.local_analysis?.threat_score || 0)
}

function getSources(data, type) {
  if (!data) return []
  if (type === 'url') return data.source_results || []
  return data.cloud_analysis?.source_results || []
}

export default function DeepScan() {
  const [activeTab, setActiveTab] = useState('indicator')
  const [target, setTarget] = useState('')
  const [file, setFile] = useState(null)
  const [smartMode, setSmartMode] = useState(true)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('')
  const [result, setResult] = useState(null)
  const [scanHistory, setScanHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('deepscan_history') || '[]') } catch { return [] }
  })

  const verdict = getVerdict(result?.data, result?.type)
  const score = getScore(result?.data, result?.type)
  const sources = getSources(result?.data, result?.type)
  const positives = sources.filter(item => item.found && item.verdict !== 'clean')
  const sourceNames = sources.map(item => item.source).filter(Boolean)

  const riskFactors = useMemo(() => {
    if (!result) return []
    if (result.type === 'url') {
      return result.data.risk_factors || result.data.suspicious_patterns || []
    }
    return [
      ...(result.data.cloud_analysis?.risk_factors || []),
      ...(result.data.local_analysis?.suspicious_features || []),
    ]
  }, [result])

  const rememberScan = useCallback((entry) => {
    setScanHistory(prev => {
      const next = [entry, ...prev].slice(0, 12)
      localStorage.setItem('deepscan_history', JSON.stringify(next))
      return next
    })
  }, [])

  const normalizeTarget = (value) => {
    const trimmed = value.trim()
    if (!trimmed) return ''
    const isHash = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(trimmed)
    if (isHash) return trimmed
    return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  }

  const runIndicatorScan = async (e) => {
    e.preventDefault()
    const normalized = normalizeTarget(target)
    if (!normalized) return
    const isHash = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(normalized)

    setLoading(true)
    setResult(null)
    setStatus(isHash ? 'Checking hash reputation' : 'Checking URL and host intelligence')

    try {
      const formData = new FormData()
      formData.append('mode', smartMode ? 'advanced' : 'basic')
      let res
      if (isHash) {
        formData.append('hash', normalized)
        res = await api.post('/sandbox/scan-hash', formData)
        setResult({ type: 'file', data: res.data })
      } else {
        formData.append('url', normalized)
        res = await api.post('/sandbox/scan-url', formData)
        setResult({ type: 'url', data: res.data })
      }
      rememberScan({
        type: isHash ? 'hash' : 'url',
        label: normalized,
        verdict: isHash ? res.data.cloud_analysis?.verdict : res.data.verdict,
        mode: smartMode ? 'advanced' : 'basic',
        scannedAt: new Date().toISOString(),
      })
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Scan failed')
    } finally {
      setLoading(false)
      setStatus('')
    }
  }

  const runFileScan = async (e) => {
    e.preventDefault()
    if (!file) return
    setLoading(true)
    setResult(null)
    setStatus('Hashing file and checking reputation')

    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('mode', smartMode ? 'advanced' : 'basic')
      const res = await api.post('/sandbox/scan-file', formData)
      setResult({ type: 'file', data: res.data })
      rememberScan({
        type: 'file',
        label: file.name,
        verdict: res.data.cloud_analysis?.verdict || res.data.local_analysis?.verdict,
        mode: smartMode ? 'advanced' : 'basic',
        scannedAt: new Date().toISOString(),
      })
    } catch {
      toast.error('File scan failed')
    } finally {
      setLoading(false)
      setStatus('')
    }
  }

  const copyReport = async () => {
    if (!result) return
    await navigator.clipboard.writeText(JSON.stringify(result.data, null, 2))
    toast.success('Report copied')
  }

  const downloadReport = () => {
    if (!result) return
    const objectUrl = URL.createObjectURL(new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = objectUrl
    a.download = `deepscan-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(objectUrl)
  }

  const clearHistory = () => {
    localStorage.removeItem('deepscan_history')
    setScanHistory([])
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-4 border-b border-slate-800 pb-5 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10">
              <ScanLine className="h-5 w-5 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-2xl font-black text-white">DeepScan Lab</h1>
              <p className="text-sm text-slate-400">File, URL, hash, and host reputation analysis</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 p-1">
          <button onClick={() => setSmartMode(false)} className={clsx('rounded-md px-3 py-2 text-xs font-bold', !smartMode ? 'bg-slate-800 text-white' : 'text-slate-500')}>Basic</button>
          <button onClick={() => setSmartMode(true)} className={clsx('rounded-md px-3 py-2 text-xs font-bold', smartMode ? 'bg-cyan-500/20 text-cyan-200' : 'text-slate-500')}>Advanced</button>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[380px_1fr]">
        <div className="space-y-5">
          <Panel title="Scan Target" icon={Radar}>
            <div className="mb-4 grid grid-cols-2 rounded-lg border border-slate-800 bg-slate-950 p-1">
              <button onClick={() => setActiveTab('indicator')} className={clsx('flex items-center justify-center gap-2 rounded-md py-2 text-sm font-bold', activeTab === 'indicator' ? 'bg-slate-800 text-white' : 'text-slate-500')}>
                <LinkIcon className="h-4 w-4" /> Indicator
              </button>
              <button onClick={() => setActiveTab('file')} className={clsx('flex items-center justify-center gap-2 rounded-md py-2 text-sm font-bold', activeTab === 'file' ? 'bg-slate-800 text-white' : 'text-slate-500')}>
                <Upload className="h-4 w-4" /> File
              </button>
            </div>

            {activeTab === 'indicator' ? (
              <form onSubmit={runIndicatorScan} className="space-y-4">
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={loading}
                  className="input font-mono"
                  placeholder="https://site.com, domain, IP, or hash"
                />
                <button disabled={loading || !target.trim()} className="btn-primary flex w-full items-center justify-center gap-2">
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                  Scan Indicator
                </button>
              </form>
            ) : (
              <form onSubmit={runFileScan} className="space-y-4">
                <button
                  type="button"
                  onClick={() => document.getElementById('deepscan-file').click()}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault()
                    const dropped = e.dataTransfer.files?.[0]
                    if (dropped) setFile(dropped)
                  }}
                  className={clsx('flex min-h-36 w-full flex-col items-center justify-center gap-3 rounded-lg border border-dashed p-5 text-center transition', file ? 'border-cyan-500/40 bg-cyan-500/10' : 'border-slate-700 bg-slate-950 hover:border-cyan-500/30')}
                >
                  <input id="deepscan-file" type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
                  <FileWarning className="h-8 w-8 text-cyan-300" />
                  <span className="max-w-full truncate text-sm font-bold text-white">{file?.name || 'Select file'}</span>
                  {file && <span className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB</span>}
                </button>
                <button disabled={loading || !file} className="btn-primary flex w-full items-center justify-center gap-2">
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                  Scan File
                </button>
              </form>
            )}
          </Panel>

          <Panel title="Recent Scans" icon={History} action={scanHistory.length > 0 && (
            <button onClick={clearHistory} className="text-slate-500 hover:text-red-300"><Trash2 className="h-4 w-4" /></button>
          )}>
            {scanHistory.length === 0 ? (
              <div className="text-sm text-slate-500">No recent scans.</div>
            ) : (
              <div className="space-y-2">
                {scanHistory.map((item, index) => (
                  <button key={`${item.scannedAt}-${index}`} onClick={() => item.type !== 'file' && setTarget(item.label)} className="w-full rounded-lg border border-slate-800 bg-slate-900/50 p-3 text-left hover:border-cyan-500/30">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-xs text-slate-300">{item.label}</span>
                      <Pill tone={item.verdict === 'Malicious' ? 'red' : item.verdict === 'Suspicious' ? 'amber' : 'slate'}>{item.verdict || 'Unknown'}</Pill>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </Panel>
        </div>

        <div className="space-y-5">
          <Panel title="Verdict" icon={ShieldAlert} action={result && (
            <div className="flex gap-2">
              <button onClick={copyReport} className="btn-ghost flex items-center gap-2 text-xs"><Clipboard className="h-4 w-4" /> Copy</button>
              <button onClick={downloadReport} className="btn-ghost flex items-center gap-2 text-xs"><Download className="h-4 w-4" /> JSON</button>
            </div>
          )}>
            {loading ? (
              <div className="flex min-h-72 flex-col items-center justify-center gap-4">
                <Loader2 className="h-10 w-10 animate-spin text-cyan-300" />
                <div className="text-sm font-bold text-cyan-200">{status}</div>
              </div>
            ) : !result ? (
              <div className="flex min-h-72 flex-col items-center justify-center gap-3 text-slate-500">
                <ShieldCheck className="h-12 w-12" />
                <div className="text-sm">Run a scan to view evidence.</div>
              </div>
            ) : (
              <div className="space-y-5">
                <div className="grid gap-3 md:grid-cols-4">
                  <div className={clsx('rounded-lg border p-4 md:col-span-2', verdictStyle[verdict] || verdictStyle['Review Required'])}>
                    <div className="text-xs font-bold uppercase tracking-widest opacity-70">Final Verdict</div>
                    <div className="mt-2 text-2xl font-black">{verdict}</div>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
                    <div className="text-xs font-bold uppercase tracking-widest text-slate-500">Risk Score</div>
                    <div className="mt-2 text-2xl font-black text-white">{score}<span className="text-sm text-slate-500">/100</span></div>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
                    <div className="text-xs font-bold uppercase tracking-widest text-slate-500">Positive Sources</div>
                    <div className="mt-2 text-2xl font-black text-white">{positives.length}</div>
                  </div>
                </div>

                {(result.data.summary || result.data.ai_report || result.data.cloud_analysis?.summary) && (
                  <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-4">
                    <div className="mb-2 flex items-center gap-2 text-sm font-bold text-cyan-200">
                      <Zap className="h-4 w-4" /> Analyst Summary
                    </div>
                    <p className="text-sm leading-6 text-slate-300">{result.data.summary || result.data.cloud_analysis?.summary || result.data.ai_report}</p>
                  </div>
                )}

                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                    <div className="mb-3 flex items-center gap-2 text-sm font-bold text-white"><Database className="h-4 w-4 text-cyan-300" /> Evidence</div>
                    {riskFactors.length === 0 ? (
                      <div className="text-sm text-slate-500">No high-confidence risk factors returned.</div>
                    ) : (
                      <div className="space-y-2">
                        {riskFactors.slice(0, 8).map((item, index) => (
                          <div key={index} className="flex gap-2 rounded-md border border-slate-800 bg-slate-950 p-2 text-sm text-slate-300">
                            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                            <span>{item}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                    <div className="mb-3 flex items-center gap-2 text-sm font-bold text-white"><Globe2 className="h-4 w-4 text-cyan-300" /> Source Coverage</div>
                    <div className="flex flex-wrap gap-2">
                      {(sourceNames.length ? sourceNames : ['Local Static Analysis']).map(source => <Pill key={source} tone="sky">{source}</Pill>)}
                    </div>
                  </div>
                </div>

                {sources.length > 0 && (
                  <div className="overflow-hidden rounded-lg border border-slate-800">
                    <table className="w-full text-left text-sm">
                      <thead className="bg-slate-900 text-xs uppercase tracking-widest text-slate-500">
                        <tr>
                          <th className="p-3">Source</th>
                          <th className="p-3">Status</th>
                          <th className="p-3">Details</th>
                          <th className="p-3"></th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 bg-slate-950/60">
                        {sources.map((item, index) => (
                          <tr key={`${item.source}-${index}`}>
                            <td className="p-3 font-bold text-white">{item.source}</td>
                            <td className="p-3">
                              {item.found ? <Pill tone={item.verdict === 'malicious' ? 'red' : item.verdict === 'suspicious' ? 'amber' : 'emerald'}>{item.verdict || 'found'}</Pill> : <Pill>Not found</Pill>}
                            </td>
                            <td className="p-3 text-slate-400">{item.detections || item.message || item.vx_family || 'Checked'}</td>
                            <td className="p-3 text-right">
                              {item.report_url && <a href={item.report_url} target="_blank" rel="noreferrer" className="inline-flex text-cyan-300 hover:text-white"><ExternalLink className="h-4 w-4" /></a>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {result.type === 'url' && result.data.network_exposure && (
                  <div className="grid gap-3 md:grid-cols-3">
                    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                      <div className="text-xs font-bold uppercase tracking-widest text-slate-500">IP</div>
                      <div className="mt-2 font-mono text-sm text-white">{result.data.ip || 'Unknown'}</div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                      <div className="text-xs font-bold uppercase tracking-widest text-slate-500">Open Ports</div>
                      <div className="mt-2 text-sm text-white">{(result.data.network_exposure.ports || []).join(', ') || 'None returned'}</div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                      <div className="text-xs font-bold uppercase tracking-widest text-slate-500">CVEs</div>
                      <div className="mt-2 text-sm text-white">{(result.data.network_exposure.vulns || []).slice(0, 4).join(', ') || 'None returned'}</div>
                    </div>
                  </div>
                )}

                {result.type === 'file' && result.data.local_analysis && (
                  <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                    <div className="mb-3 flex items-center gap-2 text-sm font-bold text-white"><Lock className="h-4 w-4 text-cyan-300" /> File Metadata</div>
                    <div className="grid gap-3 md:grid-cols-2">
                      <div className="rounded-md bg-slate-950 p-3">
                        <div className="text-xs text-slate-500">SHA-256</div>
                        <div className="mt-1 break-all font-mono text-xs text-slate-300">{result.data.local_analysis.sha256}</div>
                      </div>
                      <div className="rounded-md bg-slate-950 p-3">
                        <div className="text-xs text-slate-500">Size</div>
                        <div className="mt-1 text-sm text-white">{result.data.local_analysis.size_kb} KB</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  )
}
