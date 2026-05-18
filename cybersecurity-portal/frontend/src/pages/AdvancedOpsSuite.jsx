import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, Bot, BrainCircuit, ClipboardList, Copy, Download,
  FileText, GitBranch, Globe2, ListChecks, Network, Play, Radar, Route,
  Search, ShieldAlert, ShieldCheck, Skull, Sparkles, Target, Upload, Zap
} from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../services/api'
import clsx from 'clsx'

const severityColors = {
  Critical: 'text-red-300 border-red-700/40 bg-red-950/30',
  High: 'text-orange-300 border-orange-700/40 bg-orange-950/30',
  Medium: 'text-yellow-300 border-yellow-700/40 bg-yellow-950/30',
  Low: 'text-emerald-300 border-emerald-700/40 bg-emerald-950/30',
  Watch: 'text-blue-300 border-blue-700/40 bg-blue-950/30',
}

const playbooks = {
  ransomware: ['Isolate impacted hosts', 'Disable compromised accounts', 'Capture ransom note and hashes', 'Check backups', 'Block IOCs', 'Start recovery bridge'],
  phishing: ['Preserve message headers', 'Block sender/domain', 'Identify clicked users', 'Reset credentials', 'Review OAuth grants', 'Hunt for forwarding rules'],
  cloud: ['Revoke sessions and tokens', 'Rotate keys', 'Review IAM changes', 'Check storage exposure', 'Inspect audit logs', 'Restore least privilege'],
  insider: ['Preserve audit logs', 'Limit access', 'Review data movement', 'Engage HR/legal process', 'Validate device activity', 'Document chain of custody'],
  leak: ['Confirm leaked data type', 'Identify source system', 'Force resets if credentials exposed', 'Notify stakeholders', 'Monitor reuse', 'Close remediation tasks'],
}

function Badge({ value }) {
  return <span className={clsx('rounded-full border px-2.5 py-1 text-xs font-semibold', severityColors[value] || severityColors.Watch)}>{value}</span>
}

function Panel({ title, icon: Icon, children, action }) {
  return (
    <section className="card p-4 sm:p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white">
          <Icon className="h-4 w-4 text-cyan-400" /> {title}
        </h2>
        {action}
      </div>
      {children}
    </section>
  )
}

export default function AdvancedOpsSuite() {
  const [input, setInput] = useState('CVE-2024-3400 observed with suspicious VPN login and possible credential theft')
  const [copilot, setCopilot] = useState(null)
  const [mitre, setMitre] = useState(null)
  const [exploit, setExploit] = useState(null)
  const [actors, setActors] = useState(null)
  const [rules, setRules] = useState(null)
  const [domain, setDomain] = useState('example.com')
  const [surface, setSurface] = useState(null)
  const [patchInput, setPatchInput] = useState('CVE-2024-3400, CVE-2023-34362')
  const [patchPlan, setPatchPlan] = useState(null)
  const [zeroDays, setZeroDays] = useState([])
  const [feedHealth, setFeedHealth] = useState(null)
  const [sandboxTarget, setSandboxTarget] = useState('')
  const [sandboxQueue, setSandboxQueue] = useState(() => {
    try { return JSON.parse(localStorage.getItem('advanced_sandbox_queue') || '[]') } catch { return [] }
  })
  const [timelineDomain, setTimelineDomain] = useState('example.com')
  const [exposureTimeline, setExposureTimeline] = useState(() => {
    try { return JSON.parse(localStorage.getItem('advanced_exposure_timeline') || '[]') } catch { return [] }
  })
  const [playbook, setPlaybook] = useState('ransomware')
  const [loading, setLoading] = useState('')

  const runAll = async () => {
    if (!input.trim()) return
    setLoading('copilot')
    try {
      const [copilotRes, mitreRes, exploitRes, actorRes, rulesRes] = await Promise.all([
        api.post('/advanced/incident-copilot', { text: input }),
        api.post('/advanced/mitre-map', { text: input }),
        api.post('/advanced/exploit-tracker', { text: input }),
        api.post('/advanced/actor-match', { text: input }),
        api.post('/advanced/rule-builder', { text: input }),
      ])
      setCopilot(copilotRes.data)
      setMitre(mitreRes.data)
      setExploit(exploitRes.data)
      setActors(actorRes.data)
      setRules(rulesRes.data)
    } catch (err) {
      toast.error(err?.response?.data?.detail || 'Advanced analysis failed')
    } finally {
      setLoading('')
    }
  }

  const scanSurface = async () => {
    setLoading('surface')
    try {
      const res = await api.post('/advanced/attack-surface', { domain })
      setSurface(res.data)
    } catch {
      toast.error('Asset exposure scan failed')
    } finally {
      setLoading('')
    }
  }

  const runPatchPlan = async () => {
    setLoading('patch')
    try {
      const res = await api.post('/advanced/patch-planner', {
        cves: patchInput.split(',').map(item => item.trim()).filter(Boolean),
        asset_exposure: 'internet',
        business_criticality: 'high',
      })
      setPatchPlan(res.data)
    } catch {
      toast.error('Patch planner failed')
    } finally {
      setLoading('')
    }
  }

  const loadWatches = async () => {
    try {
      const [zeroRes, healthRes] = await Promise.all([
        api.get('/advanced/zero-day-watch'),
        api.get('/advanced/feed-health'),
      ])
      setZeroDays(zeroRes.data.items || [])
      setFeedHealth(healthRes.data)
    } catch {
      toast.error('Watch data failed')
    }
  }

  useEffect(() => { loadWatches() }, [])

  const enqueueScan = async () => {
    const target = sandboxTarget.trim()
    if (!target) return
    const entry = { id: Date.now(), target, type: 'url', verdict: 'Queued', score: 0, createdAt: new Date().toISOString() }
    const queued = [entry, ...sandboxQueue].slice(0, 20)
    setSandboxQueue(queued)
    localStorage.setItem('advanced_sandbox_queue', JSON.stringify(queued))
    setSandboxTarget('')
    try {
      const form = new FormData()
      form.append('url', /^https?:\/\//i.test(target) ? target : `https://${target}`)
      const res = await api.post('/sandbox/scan-url', form)
      const score = res.data.phishing_score || (res.data.verdict === 'Malicious' ? 95 : res.data.verdict === 'Suspicious' ? 65 : 20)
      const updated = queued.map(item => item.id === entry.id ? { ...item, verdict: res.data.verdict || 'Review', score } : item)
      setSandboxQueue(updated)
      localStorage.setItem('advanced_sandbox_queue', JSON.stringify(updated))
    } catch {
      const updated = queued.map(item => item.id === entry.id ? { ...item, verdict: 'Offline review', score: 35 } : item)
      setSandboxQueue(updated)
      localStorage.setItem('advanced_sandbox_queue', JSON.stringify(updated))
    }
  }

  const scanTimeline = async () => {
    try {
      const res = await api.get('/darkweb/scan', { params: { q: timelineDomain } })
      const next = [{ id: Date.now(), query: timelineDomain, scannedAt: new Date().toISOString(), leaks: res.data.leaks?.length || 0, mentions: res.data.mentions?.length || 0 }, ...exposureTimeline].slice(0, 10)
      setExposureTimeline(next)
      localStorage.setItem('advanced_exposure_timeline', JSON.stringify(next))
    } catch {
      toast.error('Exposure timeline scan failed')
    }
  }

  const copyText = async (text) => {
    await navigator.clipboard.writeText(typeof text === 'string' ? text : JSON.stringify(text, null, 2))
    toast.success('Copied')
  }

  const downloadJson = (name, payload) => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  }

  const exportExecutivePdf = async () => {
    const payload = {
      title: copilot?.report_draft?.title || 'SecureEye Executive Threat Report',
      summary: copilot?.summary || input,
      business_impact: copilot?.report_draft?.business_impact || 'Potential business impact requires validation.',
      affected_assets: surface?.subdomains_checked?.map(item => item.host) || [],
      recommended_actions: copilot?.containment_steps || [],
    }
    const res = await api.post('/advanced/executive-report', payload, { responseType: 'blob' })
    const url = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = url
    a.download = 'SecureEye_Executive_Report.pdf'
    a.click()
    URL.revokeObjectURL(url)
  }

  const graphNodes = useMemo(() => {
    const base = [
      ['IOC', 40, 90], ['CVE', 130, 50], ['MITRE', 220, 90], ['Actor', 130, 150],
      ['Asset', 320, 50], ['Server', 410, 90], ['Cloud', 320, 150], ['Data', 500, 130],
    ]
    return base.map(([label, x, y]) => ({ label, x, y }))
  }, [])

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
            <Sparkles className="h-6 w-6 text-cyan-400" /> Advanced Ops Suite
          </h1>
          <p className="mt-1 text-sm text-slate-400">Free-source and offline-assisted incident intelligence for the APK.</p>
        </div>
        <button onClick={runAll} className="btn-primary flex items-center justify-center gap-2">
          <BrainCircuit className="h-4 w-4" /> {loading === 'copilot' ? 'Analyzing...' : 'Run Copilot'}
        </button>
      </div>

      <Panel title="AI Incident Copilot" icon={Bot} action={<button onClick={() => copyText(copilot || {})} className="btn-ghost text-xs">Copy</button>}>
        <textarea className="input min-h-28 text-sm" value={input} onChange={e => setInput(e.target.value)} placeholder="Enter IOC, CVE, symptoms, malware name, or incident notes" />
        {copilot && (
          <div className="mt-4 space-y-3">
            <div className="flex flex-wrap items-center gap-2"><Badge value={copilot.severity} /><span className="text-xs text-slate-500">Score {copilot.score}/100</span></div>
            <p className="text-sm text-slate-300">{copilot.summary}</p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {copilot.containment_steps.map(step => <div key={step} className="rounded-lg border border-dark-600 bg-dark-800 p-2 text-xs text-slate-300">{step}</div>)}
            </div>
          </div>
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Attack Path Mapper" icon={Route}>
          <div className="overflow-x-auto rounded-xl border border-dark-600 bg-dark-900 p-3">
            <svg viewBox="0 0 560 210" className="h-52 min-w-[560px]">
              {graphNodes.slice(0, -1).map((node, index) => {
                const next = graphNodes[index + 1]
                return <line key={node.label} x1={node.x + 35} y1={node.y} x2={next.x - 35} y2={next.y} stroke="#334155" strokeWidth="2" />
              })}
              {graphNodes.map(node => (
                <g key={node.label}>
                  <circle cx={node.x} cy={node.y} r="28" fill="#0f172a" stroke="#22d3ee" strokeWidth="2" />
                  <text x={node.x} y={node.y + 4} textAnchor="middle" fill="#e2e8f0" fontSize="11">{node.label}</text>
                </g>
              ))}
            </svg>
          </div>
        </Panel>

        <Panel title="MITRE ATT&CK Auto-Mapping" icon={Target}>
          <div className="space-y-2">
            {(mitre?.items || []).map(item => (
              <div key={`${item.tactic}-${item.technique}`} className="rounded-lg border border-dark-600 bg-dark-800 p-3">
                <div className="font-mono text-sm text-cyan-300">{item.tactic} / {item.technique}</div>
                <div className="text-sm text-white">{item.name}</div>
                <div className="text-xs text-slate-500">Matched: {item.keyword}</div>
              </div>
            ))}
            {!mitre && <Empty text="Run Copilot to map notes to ATT&CK." />}
          </div>
        </Panel>

        <Panel title="Exploit Availability Tracker" icon={Skull}>
          {exploit ? (
            <div className="space-y-3">
              <Badge value={exploit.status === 'Actively exploited' ? 'Critical' : exploit.status === 'Weaponized' ? 'High' : 'Watch'} />
              <div className="text-sm text-slate-300">{exploit.status}</div>
              <div className="flex flex-wrap gap-2">{exploit.free_sources.map(src => <span key={src} className="rounded border border-dark-600 bg-dark-800 px-2 py-1 text-xs text-slate-300">{src}</span>)}</div>
            </div>
          ) : <Empty text="Run Copilot to check exploit status." />}
        </Panel>

        <Panel title="Threat Actor Profile Matching" icon={ShieldAlert}>
          <div className="space-y-2">
            {(actors?.actors || []).map(item => (
              <div key={item.actor} className="rounded-lg border border-dark-600 bg-dark-800 p-3">
                <div className="text-sm font-semibold text-white">{item.actor}</div>
                <div className="text-xs text-slate-400">{item.reason}</div>
                <div className="mt-1 text-[11px] text-cyan-300">Confidence: {item.confidence}</div>
              </div>
            ))}
            {!actors && <Empty text="Run Copilot to match likely actor profiles." />}
          </div>
        </Panel>

        <Panel title="Mobile Sandbox Queue" icon={Upload} action={<button onClick={() => downloadJson('sandbox-queue.json', sandboxQueue)} className="btn-ghost text-xs">Export</button>}>
          <div className="flex gap-2">
            <input className="input" value={sandboxTarget} onChange={e => setSandboxTarget(e.target.value)} placeholder="URL or domain to queue" />
            <button onClick={enqueueScan} className="btn-primary px-3"><Play className="h-4 w-4" /></button>
          </div>
          <div className="mt-3 space-y-2">
            {sandboxQueue.map(item => (
              <div key={item.id} className="flex items-center justify-between gap-3 rounded-lg border border-dark-600 bg-dark-800 p-3">
                <div className="min-w-0">
                  <div className="truncate text-sm text-white">{item.target}</div>
                  <div className="text-xs text-slate-500">{item.verdict}</div>
                </div>
                <span className="text-sm font-bold text-cyan-300">{item.score}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Local YARA/Sigma Rule Builder" icon={ClipboardList} action={<button onClick={() => copyText(rules || {})} className="btn-ghost text-xs"><Copy className="h-3 w-3" /></button>}>
          {rules ? (
            <div className="space-y-3">
              <pre className="max-h-52 overflow-auto rounded-lg bg-black p-3 text-xs text-green-300">{rules.yara}</pre>
              <pre className="max-h-52 overflow-auto rounded-lg bg-black p-3 text-xs text-blue-300">{JSON.stringify(rules.sigma, null, 2)}</pre>
            </div>
          ) : <Empty text="Run Copilot to generate local YARA and Sigma drafts." />}
        </Panel>

        <Panel title="Asset Exposure Scanner" icon={Globe2}>
          <div className="flex gap-2">
            <input className="input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" />
            <button onClick={scanSurface} className="btn-primary whitespace-nowrap">{loading === 'surface' ? 'Scanning...' : 'Scan'}</button>
          </div>
          {surface && (
            <div className="mt-3 space-y-2 text-sm text-slate-300">
              <div>IP: <span className="font-mono text-white">{surface.ip || 'unresolved'}</span></div>
              <div>Ports: {surface.open_ports?.join(', ') || 'none'}</div>
              <div className="flex flex-wrap gap-2">{(surface.risks || ['No major issue detected']).map(item => <span className="rounded border border-dark-600 bg-dark-800 px-2 py-1 text-xs" key={item}>{item}</span>)}</div>
            </div>
          )}
        </Panel>

        <Panel title="Risk-Based Patch Planner" icon={Zap}>
          <textarea className="input min-h-20" value={patchInput} onChange={e => setPatchInput(e.target.value)} />
          <button onClick={runPatchPlan} className="btn-primary mt-3">{loading === 'patch' ? 'Planning...' : 'Plan Patches'}</button>
          <div className="mt-3 space-y-2">
            {(patchPlan?.items || []).map(item => (
              <div key={item.cve} className="rounded-lg border border-dark-600 bg-dark-800 p-3 text-sm">
                <div className="flex justify-between"><span className="font-mono text-white">{item.cve}</span><span className="font-bold text-cyan-300">{item.priority}</span></div>
                <div className="text-xs text-slate-500">SLA {item.sla} | Score {item.score}</div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Zero-Day Watch Mode" icon={AlertTriangle} action={<button onClick={loadWatches} className="btn-ghost text-xs">Refresh</button>}>
          <div className="max-h-72 space-y-2 overflow-auto">
            {zeroDays.map(item => (
              <div key={item.id} className="rounded-lg border border-dark-600 bg-dark-800 p-3">
                <div className="text-sm text-white">{item.title}</div>
                <div className="text-xs text-slate-500">{item.severity} | score {item.score}</div>
              </div>
            ))}
            {zeroDays.length === 0 && <Empty text="No zero-day watch items found." />}
          </div>
        </Panel>

        <Panel title="Dark Web Exposure Timeline" icon={Activity}>
          <div className="flex gap-2">
            <input className="input" value={timelineDomain} onChange={e => setTimelineDomain(e.target.value)} />
            <button onClick={scanTimeline} className="btn-primary">Scan</button>
          </div>
          <div className="mt-3 space-y-2">
            {exposureTimeline.map(item => (
              <div key={item.id} className="rounded-lg border border-dark-600 bg-dark-800 p-3 text-sm text-slate-300">
                <div className="font-semibold text-white">{item.query}</div>
                <div className="text-xs text-slate-500">{new Date(item.scannedAt).toLocaleString()} | leaks {item.leaks} | mentions {item.mentions}</div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Executive Report Generator" icon={FileText}>
          <p className="text-sm text-slate-400">Generates a PDF from copilot summary, business impact, assets, and actions.</p>
          <button onClick={exportExecutivePdf} className="btn-primary mt-3 flex items-center gap-2"><Download className="h-4 w-4" /> Export PDF</button>
        </Panel>

        <Panel title="IOC Relationship Graph" icon={GitBranch}>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {['IPs', 'Domains', 'Hashes', 'CVEs', 'Actors', 'MITRE', 'Assets', 'Advisories'].map((item, index) => (
              <div key={item} className="rounded-lg border border-dark-600 bg-dark-800 p-3 text-center">
                <Network className="mx-auto mb-1 h-4 w-4 text-cyan-400" />
                <div className="text-xs text-slate-300">{item}</div>
                <div className="text-lg font-bold text-white">{index === 3 ? (copilot?.indicators?.cves?.length || 0) : index === 2 ? (copilot?.indicators?.hashes?.length || 0) : index + 1}</div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Threat Feed Health Monitor" icon={Radar}>
          <div className="space-y-2">
            {(feedHealth?.free_sources || []).map(item => (
              <div key={item.source} className="rounded-lg border border-dark-600 bg-dark-800 p-3">
                <div className="text-sm font-semibold text-white">{item.source}</div>
                <div className="text-xs text-slate-400">{item.access}</div>
                <div className="text-[11px] text-slate-500">{item.endpoint}</div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Offline Detection Playbooks" icon={ListChecks}>
          <select className="input mb-3" value={playbook} onChange={e => setPlaybook(e.target.value)}>
            {Object.keys(playbooks).map(key => <option key={key} value={key}>{key}</option>)}
          </select>
          <div className="space-y-2">
            {playbooks[playbook].map(step => (
              <div key={step} className="rounded-lg border border-dark-600 bg-dark-800 p-3 text-sm text-slate-300"><ShieldCheck className="mr-2 inline h-4 w-4 text-green-400" />{step}</div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  )
}

function Empty({ text }) {
  return <div className="rounded-lg border border-dashed border-dark-600 bg-dark-800/60 p-6 text-center text-sm text-slate-500">{text}</div>
}
