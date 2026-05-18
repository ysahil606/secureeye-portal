import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, CheckCircle2, Clipboard, Clock, Copy, Download,
  FileText, Fingerprint, KeyRound, LifeBuoy, ListChecks, LockKeyhole,
  Mail, Phone, Plus, Radar, RefreshCw, ShieldCheck, Trash2, WifiOff
} from 'lucide-react'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const checklistTemplate = [
  'Confirm impacted users, systems, and business process',
  'Capture screenshots, logs, domains, IPs, hashes, and timestamps',
  'Contain affected endpoint, account, or network segment',
  'Reset exposed credentials and confirm MFA status',
  'Search SIEM, EDR, DNS, firewall, and proxy logs',
  'Document actions, owner, and next review time',
]

const classifyIoc = (value) => {
  const text = value.trim()
  if (/^https?:\/\//i.test(text)) return 'url'
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) return 'ip'
  if (/^[a-f0-9]{32}$/i.test(text)) return 'md5'
  if (/^[a-f0-9]{40}$/i.test(text)) return 'sha1'
  if (/^[a-f0-9]{64}$/i.test(text)) return 'sha256'
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(text)) return 'domain'
  return text ? 'unknown' : 'empty'
}

const severityWeights = { internet: 30, kev: 25, exploit: 20, sensitive: 15, auth: 10 }

export default function MobileToolkit() {
  const [password, setPassword] = useState('')
  const [hashInput, setHashInput] = useState('')
  const [hashOutput, setHashOutput] = useState('')
  const [iocValue, setIocValue] = useState('')
  const [checklist, setChecklist] = useState(() => {
    try { return JSON.parse(localStorage.getItem('mobile_checklist') || 'null') || checklistTemplate.map(text => ({ text, done: false })) } catch { return checklistTemplate.map(text => ({ text, done: false })) }
  })
  const [notes, setNotes] = useState(() => localStorage.getItem('mobile_secure_notes') || '')
  const [contacts, setContacts] = useState(() => {
    try { return JSON.parse(localStorage.getItem('mobile_contacts') || '[]') } catch { return [] }
  })
  const [contact, setContact] = useState({ name: '', phone: '', email: '' })
  const [timerStarted, setTimerStarted] = useState(() => Number(localStorage.getItem('incident_started_at') || 0))
  const [nowTick, setNowTick] = useState(Date.now())
  const [riskFlags, setRiskFlags] = useState({ internet: true, kev: false, exploit: false, sensitive: false, auth: false })
  const [logBuilder, setLogBuilder] = useState({ ioc: '', user: '', host: '' })

  useEffect(() => {
    if (!timerStarted) return undefined
    const id = window.setInterval(() => setNowTick(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [timerStarted])

  const elapsed = timerStarted ? Math.max(0, nowTick - timerStarted) : 0
  const elapsedText = new Date(elapsed).toISOString().slice(11, 19)
  const iocType = classifyIoc(iocValue)
  const riskScore = Object.entries(riskFlags).reduce((total, [key, enabled]) => total + (enabled ? severityWeights[key] : 0), 0)
  const riskLabel = riskScore >= 75 ? 'Critical' : riskScore >= 50 ? 'High' : riskScore >= 25 ? 'Medium' : 'Low'
  const logQuery = useMemo(() => {
    return [
      logBuilder.ioc && `(src:${logBuilder.ioc} OR dst:${logBuilder.ioc} OR url:${logBuilder.ioc})`,
      logBuilder.user && `(user:${logBuilder.user} OR account:${logBuilder.user})`,
      logBuilder.host && `(host:${logBuilder.host} OR device:${logBuilder.host})`,
    ].filter(Boolean).join(' AND ')
  }, [logBuilder])

  const saveChecklist = (next) => {
    setChecklist(next)
    localStorage.setItem('mobile_checklist', JSON.stringify(next))
  }

  const saveContacts = (next) => {
    setContacts(next)
    localStorage.setItem('mobile_contacts', JSON.stringify(next))
  }

  const generatePassword = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%+-_=*'
    const bytes = new Uint32Array(20)
    crypto.getRandomValues(bytes)
    const next = Array.from(bytes, n => chars[n % chars.length]).join('')
    setPassword(next)
  }

  const copyText = async (text, message = 'Copied') => {
    if (!text) return
    await navigator.clipboard.writeText(text)
    toast.success(message)
  }

  const hashText = async () => {
    const data = new TextEncoder().encode(hashInput)
    const digest = await crypto.subtle.digest('SHA-256', data)
    setHashOutput(Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join(''))
  }

  const saveNotes = (value) => {
    setNotes(value)
    localStorage.setItem('mobile_secure_notes', value)
  }

  const addContact = (e) => {
    e.preventDefault()
    if (!contact.name.trim()) return
    saveContacts([{ ...contact, id: Date.now() }, ...contacts].slice(0, 8))
    setContact({ name: '', phone: '', email: '' })
    toast.success('Contact saved')
  }

  const exportIncidentPack = () => {
    const payload = {
      generatedAt: new Date().toISOString(),
      elapsed: elapsedText,
      checklist,
      notes,
      contacts,
      ioc: { value: iocValue, type: iocType },
      risk: { score: riskScore, label: riskLabel, flags: riskFlags },
      logQuery,
    }
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `secureeye-mobile-pack-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="flex items-center gap-3 text-2xl font-bold text-white">
          <LifeBuoy className="h-6 w-6 text-cyan-400" />
          Mobile Response Toolkit
        </h1>
        <p className="mt-1 text-sm text-slate-400">Offline-ready tools for the free APK: triage, notes, hashes, contacts, and incident packs.</p>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric icon={WifiOff} label="Offline tools" value="12" color="cyan" />
        <Metric icon={Clock} label="Timer" value={timerStarted ? elapsedText : 'Ready'} color="blue" />
        <Metric icon={Radar} label="IOC type" value={iocType} color="purple" />
        <Metric icon={AlertTriangle} label="Risk" value={riskLabel} color="red" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ToolCard icon={Clock} title="Incident Timer">
          <div className="text-4xl font-bold tabular-nums text-white">{timerStarted ? elapsedText : '00:00:00'}</div>
          <div className="mt-4 flex gap-2">
            <button className="btn-primary flex-1" onClick={() => { const startedAt = Date.now(); setNowTick(startedAt); setTimerStarted(startedAt); localStorage.setItem('incident_started_at', String(startedAt)) }}>Start</button>
            <button className="btn-ghost flex-1" onClick={() => { setNowTick(Date.now()); setTimerStarted(0); localStorage.removeItem('incident_started_at') }}>Reset</button>
          </div>
        </ToolCard>

        <ToolCard icon={KeyRound} title="Password Generator">
          <div className="flex gap-2">
            <input className="input font-mono text-sm" readOnly value={password} placeholder="Generate a strong password" />
            <button className="btn-primary px-3" onClick={generatePassword} title="Generate"><RefreshCw className="h-4 w-4" /></button>
            <button className="btn-ghost px-3" onClick={() => copyText(password, 'Password copied')} title="Copy"><Copy className="h-4 w-4" /></button>
          </div>
        </ToolCard>

        <ToolCard icon={Fingerprint} title="SHA-256 Hash">
          <textarea className="input min-h-24 text-sm" value={hashInput} onChange={e => setHashInput(e.target.value)} placeholder="Paste text, IOC, or evidence note" />
          <div className="mt-3 flex gap-2">
            <button className="btn-primary" onClick={hashText}>Hash</button>
            <button className="btn-ghost" onClick={() => copyText(hashOutput, 'Hash copied')}>Copy</button>
          </div>
          {hashOutput && <div className="mt-3 break-all rounded-lg bg-dark-900 p-3 font-mono text-xs text-cyan-300">{hashOutput}</div>}
        </ToolCard>

        <ToolCard icon={Radar} title="IOC Classifier">
          <input className="input" value={iocValue} onChange={e => setIocValue(e.target.value)} placeholder="IP, domain, URL, MD5, SHA1, SHA256" />
          <div className="mt-3 rounded-lg border border-dark-600 bg-dark-900 p-3 text-sm text-slate-300">
            Detected: <span className="font-bold uppercase text-cyan-300">{iocType}</span>
          </div>
        </ToolCard>

        <ToolCard icon={ListChecks} title="Breach Checklist">
          <div className="space-y-2">
            {checklist.map((item, index) => (
              <label key={item.text} className="flex items-start gap-3 rounded-lg border border-dark-600 bg-dark-900/60 p-3 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={item.done}
                  onChange={e => saveChecklist(checklist.map((row, i) => i === index ? { ...row, done: e.target.checked } : row))}
                  className="mt-1"
                />
                <span className={clsx(item.done && 'text-slate-500 line-through')}>{item.text}</span>
              </label>
            ))}
          </div>
        </ToolCard>

        <ToolCard icon={AlertTriangle} title="Risk Score">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {Object.keys(riskFlags).map(key => (
              <label key={key} className="flex items-center justify-between rounded-lg border border-dark-600 bg-dark-900 p-3 text-sm text-slate-300">
                <span className="capitalize">{key}</span>
                <input type="checkbox" checked={riskFlags[key]} onChange={e => setRiskFlags(flags => ({ ...flags, [key]: e.target.checked }))} />
              </label>
            ))}
          </div>
          <div className="mt-3 rounded-lg bg-dark-900 p-3 text-sm text-slate-300">Score: <span className="font-bold text-white">{riskScore}</span> / 100</div>
        </ToolCard>

        <ToolCard icon={LockKeyhole} title="Secure Notes">
          <textarea className="input min-h-36 text-sm" value={notes} onChange={e => saveNotes(e.target.value)} placeholder="Local incident notes. Stored only on this device." />
          <div className="mt-3 flex gap-2">
            <button className="btn-ghost" onClick={() => copyText(notes, 'Notes copied')}>Copy</button>
            <button className="btn-ghost text-red-300" onClick={() => saveNotes('')}>Clear</button>
          </div>
        </ToolCard>

        <ToolCard icon={Phone} title="Emergency Contacts">
          <form onSubmit={addContact} className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <input className="input text-sm" value={contact.name} onChange={e => setContact(c => ({ ...c, name: e.target.value }))} placeholder="Name" />
            <input className="input text-sm" value={contact.phone} onChange={e => setContact(c => ({ ...c, phone: e.target.value }))} placeholder="Phone" />
            <button className="btn-primary flex items-center justify-center gap-2 text-sm"><Plus className="h-4 w-4" /> Add</button>
            <input className="input text-sm sm:col-span-3" value={contact.email} onChange={e => setContact(c => ({ ...c, email: e.target.value }))} placeholder="Email" />
          </form>
          <div className="mt-3 space-y-2">
            {contacts.map(item => (
              <div key={item.id} className="flex items-center gap-2 rounded-lg bg-dark-900 p-3 text-sm">
                <div className="min-w-0 flex-1">
                  <div className="font-semibold text-white">{item.name}</div>
                  <div className="truncate text-xs text-slate-500">{item.phone || item.email || 'No contact detail'}</div>
                </div>
                {item.phone && <a className="text-green-400" href={`tel:${item.phone}`}><Phone className="h-4 w-4" /></a>}
                {item.email && <a className="text-blue-400" href={`mailto:${item.email}`}><Mail className="h-4 w-4" /></a>}
                <button className="text-slate-600 hover:text-red-400" onClick={() => saveContacts(contacts.filter(row => row.id !== item.id))}><Trash2 className="h-4 w-4" /></button>
              </div>
            ))}
          </div>
        </ToolCard>

        <ToolCard icon={FileText} title="Log Query Builder">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <input className="input text-sm" value={logBuilder.ioc} onChange={e => setLogBuilder(v => ({ ...v, ioc: e.target.value }))} placeholder="IOC" />
            <input className="input text-sm" value={logBuilder.user} onChange={e => setLogBuilder(v => ({ ...v, user: e.target.value }))} placeholder="User" />
            <input className="input text-sm" value={logBuilder.host} onChange={e => setLogBuilder(v => ({ ...v, host: e.target.value }))} placeholder="Host" />
          </div>
          <div className="mt-3 break-all rounded-lg bg-dark-900 p-3 font-mono text-xs text-slate-300">{logQuery || 'Fill fields to build a SIEM query'}</div>
          <button className="btn-ghost mt-3" onClick={() => copyText(logQuery, 'Query copied')}>Copy query</button>
        </ToolCard>

        <ToolCard icon={Clipboard} title="Incident Pack">
          <p className="text-sm text-slate-400">Export timer, checklist, notes, contacts, IOC classification, risk score, and log query as one JSON evidence pack.</p>
          <button className="btn-primary mt-4 flex items-center gap-2" onClick={exportIncidentPack}><Download className="h-4 w-4" /> Export Pack</button>
        </ToolCard>

        <ToolCard icon={ShieldCheck} title="Offline Playbook">
          <div className="space-y-2 text-sm text-slate-300">
            {['Identify scope', 'Contain access', 'Preserve evidence', 'Eradicate root cause', 'Recover services', 'Review lessons learned'].map(step => (
              <div key={step} className="flex items-center gap-2 rounded-lg bg-dark-900 p-2">
                <CheckCircle2 className="h-4 w-4 text-green-400" />
                <span>{step}</span>
              </div>
            ))}
          </div>
        </ToolCard>
      </div>
    </div>
  )
}

function ToolCard({ icon: Icon, title, children }) {
  return (
    <section className="card p-4 sm:p-5">
      <h2 className="mb-4 flex items-center gap-2 text-sm font-bold text-white">
        <Icon className="h-4 w-4 text-cyan-400" />
        {title}
      </h2>
      {children}
    </section>
  )
}

function Metric({ icon: Icon, label, value, color }) {
  const colors = {
    cyan: 'text-cyan-300',
    blue: 'text-blue-300',
    purple: 'text-purple-300',
    red: 'text-red-300',
  }
  return (
    <div className="card p-3">
      <div className="flex items-center gap-2 text-xs text-slate-500">
        <Icon className="h-4 w-4" />
        {label}
      </div>
      <div className={clsx('mt-2 truncate text-lg font-bold capitalize', colors[color])}>{value}</div>
    </div>
  )
}
