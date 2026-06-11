import { useEffect, useState } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import {
  ArrowLeft, ArrowRight, Plus, X, Save, Check,
  FileText, Tag, Zap, Shield, ChevronRight,
  AlertTriangle, Activity, Eye, EyeOff, Loader2,
  Hash, Server, Globe, Key
} from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const ATTACK_TYPES = ['RCE', 'SQLi', 'XSS', 'SSRF', 'LFI', 'XXE', 'Auth Bypass', 'Privilege Escalation', 'DoS', 'CSRF', 'Path Traversal', 'Deserialization', 'Supply Chain']
const SEVERITY_OPTIONS = [
  { value: 'critical',      label: 'Critical',      color: '#ef4444', desc: 'Immediate action required' },
  { value: 'high',          label: 'High',          color: '#f97316', desc: 'High risk — patch urgently' },
  { value: 'medium',        label: 'Medium',        color: '#eab308', desc: 'Moderate risk — plan patch' },
  { value: 'low',           label: 'Low',           color: '#22c55e', desc: 'Low risk — monitor' },
  { value: 'informational', label: 'Informational', color: '#94a3b8', desc: 'Informational only' },
]

const STEPS = [
  { id: 1, label: 'Basics',         icon: FileText,       desc: 'Title, severity, score' },
  { id: 2, label: 'Content',        icon: Eye,            desc: 'Description & mitigation' },
  { id: 3, label: 'Classification', icon: Tag,            desc: 'CVEs, TTPs, vendors' },
  { id: 4, label: 'Review',         icon: Check,          desc: 'Preview & publish' },
]

const STORAGE_KEY = 'advisory_draft'

function StepIndicator({ current, total }) {
  return (
    <div className="flex items-center justify-center gap-0 mb-8">
      {STEPS.map((step, i) => {
        const done    = current > step.id
        const active  = current === step.id
        const Icon    = step.icon
        return (
          <div key={step.id} className="flex items-center">
            <div className="flex flex-col items-center gap-1">
              <div className={clsx(
                'w-9 h-9 rounded-full border-2 flex items-center justify-center transition-all duration-300',
                done   ? 'bg-blue-600 border-blue-600 text-white' :
                active ? 'bg-slate-900 border-blue-500 text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.3)]' :
                         'bg-slate-900 border-slate-700 text-slate-600'
              )}>
                {done ? <Check className="w-4 h-4" /> : <Icon className="w-4 h-4" />}
              </div>
              <span className={clsx('text-[9px] font-black uppercase tracking-widest hidden sm:block',
                active ? 'text-blue-400' : done ? 'text-slate-400' : 'text-slate-600'
              )}>{step.label}</span>
            </div>
            {i < STEPS.length - 1 && (
              <div className={clsx('h-0.5 w-12 sm:w-20 mx-1 sm:mx-2 mb-4 rounded transition-all duration-500', done ? 'bg-blue-600' : 'bg-slate-800')} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── CVSS slider ────────────────────────────────────────────────────────────────
function CvssSlider({ value, onChange }) {
  const num = parseFloat(value) || 0
  const color = num >= 9 ? '#ef4444' : num >= 7 ? '#f97316' : num >= 4 ? '#eab308' : '#22c55e'
  const label = num >= 9 ? 'Critical' : num >= 7 ? 'High' : num >= 4 ? 'Medium' : num > 0 ? 'Low' : 'None'
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className="text-xs text-slate-400 font-bold uppercase tracking-wider">CVSS Score (0–10)</label>
        <span className="text-sm font-black tabular-nums" style={{ color }}>{num.toFixed(1)} — {label}</span>
      </div>
      <div className="relative">
        <input
          type="range" min="0" max="10" step="0.1"
          value={value || 0}
          onChange={e => onChange(e.target.value)}
          className="w-full h-2 rounded-full appearance-none cursor-pointer"
          style={{
            background: `linear-gradient(to right, ${color} 0%, ${color} ${num * 10}%, rgba(255,255,255,0.08) ${num * 10}%, rgba(255,255,255,0.08) 100%)`,
          }}
        />
      </div>
      <div className="flex justify-between text-[9px] text-slate-700 font-mono mt-1">
        <span>0.0</span><span>2.5</span><span>5.0</span><span>7.5</span><span>10.0</span>
      </div>
    </div>
  )
}

// ── Tag input ─────────────────────────────────────────────────────────────────
function TagInput({ label, placeholder, tags, onAdd, onRemove, chipClass = 'bg-slate-800 text-slate-300 border-slate-700', inputExtra = '' }) {
  const [val, setVal] = useState('')
  const add = () => { if (!val.trim()) return; onAdd(val.trim()); setVal('') }
  return (
    <div>
      <label className="block text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">{label}</label>
      <div className="flex gap-2 mb-2">
        <input
          className="flex-1 bg-slate-950/50 border border-slate-700/60 text-white rounded-xl px-3 py-2 text-sm placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/40 transition-all"
          placeholder={placeholder}
          value={val}
          onChange={e => setVal(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), add())}
        />
        <button type="button" onClick={add} className="px-3 py-2 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-500/30 transition-all">
          <Plus className="w-4 h-4" />
        </button>
      </div>
      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {tags.map((t, i) => (
            <span key={i} className={clsx('flex items-center gap-1.5 text-xs font-bold px-2.5 py-1 rounded-lg border', chipClass)}>
              {t}
              <button type="button" onClick={() => onRemove(i)} className="hover:text-red-400 transition-colors">
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AdvisoryForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const isEdit = !!id
  const [sectors, setSectors] = useState([])
  const [saving, setSaving]   = useState(false)
  const [step, setStep]       = useState(1)
  const [showPreview, setShowPreview] = useState(false)

  const [form, setForm] = useState(() => {
    if (!isEdit) {
      try { const d = JSON.parse(localStorage.getItem(STORAGE_KEY)); if (d) return d } catch {}
    }
    return {
      title: '', description: '', mitigation: '',
      severity: 'medium', cvss_score: '',
      sector_id: '', cve_ids: [], iocs: [],
      affected_vendors: [], attack_types: [], apt_groups: [], mitre_ttps: [],
      is_zero_day: false, zero_day_status: '', source_url: '', status: 'pending'
    }
  })

  // Auto-save draft
  useEffect(() => {
    if (!isEdit) {
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(form)) } catch {}
    }
  }, [form, isEdit])

  useEffect(() => {
    api.get('/admin/sectors').then(r => setSectors(r.data)).catch(() => {})
    if (isEdit) {
      api.get(`/advisories/${id}`).then(r => {
        const a = r.data
        setForm({
          title: a.title || '', description: a.description || '', mitigation: a.mitigation || '',
          severity: a.severity || 'medium', cvss_score: a.cvss_score || '',
          sector_id: a.sector_id || '', cve_ids: a.cve_ids || [], iocs: a.iocs || [],
          affected_vendors: a.affected_vendors || [], attack_types: a.attack_types || [],
          apt_groups: a.apt_groups || [], mitre_ttps: a.mitre_ttps || [],
          is_zero_day: a.is_zero_day || false, zero_day_status: a.zero_day_status || '',
          source_url: a.source_url || '', status: a.status || 'pending',
        })
      }).catch(() => { toast.error('Failed to load'); navigate('/advisories') })
    }
  }, [id])

  const setF = (k, v) => setForm(f => ({ ...f, [k]: v }))
  const addTag    = (field, val) => setForm(f => ({ ...f, [field]: [...(f[field] || []), val] }))
  const removeTag = (field, i)   => setForm(f => ({ ...f, [field]: f[field].filter((_, idx) => idx !== i) }))
  const toggleAttack = t => {
    const idx = form.attack_types.indexOf(t)
    if (idx >= 0) removeTag('attack_types', idx)
    else addTag('attack_types', t)
  }

  const handleSubmit = async (forceStatus = null) => {
    setSaving(true)
    try {
      const payload = {
        ...form,
        status: forceStatus || form.status,
        cvss_score: form.cvss_score ? parseFloat(form.cvss_score) : null,
        sector_id: form.sector_id ? parseInt(form.sector_id) : null,
      }
      if (isEdit) {
        await api.put(`/advisories/${id}`, payload)
        toast.success('Advisory updated')
        navigate(`/advisories/${id}`)
      } else {
        const r = await api.post('/advisories', payload)
        if (forceStatus === 'published') await api.post(`/advisories/${r.data.id}/publish`)
        try { localStorage.removeItem(STORAGE_KEY) } catch {}
        toast.success('Advisory created')
        navigate(`/advisories/${r.data.id}`)
      }
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Save failed')
    } finally { setSaving(false) }
  }

  const canNext = () => {
    if (step === 1) return form.title.trim().length > 0
    if (step === 2) return form.description.trim().length > 0
    return true
  }

  const selectedSev = SEVERITY_OPTIONS.find(s => s.value === form.severity)

  return (
    <div className="max-w-2xl mx-auto space-y-6 pb-12 animate-in fade-in duration-500">
      <div className="flex items-center gap-3">
        <Link to={isEdit ? `/advisories/${id}` : '/advisories'}
          className="flex items-center gap-2 text-slate-400 hover:text-white text-xs font-bold uppercase tracking-wider transition-colors">
          <ArrowLeft className="w-4 h-4" />
          {isEdit ? 'Back to Advisory' : 'Back to Advisories'}
        </Link>
        {!isEdit && (
          <span className="ml-auto text-[10px] text-slate-600 font-mono">Draft auto-saved</span>
        )}
      </div>

      <div>
        <h1 className="text-2xl font-extrabold text-white">
          {isEdit ? 'Edit Advisory' : 'New Advisory'}
        </h1>
        <p className="text-slate-500 text-sm mt-1">
          {STEPS[step - 1].desc}
        </p>
      </div>

      <StepIndicator current={step} total={STEPS.length} />

      {/* ── Step 1: Basics ─────────────────────────────────────────────────── */}
      {step === 1 && (
        <div className="space-y-5 animate-in slide-in-from-right-4 fade-in duration-300">
          {/* Title */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Advisory Title</h2>
            <input
              className="w-full bg-slate-950/50 border border-slate-700/60 text-white rounded-xl px-4 py-3 text-sm placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/40 transition-all"
              value={form.title}
              onChange={e => setF('title', e.target.value)}
              placeholder="e.g. CVE-2024-3400 Palo Alto PAN-OS Remote Code Execution"
              required
            />
            <div className="flex items-center justify-between text-[10px]">
              <span className="text-slate-600">{form.title.length}/200 characters</span>
              {form.title.length > 0 && <span className="text-green-400 font-bold">✓ Good</span>}
            </div>
          </div>

          {/* Severity selector */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Severity Level</h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {SEVERITY_OPTIONS.map(s => (
                <button key={s.value} type="button" onClick={() => setF('severity', s.value)}
                  className={clsx(
                    'flex flex-col items-start gap-1 p-3 rounded-xl border transition-all text-left',
                    form.severity === s.value
                      ? 'border-blue-500/50 bg-blue-500/10 ring-1 ring-blue-500/30'
                      : 'border-slate-700/60 bg-slate-950/30 hover:border-slate-600'
                  )}>
                  <div className="flex items-center gap-2 w-full">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: s.color }} />
                    <span className="text-xs font-black text-white">{s.label}</span>
                    {form.severity === s.value && <Check className="w-3 h-3 text-blue-400 ml-auto" />}
                  </div>
                  <span className="text-[10px] text-slate-500 leading-tight">{s.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* CVSS + Sector + Source */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Scoring & Metadata</h2>
            <CvssSlider value={form.cvss_score} onChange={v => setF('cvss_score', v)} />
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">Sector</label>
                <select
                  className="w-full bg-slate-950/50 border border-slate-700/60 text-slate-300 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/30 transition-all"
                  value={form.sector_id} onChange={e => setF('sector_id', e.target.value)}>
                  <option value="">— No Sector —</option>
                  {sectors.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">Status</label>
                <select
                  className="w-full bg-slate-950/50 border border-slate-700/60 text-slate-300 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/30 transition-all"
                  value={form.status} onChange={e => setF('status', e.target.value)}>
                  {['pending', 'published', 'archived'].map(s => (
                    <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                  ))}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">Source URL</label>
              <div className="relative">
                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                <input
                  type="url"
                  className="w-full bg-slate-950/50 border border-slate-700/60 text-white rounded-xl pl-10 pr-4 py-2.5 text-sm placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 transition-all"
                  value={form.source_url} onChange={e => setF('source_url', e.target.value)}
                  placeholder="https://nvd.nist.gov/vuln/detail/..."
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Step 2: Content ────────────────────────────────────────────────── */}
      {step === 2 && (
        <div className="space-y-5 animate-in slide-in-from-right-4 fade-in duration-300">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Description *</h2>
              <button type="button" onClick={() => setShowPreview(v => !v)}
                className="flex items-center gap-1.5 text-[10px] font-bold text-slate-500 hover:text-white transition-colors uppercase tracking-wider">
                {showPreview ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                {showPreview ? 'Edit' : 'Preview'}
              </button>
            </div>
            {showPreview ? (
              <div className="min-h-[160px] bg-slate-950/40 border border-slate-700/40 rounded-xl p-4 text-sm text-slate-300 leading-relaxed prose prose-invert max-w-none"
                dangerouslySetInnerHTML={{ __html: form.description.replace(/\n/g, '<br>') || '<span class="text-slate-600">Nothing to preview yet...</span>' }} />
            ) : (
              <textarea
                className="w-full bg-slate-950/50 border border-slate-700/60 text-white rounded-xl px-4 py-3 text-sm placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/40 transition-all resize-none"
                rows={8}
                value={form.description}
                onChange={e => setF('description', e.target.value)}
                placeholder="Detailed vulnerability description. Supports plain text or basic markdown..."
                required
              />
            )}
            <div className="text-[10px] text-slate-600 text-right">{form.description.length} characters</div>
          </div>

          <div className="rounded-2xl border border-emerald-500/15 bg-emerald-950/10 p-5 space-y-3">
            <h2 className="text-xs font-black text-emerald-400/80 uppercase tracking-widest">Mitigation Steps</h2>
            <textarea
              className="w-full bg-slate-950/50 border border-slate-700/60 text-white rounded-xl px-4 py-3 text-sm placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500/30 transition-all resize-none"
              rows={5}
              value={form.mitigation}
              onChange={e => setF('mitigation', e.target.value)}
              placeholder="Step-by-step remediation guidance: patch versions, config changes, workarounds..."
            />
            <div className="text-[10px] text-slate-600 text-right">{form.mitigation.length} characters</div>
          </div>
        </div>
      )}

      {/* ── Step 3: Classification ─────────────────────────────────────────── */}
      {step === 3 && (
        <div className="space-y-5 animate-in slide-in-from-right-4 fade-in duration-300">
          {/* CVE IDs */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Vulnerability Identifiers</h2>
            <TagInput
              label="CVE IDs"
              placeholder="CVE-2024-XXXX (press Enter to add)"
              tags={form.cve_ids}
              onAdd={v => addTag('cve_ids', v)}
              onRemove={i => removeTag('cve_ids', i)}
              chipClass="font-mono bg-cyan-950/40 text-cyan-300 border-cyan-800/40"
            />
            <TagInput
              label="Affected Vendors"
              placeholder="e.g. Palo Alto, Cisco, Microsoft..."
              tags={form.affected_vendors}
              onAdd={v => addTag('affected_vendors', v)}
              onRemove={i => removeTag('affected_vendors', i)}
              chipClass="bg-slate-800 text-slate-300 border-slate-700"
            />
          </div>

          {/* Attack types */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Attack Vectors</h2>
            <div className="flex flex-wrap gap-2">
              {ATTACK_TYPES.map(t => (
                <button key={t} type="button" onClick={() => toggleAttack(t)}
                  className={clsx(
                    'text-xs px-2.5 py-1.5 rounded-lg border transition-all font-bold',
                    form.attack_types.includes(t)
                      ? 'bg-orange-500/15 text-orange-300 border-orange-500/35'
                      : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-slate-600'
                  )}>
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* MITRE TTPs + APT Groups */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Threat Intelligence</h2>
            <TagInput
              label="MITRE ATT&CK TTPs"
              placeholder="e.g. T1190, T1059.001..."
              tags={form.mitre_ttps}
              onAdd={v => addTag('mitre_ttps', v)}
              onRemove={i => removeTag('mitre_ttps', i)}
              chipClass="font-mono bg-cyan-950/30 text-cyan-300 border-cyan-800/30"
            />
            <TagInput
              label="APT Groups"
              placeholder="e.g. APT29, Lazarus Group..."
              tags={form.apt_groups}
              onAdd={v => addTag('apt_groups', v)}
              onRemove={i => removeTag('apt_groups', i)}
              chipClass="bg-rose-950/20 text-rose-400 border-rose-800/30"
            />
          </div>

          {/* Zero-day */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Zero-Day Classification</h2>
            <label className="flex items-center gap-3 cursor-pointer group">
              <div
                onClick={() => setF('is_zero_day', !form.is_zero_day)}
                className={clsx(
                  'w-11 h-6 rounded-full transition-all border relative flex-shrink-0 cursor-pointer',
                  form.is_zero_day
                    ? 'bg-red-500/80 border-red-500/50'
                    : 'bg-slate-800 border-slate-700'
                )}>
                <div className={clsx('absolute top-0.5 left-0.5 w-5 h-5 rounded-full transition-all duration-200 bg-white shadow',
                  form.is_zero_day ? 'translate-x-5' : 'translate-x-0')} />
              </div>
              <div>
                <div className="text-sm font-bold text-white">Mark as Zero-Day</div>
                <div className="text-[10px] text-slate-500">Vulnerability exploited before patch was available</div>
              </div>
            </label>
            {form.is_zero_day && (
              <select
                className="w-full bg-slate-950/50 border border-slate-700/60 text-slate-300 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/20 transition-all"
                value={form.zero_day_status} onChange={e => setF('zero_day_status', e.target.value)}>
                <option value="">Select status...</option>
                <option value="Exploited in the Wild">Exploited in the Wild</option>
                <option value="Patch Available">Patch Available</option>
                <option value="Mitigated">Mitigated</option>
                <option value="Under Investigation">Under Investigation</option>
              </select>
            )}
          </div>
        </div>
      )}

      {/* ── Step 4: Review ─────────────────────────────────────────────────── */}
      {step === 4 && (
        <div className="space-y-5 animate-in slide-in-from-right-4 fade-in duration-300">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest mb-4">Preview</h2>
            <div className="rounded-xl border border-slate-700/60 bg-slate-950/50 p-4 space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2.5 py-0.5 rounded text-[10px] font-black uppercase border" style={{
                  background: `${selectedSev?.color}20`,
                  borderColor: `${selectedSev?.color}40`,
                  color: selectedSev?.color
                }}>{selectedSev?.label}</span>
                {form.is_kev && <span className="text-[10px] font-black px-2 py-0.5 rounded border border-purple-500/25 bg-purple-500/10 text-purple-400">KEV</span>}
                {form.is_zero_day && <span className="text-[10px] font-black px-2 py-0.5 rounded border border-red-500/25 bg-red-500/10 text-red-400 flex items-center gap-1"><Zap className="w-2.5 h-2.5" />0-Day</span>}
              </div>
              <h3 className="text-base font-black text-white leading-tight">{form.title || 'Untitled Advisory'}</h3>
              {form.cvss_score && (
                <div className="text-sm font-black tabular-nums" style={{ color: parseFloat(form.cvss_score) >= 9 ? '#ef4444' : parseFloat(form.cvss_score) >= 7 ? '#f97316' : '#eab308' }}>
                  CVSS: {parseFloat(form.cvss_score).toFixed(1)}
                </div>
              )}
              {form.cve_ids.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {form.cve_ids.map(c => <span key={c} className="font-mono text-[10px] text-cyan-400 bg-cyan-950/30 px-2 py-0.5 rounded border border-cyan-800/30">{c}</span>)}
                </div>
              )}
              {form.description && (
                <p className="text-xs text-slate-500 line-clamp-3">{form.description}</p>
              )}
            </div>
          </div>

          {/* Summary table */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
            <h2 className="text-xs font-black text-slate-400 uppercase tracking-widest">Submission Summary</h2>
            <div className="grid grid-cols-2 gap-3 text-xs">
              {[
                { label: 'Severity',      value: form.severity },
                { label: 'CVSS',          value: form.cvss_score ? `${parseFloat(form.cvss_score).toFixed(1)}` : 'Not set' },
                { label: 'CVEs',          value: form.cve_ids.length ? form.cve_ids.join(', ') : 'None' },
                { label: 'Attack types',  value: form.attack_types.length ? `${form.attack_types.length} selected` : 'None' },
                { label: 'MITRE TTPs',    value: form.mitre_ttps.length ? form.mitre_ttps.join(', ') : 'None' },
                { label: 'Zero-Day',      value: form.is_zero_day ? (form.zero_day_status || 'Yes') : 'No' },
                { label: 'Vendors',       value: form.affected_vendors.length ? form.affected_vendors.join(', ') : 'None' },
                { label: 'Source',        value: form.source_url ? 'Provided' : 'Not set' },
              ].map(r => (
                <div key={r.label} className="rounded-lg bg-slate-950/40 border border-slate-800 p-3">
                  <div className="text-[10px] font-bold text-slate-600 uppercase tracking-wider mb-0.5">{r.label}</div>
                  <div className="text-slate-200 font-semibold truncate">{r.value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Submit buttons */}
          <div className="flex flex-col sm:flex-row gap-3">
            <button type="button" onClick={() => handleSubmit()} disabled={saving}
              className="flex-1 flex items-center justify-center gap-2 px-5 py-3 bg-slate-700 hover:bg-slate-600 border border-slate-600 text-white text-sm font-black uppercase tracking-wider rounded-xl transition-all disabled:opacity-50">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              Save as Draft
            </button>
            <button type="button" onClick={() => handleSubmit('published')} disabled={saving}
              className="flex-1 flex items-center justify-center gap-2 px-5 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-sm font-black uppercase tracking-wider rounded-xl transition-all shadow-lg disabled:opacity-50">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
              {isEdit ? 'Update Advisory' : 'Publish Now'}
            </button>
          </div>
        </div>
      )}

      {/* ── Nav buttons ───────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
        <button type="button" onClick={() => setStep(s => Math.max(1, s - 1))} disabled={step === 1}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 text-sm font-bold transition-all disabled:opacity-30">
          <ArrowLeft className="w-4 h-4" /> Previous
        </button>

        {step < 4 ? (
          <button type="button" onClick={() => setStep(s => s + 1)} disabled={!canNext()}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm font-black uppercase tracking-wider transition-all">
            Next <ArrowRight className="w-4 h-4" />
          </button>
        ) : (
          <Link to={isEdit ? `/advisories/${id}` : '/advisories'}
            className="text-sm text-slate-500 hover:text-white transition-colors">
            Cancel
          </Link>
        )}
      </div>
    </div>
  )
}
