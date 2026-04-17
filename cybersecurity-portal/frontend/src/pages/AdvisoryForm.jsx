import { useEffect, useState } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { ArrowLeft, Plus, X, Save } from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'

const ATTACK_TYPES = ['RCE', 'SQLi', 'XSS', 'SSRF', 'LFI', 'XXE', 'Auth Bypass', 'Privilege Escalation', 'DoS', 'CSRF', 'Path Traversal', 'Deserialization', 'Supply Chain']

export default function AdvisoryForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const isEdit = !!id
  const [sectors, setSectors] = useState([])
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState({
    title: '', description: '', mitigation: '',
    severity: 'medium', cvss_score: '', sector_id: '',
    cve_ids: [], iocs: [], affected_vendors: [],
    attack_types: [], apt_groups: [], mitre_ttps: [],
    is_zero_day: false, zero_day_status: '', source_url: '',
    status: 'pending'
  })
  const [cveInput, setCveInput] = useState('')
  const [vendorInput, setVendorInput] = useState('')
  const [ttpInput, setTtpInput] = useState('')
  const [iocInput, setIocInput] = useState({ type: 'ip', value: '' })

  useEffect(() => {
    api.get('/admin/sectors').then(r => setSectors(r.data)).catch(() => {})
    if (isEdit) {
      api.get(`/advisories/${id}`).then(r => {
        const a = r.data
        setForm({
          title: a.title || '',
          description: a.description || '',
          mitigation: a.mitigation || '',
          severity: a.severity || 'medium',
          cvss_score: a.cvss_score || '',
          sector_id: a.sector_id || '',
          cve_ids: a.cve_ids || [],
          iocs: a.iocs || [],
          affected_vendors: a.affected_vendors || [],
          attack_types: a.attack_types || [],
          apt_groups: a.apt_groups || [],
          mitre_ttps: a.mitre_ttps || [],
          is_zero_day: a.is_zero_day || false,
          zero_day_status: a.zero_day_status || '',
          source_url: a.source_url || '',
          status: a.status || 'pending',
        })
      }).catch(() => { toast.error('Failed to load advisory'); navigate('/advisories') })
    }
  }, [id])

  const setF = (k, v) => setForm(f => ({ ...f, [k]: v }))
  const addTag = (field, val, clear) => {
    if (!val.trim()) return
    setForm(f => ({ ...f, [field]: [...(f[field] || []), val.trim()] }))
    clear('')
  }
  const removeTag = (field, i) => setForm(f => ({ ...f, [field]: f[field].filter((_, idx) => idx !== i) }))

  const handleSubmit = async (e, forceStatus = null) => {
    if (e) e.preventDefault()
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
        if (forceStatus === 'published') {
            await api.post(`/advisories/${r.data.id}/publish`)
        }
        toast.success('Advisory created')
        navigate(`/advisories/${r.data.id}`)
      }
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Save failed')
    } finally { setSaving(false) }
  }

  return (
    <div className="max-w-3xl space-y-5">
      <Link to={isEdit ? `/advisories/${id}` : '/advisories'}
        className="inline-flex items-center gap-2 text-slate-400 hover:text-white text-sm transition-colors">
        <ArrowLeft className="w-4 h-4" /> {isEdit ? 'Back to Advisory' : 'Back to Advisories'}
      </Link>

      <h1 className="text-2xl font-bold text-white">{isEdit ? 'Edit Advisory' : 'New Advisory'}</h1>

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Basic */}
        <div className="card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Basic Information</h2>
          <div>
            <label className="block text-sm text-slate-400 mb-1">Title *</label>
            <input className="input" value={form.title} onChange={e => setF('title', e.target.value)} required placeholder="e.g. CVE-2024-3400 Palo Alto PAN-OS RCE..." />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Severity</label>
              <select className="input" value={form.severity} onChange={e => setF('severity', e.target.value)}>
                {['critical','high','medium','low','informational'].map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">CVSS Score (0–10)</label>
              <input className="input" type="number" min="0" max="10" step="0.1" value={form.cvss_score} onChange={e => setF('cvss_score', e.target.value)} placeholder="e.g. 9.8" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Sector</label>
              <select className="input" value={form.sector_id} onChange={e => setF('sector_id', e.target.value)}>
                <option value="">— No Sector —</option>
                {sectors.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Source URL</label>
              <input className="input" type="url" value={form.source_url} onChange={e => setF('source_url', e.target.value)} placeholder="https://nvd.nist.gov/..." />
            </div>
          </div>
        </div>

        {/* Description */}
        <div className="card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Content</h2>
          <div>
            <label className="block text-sm text-slate-400 mb-1">Description *</label>
            <textarea className="input resize-none" rows={5} required value={form.description} onChange={e => setF('description', e.target.value)} placeholder="Detailed vulnerability description..." />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">Mitigation Steps</label>
            <textarea className="input resize-none" rows={3} value={form.mitigation} onChange={e => setF('mitigation', e.target.value)} placeholder="Apply patches, workarounds, or mitigations..." />
          </div>
        </div>

        {/* CVEs & Vendors */}
        <div className="card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Classification</h2>

          {/* CVE IDs */}
          <div>
            <label className="block text-sm text-slate-400 mb-1">CVE IDs</label>
            <div className="flex gap-2 mb-2">
              <input className="input" placeholder="CVE-2024-XXXX" value={cveInput} onChange={e => setCveInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addTag('cve_ids', cveInput, setCveInput))} />
              <button type="button" onClick={() => addTag('cve_ids', cveInput, setCveInput)}
                className="btn-ghost text-blue-400 px-3"><Plus className="w-4 h-4" /></button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {form.cve_ids.map((c, i) => (
                <span key={i} className="font-mono text-xs bg-blue-950/40 text-blue-300 border border-blue-800/50 px-2 py-0.5 rounded flex items-center gap-1">
                  {c} <button type="button" onClick={() => removeTag('cve_ids', i)}><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          </div>

          {/* Attack Types */}
          <div>
            <label className="block text-sm text-slate-400 mb-1">Attack Types</label>
            <div className="flex flex-wrap gap-1.5 mb-2">
              {ATTACK_TYPES.map(t => (
                <button key={t} type="button"
                  onClick={() => form.attack_types.includes(t) ? removeTag('attack_types', form.attack_types.indexOf(t)) : addTag('attack_types', t, () => {})}
                  className={`text-xs px-2 py-0.5 rounded border transition-colors ${form.attack_types.includes(t) ? 'bg-orange-900/40 text-orange-300 border-orange-700/50' : 'bg-dark-800 text-slate-400 border-dark-600 hover:border-slate-500'}`}>
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Vendors */}
          <div>
            <label className="block text-sm text-slate-400 mb-1">Affected Vendors</label>
            <div className="flex gap-2 mb-2">
              <input className="input" placeholder="e.g. Palo Alto, Cisco…" value={vendorInput} onChange={e => setVendorInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addTag('affected_vendors', vendorInput, setVendorInput))} />
              <button type="button" onClick={() => addTag('affected_vendors', vendorInput, setVendorInput)} className="btn-ghost text-blue-400 px-3"><Plus className="w-4 h-4" /></button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {form.affected_vendors.map((v, i) => (
                <span key={i} className="text-xs bg-dark-800 text-slate-300 border border-dark-600 px-2 py-0.5 rounded flex items-center gap-1">
                  {v} <button type="button" onClick={() => removeTag('affected_vendors', i)}><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          </div>

          {/* MITRE TTPs */}
          <div>
            <label className="block text-sm text-slate-400 mb-1">MITRE ATT&CK TTPs</label>
            <div className="flex gap-2 mb-2">
              <input className="input" placeholder="e.g. T1190, T1059…" value={ttpInput} onChange={e => setTtpInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addTag('mitre_ttps', ttpInput, setTtpInput))} />
              <button type="button" onClick={() => addTag('mitre_ttps', ttpInput, setTtpInput)} className="btn-ghost text-blue-400 px-3"><Plus className="w-4 h-4" /></button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {form.mitre_ttps.map((t, i) => (
                <span key={i} className="text-xs font-mono bg-cyan-950/30 text-cyan-300 border border-cyan-800/50 px-2 py-0.5 rounded flex items-center gap-1">
                  {t} <button type="button" onClick={() => removeTag('mitre_ttps', i)}><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Zero-day */}
        <div className="card p-5 space-y-3">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Zero-Day</h2>
          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" className="w-4 h-4 accent-red-500"
              checked={form.is_zero_day} onChange={e => setF('is_zero_day', e.target.checked)} />
            <span className="text-slate-300">This is a Zero-Day vulnerability</span>
          </label>
          {form.is_zero_day && (
            <div>
              <label className="block text-sm text-slate-400 mb-1">Zero-Day Status</label>
              <select className="input" value={form.zero_day_status} onChange={e => setF('zero_day_status', e.target.value)}>
                <option value="">Select status…</option>
                <option value="Exploited in the Wild">Exploited in the Wild</option>
                <option value="Patch Available">Patch Available</option>
                <option value="Mitigated">Mitigated</option>
                <option value="Under Investigation">Under Investigation</option>
              </select>
            </div>
          )}
        </div>

        {/* Submit */}
        <div className="flex gap-3">
          <button type="submit" disabled={saving} className="btn-primary flex items-center gap-2">
            <Save className="w-4 h-4" />
            {saving ? 'Saving…' : isEdit ? 'Update Advisory' : 'Create Advisory'}
          </button>
          {!isEdit && (
            <button type="button" onClick={() => handleSubmit(null, 'published')} disabled={saving} className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex items-center gap-2">
              <Save className="w-4 h-4" /> Save & Publish
            </button>
          )}
          <Link to={isEdit ? `/advisories/${id}` : '/advisories'} className="btn-ghost">Cancel</Link>
        </div>
      </form>
    </div>
  )
}
