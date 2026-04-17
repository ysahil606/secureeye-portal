import { useEffect, useState } from 'react'
import { Network, Plus, Trash2, Search, Globe, ExternalLink, Radar } from 'lucide-react'
import api from '../services/api'
import { useAuth } from '../context/AuthContext'
import { formatDateTime, truncate } from '../utils/helpers'
import toast from 'react-hot-toast'

const TYPE_COLORS = {
  ip: 'text-purple-400 bg-purple-900/30 border-purple-700/40',
  domain: 'text-cyan-400 bg-cyan-900/30 border-cyan-700/40',
  hash: 'text-yellow-400 bg-yellow-900/30 border-yellow-700/40',
  url: 'text-green-400 bg-green-900/30 border-green-700/40',
}

function TypeBadge({ type }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold ${TYPE_COLORS[type] || 'text-slate-400 border-dark-600'}`}>
      {(type || 'ioc').toUpperCase()}
    </span>
  )
}

function ExternalIOCRow({ item }) {
  return (
    <div className="card p-4 border border-dark-600 hover:border-blue-500/40 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-2">
            <TypeBadge type={item.ioc_type} />
            <span className="text-xs text-slate-300 bg-dark-800 px-2 py-0.5 rounded-full border border-dark-600">
              {item.source_name}
            </span>
          </div>
          <div className="font-mono text-slate-100 break-all">{item.value}</div>
          {item.display_url && (
            <div className="text-xs text-emerald-400 mt-1 truncate">{item.display_url}</div>
          )}
          {item.description && (
            <p className="text-sm text-slate-400 mt-2 leading-relaxed">
              {truncate(item.description.replace(/<[^>]+>/g, ' '), 220)}
            </p>
          )}
        </div>
        {item.source_url && (
          <a
            href={item.source_url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-slate-400 hover:text-blue-400 transition-colors flex items-center gap-1 text-sm"
          >
            <ExternalLink className="w-4 h-4" /> Open
          </a>
        )}
      </div>
    </div>
  )
}

export default function IOCManagement() {
  const { isAnalyst, isAdmin } = useAuth()
  const [localIocs, setLocalIocs] = useState([])
  const [externalItems, setExternalItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ value: '', ioc_type: 'ip', source: '', tags: [] })
  const [saving, setSaving] = useState(false)
  const [configurationHint, setConfigurationHint] = useState('')

  const loadTrackedIocs = async () => {
    setLoading(true)
    try {
      const params = {}
      if (typeFilter) params.ioc_type = typeFilter
      const r = await api.get('/admin/iocs', { params })
      setLocalIocs(r.data)
      setExternalItems([])
      setConfigurationHint('')
    } catch {
      toast.error('Failed to load IOCs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadTrackedIocs() }, [typeFilter])

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!search.trim()) {
      loadTrackedIocs()
      return
    }

    setLoading(true)
    try {
      const params = { search: search.trim() }
      if (typeFilter) params.ioc_type = typeFilter
      const r = await api.get('/admin/iocs/live-search', { params })
      setLocalIocs(r.data.local_items)
      setExternalItems(r.data.external_items)
      setConfigurationHint(r.data.configuration_hint || '')
    } catch (error) {
      toast.error(error?.response?.data?.detail || 'Failed to search IOCs')
    } finally {
      setLoading(false)
    }
  }

  const addIOC = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      const r = await api.post('/admin/iocs', form)
      setLocalIocs(prev => [r.data, ...prev])
      setForm({ value: '', ioc_type: 'ip', source: '', tags: [] })
      setShowForm(false)
      toast.success('IOC added')
    } catch {
      toast.error('Failed to add IOC')
    } finally {
      setSaving(false)
    }
  }

  const deleteIOC = async (id) => {
    if (!confirm('Delete this IOC?')) return
    try {
      await api.delete(`/admin/iocs/${id}`)
      setLocalIocs(prev => prev.filter(i => i.id !== id))
      toast.success('IOC deleted')
    } catch {
      toast.error('Failed to delete')
    }
  }

  const checkSandbox = async (hash) => {
    toast.loading('Searching malware sandbox...', { id: 'sb' })
    try {
      const r = await api.get(`/sandbox/report/${hash}`)
      if (r.data.found) {
        toast.success(`Verdict: ${r.data.verdict.toUpperCase()}`, { id: 'sb' })
        window.open(r.data.report_url, '_blank')
      } else {
        toast.error('No report found for this hash', { id: 'sb' })
      }
    } catch {
      toast.error('Sandbox service unavailable', { id: 'sb' })
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Network className="w-6 h-6 text-cyan-400" /> IOC Management
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">{localIocs.length} indicators tracked</p>
        </div>
        {isAnalyst && (
          <button onClick={() => setShowForm(v => !v)}
            className="btn-primary flex items-center gap-2 text-sm">
            <Plus className="w-4 h-4" /> Add IOC
          </button>
        )}
      </div>

      {showForm && (
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Add New IOC</h2>
          <form onSubmit={addIOC} className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <select className="input" value={form.ioc_type} onChange={e => setForm(f => ({ ...f, ioc_type: e.target.value }))}>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="hash">File Hash</option>
              <option value="url">URL</option>
            </select>
            <input className="input col-span-2" required placeholder="IOC value (e.g. 192.168.1.1, evil.com, abc123...)"
              value={form.value} onChange={e => setForm(f => ({ ...f, value: e.target.value }))} />
            <input className="input" placeholder="Source (optional)"
              value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value }))} />
            <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
              <button type="button" onClick={() => setShowForm(false)} className="btn-ghost">Cancel</button>
              <button type="submit" disabled={saving} className="btn-primary">
                {saving ? 'Adding...' : 'Add IOC'}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="card p-4 flex flex-wrap gap-3 items-center">
        <form onSubmit={handleSearch} className="flex gap-2 flex-1 min-w-[200px]">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input className="input pl-9 text-sm" placeholder="Search IOC values or run live IOC lookup..." value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <button type="submit" className="btn-primary text-sm">Search</button>
        </form>
        <select className="input w-auto text-sm" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">All Types</option>
          <option value="ip">IP Address</option>
          <option value="domain">Domain</option>
          <option value="hash">Hash</option>
          <option value="url">URL</option>
        </select>
      </div>

      {configurationHint && (
        <div className="card p-4 text-sm text-amber-300 border border-amber-700/30 bg-amber-950/20">
          {configurationHint}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
        </div>
      ) : (
        <div className="space-y-6">
          <section>
            <div className="flex items-center gap-2 mb-3">
              <Radar className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-semibold text-white">Live IOC Results</h2>
              <span className="text-xs text-slate-500">({externalItems.length})</span>
            </div>
            {externalItems.length === 0 ? (
              <div className="card p-12 text-center text-slate-500">No live IOC matches found.</div>
            ) : (
              <div className="space-y-3">
                {externalItems.map((item, index) => (
                  <ExternalIOCRow key={`${item.source_url || item.value}-${index}`} item={item} />
                ))}
              </div>
            )}
          </section>

          <section>
            <div className="flex items-center gap-2 mb-3">
              <Globe className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-white">Tracked IOCs</h2>
              <span className="text-xs text-slate-500">({localIocs.length})</span>
            </div>
            {localIocs.length === 0 ? (
              <div className="card p-12 text-center text-slate-500">No IOCs found.</div>
            ) : (
              <div className="card overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-dark-800 border-b border-dark-600">
                      <tr>
                        {['Type', 'Value', 'Source', 'First Seen', 'Tags', isAdmin ? 'Actions' : ''].filter(Boolean).map(h => (
                          <th key={h} className="text-left px-4 py-3 text-xs uppercase tracking-wider text-slate-500">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-dark-600">
                      {localIocs.map(ioc => (
                        <tr key={ioc.id} className="hover:bg-dark-700/50 transition-colors">
                          <td className="px-4 py-3"><TypeBadge type={ioc.ioc_type} /></td>
                          <td className="px-4 py-3 font-mono text-slate-200 break-all max-w-[250px]">{ioc.value}</td>
                          <td className="px-4 py-3 text-slate-400">{ioc.source || '-'}</td>
                          <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{formatDateTime(ioc.first_seen)}</td>
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1">
                              {(ioc.tags || []).map((t, i) => (
                                <span key={i} className="text-xs bg-dark-800 text-slate-400 border border-dark-600 px-1.5 py-0.5 rounded">{t}</span>
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              {ioc.ioc_type === 'hash' && (
                                <button onClick={() => checkSandbox(ioc.value)} className="text-blue-400 hover:text-blue-300 transition-colors p-1" title="Sandbox Quick Scan">
                                  <Radar className="w-4 h-4" />
                                </button>
                              )}
                              {isAdmin && (
                                <button onClick={() => deleteIOC(ioc.id)} className="text-slate-500 hover:text-red-400 transition-colors p-1">
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  )
}
