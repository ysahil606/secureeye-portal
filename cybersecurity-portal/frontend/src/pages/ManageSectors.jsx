import { useEffect, useState } from 'react'
import { Layers, Plus, Trash2 } from 'lucide-react'
import api from '../services/api'
import toast from 'react-hot-toast'

export default function ManageSectors() {
  const [sectors, setSectors] = useState([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState({ name: '', description: '' })
  const [saving, setSaving] = useState(false)

  const load = () => {
    api.get('/admin/sectors').then(r => setSectors(r.data)).catch(() => toast.error('Failed to load')).finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  const add = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      await api.post('/admin/sectors', form)
      setForm({ name: '', description: '' })
      toast.success('Sector added')
      load()
    } catch (err) { toast.error(err.response?.data?.detail || 'Failed') }
    finally { setSaving(false) }
  }

  const remove = async (id) => {
    if (!confirm('Deactivate this sector?')) return
    try {
      await api.delete(`/admin/sectors/${id}`)
      toast.success('Sector deactivated')
      load()
    } catch { toast.error('Failed') }
  }

  return (
    <div className="space-y-5 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Layers className="w-6 h-6 text-green-400" /> Manage Sectors
        </h1>
        <p className="text-slate-400 text-sm mt-0.5">Industry sectors for threat categorization</p>
      </div>

      <div className="card p-5">
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Add New Sector</h2>
        <form onSubmit={add} className="flex gap-3">
          <input className="input flex-1" required placeholder="Sector name (e.g. Telecom)"
            value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          <input className="input flex-1" placeholder="Description (optional)"
            value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          <button type="submit" disabled={saving} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" /> {saving ? '…' : 'Add'}
          </button>
        </form>
      </div>

      {loading ? (
        <div className="flex justify-center py-8"><div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" /></div>
      ) : (
        <div className="card divide-y divide-dark-600">
          {sectors.map(s => (
            <div key={s.id} className={`flex items-center justify-between px-5 py-3 ${!s.is_active ? 'opacity-50' : ''}`}>
              <div>
                <div className="font-medium text-white">{s.name}</div>
                {s.description && <div className="text-xs text-slate-500 mt-0.5">{s.description}</div>}
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-xs ${s.is_active ? 'text-green-400' : 'text-slate-500'}`}>
                  {s.is_active ? '● Active' : '● Inactive'}
                </span>
                {s.is_active && (
                  <button onClick={() => remove(s.id)} className="text-slate-500 hover:text-red-400 transition-colors">
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
