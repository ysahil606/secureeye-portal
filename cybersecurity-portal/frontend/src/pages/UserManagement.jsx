import { useEffect, useState } from 'react'
import { Users, Plus, Edit, Trash2, Shield, User } from 'lucide-react'
import api from '../services/api'
import { formatDateTime } from '../utils/helpers'
import { useAuth } from '../context/AuthContext'
import toast from 'react-hot-toast'

const ROLE_STYLES = {
  admin:   'text-red-400 bg-red-900/30 border-red-700/40',
  analyst: 'text-blue-400 bg-blue-900/30 border-blue-700/40',
  viewer:  'text-green-400 bg-green-900/30 border-green-700/40',
}

export default function UserManagement() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editUser, setEditUser] = useState(null)
  const [form, setForm] = useState({ email: '', username: '', full_name: '', password: '', role: 'viewer' })
  const [saving, setSaving] = useState(false)

  const load = () => {
    setLoading(true)
    api.get('/admin/users').then(r => setUsers(r.data)).catch(() => toast.error('Failed to load users')).finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  const openCreate = () => { setEditUser(null); setForm({ email: '', username: '', full_name: '', password: '', role: 'viewer' }); setShowForm(true) }
  const openEdit = (u) => { setEditUser(u); setForm({ full_name: u.full_name, role: u.role, is_active: u.is_active }); setShowForm(true) }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      if (editUser) {
        await api.put(`/admin/users/${editUser.id}`, form)
        toast.success('User updated')
      } else {
        await api.post('/admin/users', form)
        toast.success('User created')
      }
      setShowForm(false)
      load()
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Save failed')
    } finally { setSaving(false) }
  }

  const deleteUser = async (u) => {
    if (!confirm(`Delete user ${u.username}?`)) return
    try {
      await api.delete(`/admin/users/${u.id}`)
      toast.success('User deleted')
      load()
    } catch { toast.error('Failed to delete') }
  }

  const toggleActive = async (u) => {
    try {
      await api.put(`/admin/users/${u.id}`, { is_active: !u.is_active })
      toast.success(`User ${u.is_active ? 'deactivated' : 'activated'}`)
      load()
    } catch { toast.error('Failed to update') }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Users className="w-6 h-6 text-blue-400" /> User Management
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">{users.length} users registered</p>
        </div>
        <button onClick={openCreate} className="btn-primary flex items-center gap-2 text-sm">
          <Plus className="w-4 h-4" /> Add User
        </button>
      </div>

      {/* Form modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card w-full max-w-md p-6 shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-4">{editUser ? 'Edit User' : 'Create User'}</h2>
            <form onSubmit={handleSubmit} className="space-y-3">
              {!editUser && <>
                <input className="input" required placeholder="Username" value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
                <input className="input" required type="email" placeholder="Email" value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
                <input className="input" required type="password" placeholder="Password" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
              </>}
              <input className="input" required placeholder="Full Name" value={form.full_name || ''} onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))} />
              <select className="input" value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
              <div className="flex gap-2 pt-1">
                <button type="submit" disabled={saving} className="btn-primary flex-1">{saving ? 'Saving…' : editUser ? 'Update' : 'Create'}</button>
                <button type="button" onClick={() => setShowForm(false)} className="btn-ghost flex-1">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="flex justify-center py-12"><div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" /></div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-dark-800 border-b border-dark-600">
                <tr>
                  {['User', 'Role', 'Status', 'Alerts', 'Last Login', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs uppercase tracking-wider text-slate-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-600">
                {users.map(u => (
                  <tr key={u.id} className={`hover:bg-dark-700/50 transition-colors ${!u.is_active ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-xs font-bold text-white uppercase">{u.username[0]}</div>
                        <div>
                          <div className="font-medium text-white">{u.full_name}</div>
                          <div className="text-xs text-slate-500">{u.username} · {u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full border capitalize ${ROLE_STYLES[u.role] || ''}`}>{u.role}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs ${u.is_active ? 'text-green-400' : 'text-red-400'}`}>
                        {u.is_active ? '● Active' : '● Inactive'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">
                      {u.alert_subscribed ? (u.alert_critical_only ? 'Critical only' : 'All alerts') : 'None'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs whitespace-nowrap">{formatDateTime(u.last_login)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button onClick={() => openEdit(u)} className="text-slate-500 hover:text-blue-400 transition-colors"><Edit className="w-4 h-4" /></button>
                        <button onClick={() => toggleActive(u)} className={`text-xs ${u.is_active ? 'text-slate-500 hover:text-yellow-400' : 'text-slate-500 hover:text-green-400'} transition-colors`}>
                          {u.is_active ? 'Disable' : 'Enable'}
                        </button>
                        {u.id !== me?.id && (
                          <button onClick={() => deleteUser(u)} className="text-slate-500 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
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
    </div>
  )
}
