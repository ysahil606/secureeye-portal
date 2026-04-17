import { useState, useEffect } from 'react'
import { MessageSquare, Send, User, Clock, FileText, Upload, Shield } from 'lucide-react'
import api from '../services/api'
import { formatDateTime } from '../utils/helpers'
import { useAuth } from '../context/AuthContext'
import toast from 'react-hot-toast'

export default function WarRoom({ advisoryId }) {
  const { user } = useAuth()
  const [messages, setMessages] = useState([])
  const [evidence, setEvidence] = useState([])
  const [newMessage, setNewMessage] = useState('')
  const [uploading, setUploading] = useState(false)
  const [loading, setLoading] = useState(true)

  const loadData = async () => {
    try {
      const [msgRes, evRes] = await Promise.all([
        api.get(`/war-room/${advisoryId}/messages`),
        api.get(`/war-room/${advisoryId}/evidence`)
      ])
      setMessages(msgRes.data)
      setEvidence(evRes.data)
    } catch {
      toast.error('Failed to load War Room data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000) // Poll every 10s
    return () => clearInterval(interval)
  }, [advisoryId])

  const handleSendMessage = async (e) => {
    e.preventDefault()
    if (!newMessage.trim()) return
    try {
      const formData = new FormData()
      formData.append('content', newMessage)
      const r = await api.post(`/war-room/${advisoryId}/messages`, formData)
      setMessages(prev => [...prev, r.data])
      setNewMessage('')
    } catch { toast.error('Failed to send message') }
  }

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setUploading(true)
    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('description', `Evidence uploaded by ${user.username}`)
      const r = await api.post(`/war-room/${advisoryId}/evidence`, formData)
      setEvidence(prev => [...prev, r.data])
      toast.success('Evidence uploaded')
    } catch { toast.error('Upload failed') }
    finally { setUploading(false) }
  }

  if (loading) return null

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Chat Column */}
      <div className="lg:col-span-2 card flex flex-col h-[500px]">
        <div className="p-4 border-b border-dark-600 flex items-center gap-2">
          <MessageSquare className="w-4 h-4 text-blue-400" />
          <h2 className="font-bold text-white text-sm uppercase tracking-tight">Active Incident Chat</h2>
        </div>
        
        <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-dark-950/20">
          {messages.map(msg => (
            <div key={msg.id} className={`flex gap-3 ${msg.user_id === user.id ? 'flex-row-reverse' : ''}`}>
                <div className="w-8 h-8 rounded-full bg-dark-700 flex items-center justify-center text-[10px] font-bold text-blue-400 border border-dark-600">
                    {msg.user?.username?.[0].toUpperCase() || 'U'}
                </div>
                <div className={`max-w-[80%] space-y-1 ${msg.user_id === user.id ? 'items-end' : ''}`}>
                    <div className="flex items-center gap-2 text-[10px] text-slate-500">
                        <span className="font-bold text-slate-400">{msg.user?.username}</span>
                        <span>{formatDateTime(msg.created_at)}</span>
                    </div>
                    <div className={`p-3 rounded-2xl text-sm ${msg.user_id === user.id ? 'bg-blue-600 text-white rounded-tr-none' : 'bg-dark-800 text-slate-200 rounded-tl-none'}`}>
                        {msg.content}
                    </div>
                </div>
            </div>
          ))}
        </div>

        <form onSubmit={handleSendMessage} className="p-4 bg-dark-800 border-t border-dark-600 flex gap-2">
          <input 
            className="input text-sm flex-1" 
            placeholder="Type your finding..." 
            value={newMessage}
            onChange={e => setNewMessage(e.target.value)}
          />
          <button type="submit" className="btn-primary p-2 px-4"><Send className="w-4 h-4" /></button>
        </form>
      </div>

      {/* Evidence Column */}
      <div className="card flex flex-col h-[500px]">
        <div className="p-4 border-b border-dark-600 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            <h2 className="font-bold text-white text-sm uppercase tracking-tight">Evidence Log</h2>
          </div>
          <label className="cursor-pointer p-1.5 hover:bg-dark-700 rounded-lg transition-colors text-blue-400">
            <Upload className="w-4 h-4" />
            <input type="file" className="hidden" onChange={handleFileUpload} disabled={uploading} />
          </label>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar bg-dark-950/20">
          {evidence.map(ev => (
            <div key={ev.id} className="p-3 bg-dark-800 border border-dark-600 rounded-xl space-y-2">
                <div className="flex items-center gap-2 text-[10px] font-black text-slate-500 uppercase tracking-widest">
                    <FileText className="w-3 h-3 text-emerald-500" /> {ev.file_type?.split('/')[1] || 'FILE'}
                </div>
                <div className="text-xs font-bold text-white truncate">{ev.file_name}</div>
                <p className="text-[10px] text-slate-400 leading-tight">{ev.description}</p>
                <div className="text-[9px] text-slate-600 flex items-center gap-2">
                    <User className="w-2.5 h-2.5" /> {ev.user?.username} | <Clock className="w-2.5 h-2.5" /> {formatDateTime(ev.created_at)}
                </div>
            </div>
          ))}
          {evidence.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-center opacity-30 space-y-2">
                <Shield className="w-10 h-10" />
                <p className="text-xs">No technical evidence<br/>logged for this incident</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
