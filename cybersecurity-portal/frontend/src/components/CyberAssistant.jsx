import { useState, useRef, useEffect } from 'react'
import { Bot, Send, X, Minimize2, Maximize2, BrainCircuit, User } from 'lucide-react'
import api from '../services/api'
import clsx from 'clsx'
import { motion } from 'framer-motion'

export default function CyberAssistant() {
  const [isOpen, setIsOpen] = useState(false)
  const [isExpanded, setIsExpanded] = useState(false)
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Neural uplink established. I am your SecureEye Cyber Assistant. How can I assist you with threat intelligence today?' }
  ])
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, loading])

  const handleSend = async (e) => {
    e.preventDefault()
    if (!input.trim() || loading) return

    const userMsg = { role: 'user', content: input.trim() }
    const currentHistory = [...messages, userMsg]
    setMessages(currentHistory)
    setInput('')
    setLoading(true)

    try {
      const res = await api.post('/ai/chat', {
        message: userMsg.content,
        history: messages.slice(-10) // Send last 10 messages for context
      })
      
      setMessages([...currentHistory, { role: 'assistant', content: res.data.reply }])
    } catch (err) {
      setMessages([...currentHistory, { role: 'assistant', content: '[SYSTEM ERROR] Neural uplink failed to retrieve response.' }])
    } finally {
      setLoading(false)
    }
  }

  // Dragging logic
  const [position, setPosition] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const dragStart = useRef({ x: 0, y: 0 })
  const initialPos = useRef({ x: 0, y: 0 })
  const hasDragged = useRef(false)

  const handlePointerDown = (e) => {
    if (e.button !== 0) return
    setIsDragging(true)
    hasDragged.current = false
    dragStart.current = { x: e.clientX, y: e.clientY }
    initialPos.current = { ...position }
    e.currentTarget.setPointerCapture(e.pointerId)
  }

  const handlePointerMove = (e) => {
    if (!isDragging) return
    const dx = e.clientX - dragStart.current.x
    const dy = e.clientY - dragStart.current.y
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
      hasDragged.current = true
    }
    setPosition({
      x: initialPos.current.x + dx,
      y: initialPos.current.y + dy
    })
  }

  const handlePointerUp = (e) => {
    if (isDragging) {
      setIsDragging(false)
      e.currentTarget.releasePointerCapture(e.pointerId)
    }
  }

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end"
         style={{ transform: `translate(${position.x}px, ${position.y}px)`, touchAction: 'none' }}>
      
      {!isOpen && (
        <button 
          onClick={() => {
            if (!hasDragged.current) setIsOpen(true)
          }}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          className="relative w-16 h-16 rounded-full shadow-[0_0_40px_rgba(168,85,247,0.4)] flex items-center justify-center transition-all hover:scale-110 group border border-white/5 bg-dark-950 overflow-hidden cursor-move"
        >
          <div className="absolute inset-[-100%] animate-spin bg-[conic-gradient(from_0deg_at_50%_50%,#a855f7_0%,#3b82f6_25%,#a855f7_50%,#3b82f6_75%,#a855f7_100%)] opacity-50 group-hover:opacity-100 transition-opacity duration-500" style={{ animationDuration: '3s' }} />
          <div className="absolute inset-[2px] rounded-full bg-gradient-to-br from-dark-900 to-dark-950 flex items-center justify-center z-10 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 to-blue-500/20 blur-md group-hover:blur-xl transition-all duration-700" />
            <BrainCircuit className="w-8 h-8 text-purple-400 drop-shadow-[0_0_10px_rgba(168,85,247,0.8)] group-hover:text-white transition-colors duration-300 relative z-20" />
          </div>
          <div className="absolute inset-0 rounded-full border border-purple-500/50 animate-ping opacity-30 z-0" style={{ animationDuration: '2s' }} />
          <div className="absolute top-0 right-0 w-4 h-4 bg-emerald-400 rounded-full border-[2.5px] border-dark-950 flex items-center justify-center z-30 shadow-[0_0_15px_rgba(52,211,153,0.8)]">
            <div className="w-1.5 h-1.5 bg-white rounded-full animate-pulse" />
          </div>
          <span className="absolute right-20 bg-dark-900/90 backdrop-blur-md text-purple-100 text-[11px] uppercase tracking-widest px-4 py-2.5 rounded-xl opacity-0 group-hover:opacity-100 transition-all border border-purple-500/30 shadow-[0_0_20px_rgba(168,85,247,0.2)] font-black whitespace-nowrap z-50 pointer-events-none">
            Cyber Assistant
          </span>
        </button>
      )}

      {isOpen && (
        <div className={clsx(
          "border border-purple-500/20 rounded-2xl shadow-2xl transition-all duration-500 flex flex-col overflow-hidden max-w-[calc(100vw-2rem)]",
          "bg-dark-900/95 backdrop-blur-3xl shadow-[0_20px_60px_rgba(0,0,0,0.5)]",
          isExpanded ? 'h-[min(780px,calc(100vh-2rem))] w-[min(600px,calc(100vw-2rem))]' : 'h-[500px] w-[min(24rem,calc(100vw-2rem))]'
        )}>
          {/* Header */}
          <motion.div 
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            className="px-4 py-3 flex items-center justify-between border-b border-purple-500/20 bg-gradient-to-r from-[#030a16] via-purple-950/40 to-[#030a16] relative flex-shrink-0 cursor-move select-none"
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
          >
            <div className="flex items-center gap-3 relative z-10">
              <div className="relative w-9 h-9 bg-gradient-to-br from-purple-900/40 to-blue-900/40 border border-purple-500/30 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(168,85,247,0.3)] pointer-events-none">
                <BrainCircuit className="w-5 h-5 text-purple-400" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-400 rounded-full border-[2px] border-dark-900 animate-pulse" />
              </div>
              <div>
                <div className="font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-300 via-blue-400 to-cyan-400 text-sm tracking-widest uppercase">
                  Cyber Assistant
                </div>
                <div className="text-[9px] text-emerald-400 uppercase tracking-[0.2em] font-bold flex items-center gap-1.5 opacity-80">
                  <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-ping" />
                  Context-Aware AI
                </div>
              </div>
            </div>
            <div className="flex items-center gap-1 relative z-10" onPointerDown={(e) => e.stopPropagation()}>
              <button onClick={() => setIsExpanded(!isExpanded)} className="p-1.5 rounded-lg text-purple-700 hover:text-purple-400 hover:bg-purple-500/10 transition-colors">
                {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
              </button>
              <button onClick={() => setIsOpen(false)} className="p-1.5 rounded-lg text-purple-700 hover:text-red-400 hover:bg-red-500/10 transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
          </motion.div>

          {/* Chat Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar bg-[#02050a]">
            {messages.map((msg, idx) => (
              <div key={idx} className={clsx("flex gap-3", msg.role === 'user' ? "flex-row-reverse" : "")}>
                <div className={clsx(
                  "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-1",
                  msg.role === 'user' ? "bg-blue-900/30 border border-blue-500/30" : "bg-purple-900/30 border border-purple-500/30"
                )}>
                  {msg.role === 'user' ? <User className="w-4 h-4 text-blue-400" /> : <Bot className="w-4 h-4 text-purple-400" />}
                </div>
                <div className={clsx(
                  "max-w-[80%] rounded-2xl px-4 py-3 text-sm font-mono whitespace-pre-wrap leading-relaxed shadow-lg",
                  msg.role === 'user' 
                    ? "bg-gradient-to-br from-blue-900/40 to-blue-950/40 border border-blue-500/20 text-blue-50 rounded-tr-none" 
                    : "bg-gradient-to-br from-purple-900/20 to-[#030a16] border border-purple-500/20 text-purple-50/90 rounded-tl-none"
                )}>
                  {msg.content}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-lg bg-purple-900/30 border border-purple-500/30 flex items-center justify-center flex-shrink-0 mt-1">
                  <Bot className="w-4 h-4 text-purple-400 animate-pulse" />
                </div>
                <div className="bg-purple-900/20 border border-purple-500/20 rounded-2xl rounded-tl-none px-5 py-4 flex items-center gap-2">
                  <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="p-3 border-t border-purple-500/20 bg-dark-950">
            <form onSubmit={handleSend} className="relative flex items-center">
              <input
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                placeholder="Ask about active threats or search..."
                className="w-full bg-dark-900 border border-purple-500/30 rounded-xl pl-4 pr-12 py-3 text-sm text-white placeholder-purple-800 focus:outline-none focus:border-purple-400 focus:ring-1 focus:ring-purple-400 transition-all font-mono"
              />
              <button 
                type="submit" 
                disabled={!input.trim() || loading}
                className="absolute right-2 p-2 text-purple-400 hover:text-white hover:bg-purple-500/20 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
