import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, Lock, User, Terminal, ChevronRight, Fingerprint, Activity } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import toast from 'react-hot-toast'
import { motion } from 'framer-motion'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 })

  useEffect(() => {
    const handleMouseMove = (e) => {
      setMousePosition({ x: e.clientX, y: e.clientY })
    }
    window.addEventListener('mousemove', handleMouseMove)
    return () => window.removeEventListener('mousemove', handleMouseMove)
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await login(form.username, form.password)
      toast.success('Authentication Successful')
      navigate('/dashboard')
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Authentication Failed')
    } finally {
      setLoading(false)
    }
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { 
      opacity: 1,
      transition: { staggerChildren: 0.1, delayChildren: 0.8 }
    }
  }

  const itemVariants = {
    hidden: { opacity: 0, y: 20, filter: 'blur(10px)' },
    visible: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.5, ease: "easeOut" } }
  }

  // Glitch animation for text
  const glitchVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      x: [-2, 2, -1, 1, 0],
      transition: { duration: 0.3, delay: 1 }
    },
    hover: {
      x: [-3, 3, -3, 3, 0],
      textShadow: ["-2px 0 red, 2px 0 cyan", "2px 0 red, -2px 0 cyan", "0 0 transparent"],
      transition: { duration: 0.2, repeat: Infinity, repeatType: "mirror" }
    }
  }

  return (
    <div className="min-h-screen bg-[#00050b] flex items-center justify-center p-4 relative overflow-hidden font-mono">
      
      {/* Dynamic Hexagon Grid Background */}
      <div className="absolute inset-0 z-0 opacity-10 pointer-events-none"
           style={{
             backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='103.92304845413264' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M30 103.92304845413264L0 86.60254037844386L0 51.96152422706632L30 34.64101615137754L60 51.96152422706632L60 86.60254037844386Z' stroke='%233b82f6' fill='none' stroke-width='1'/%3E%3C/svg%3E")`,
             backgroundSize: '60px 103.9px',
           }}
      />

      {/* Cyber Scanning Line */}
      <motion.div 
        className="absolute top-0 left-0 right-0 h-[2px] bg-cyan-400 shadow-[0_0_20px_4px_rgba(34,211,238,0.5)] z-20 pointer-events-none opacity-50"
        animate={{ y: ['0vh', '100vh'] }}
        transition={{ duration: 4, ease: "linear", repeat: Infinity }}
      />

      {/* Animated Background Gradients tracking mouse */}
      <motion.div 
        className="absolute w-[800px] h-[800px] rounded-full blur-[150px] bg-gradient-to-tr from-cyan-900/30 via-blue-900/20 to-purple-900/30 opacity-80 pointer-events-none z-0"
        animate={{
          x: mousePosition.x - 400,
          y: mousePosition.y - 400,
        }}
        transition={{ type: "tween", ease: "backOut", duration: 1.5 }}
      />

      <motion.div 
        className="w-full max-w-[440px] relative z-10"
        initial={{ opacity: 0, scale: 1.1, filter: 'blur(20px)' }}
        animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
        transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
      >
        {/* Main Cyber Card */}
        <div className="backdrop-blur-2xl bg-[#030a16]/80 border-[0.5px] border-cyan-500/30 rounded-[1rem] p-8 shadow-[0_0_50px_rgba(6,182,212,0.15)] relative overflow-hidden group">
          
          {/* Cyberpunk corner accents */}
          <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-cyan-400 rounded-tl-[1rem]" />
          <div className="absolute top-0 right-0 w-8 h-8 border-t-2 border-r-2 border-cyan-400 rounded-tr-[1rem]" />
          <div className="absolute bottom-0 left-0 w-8 h-8 border-b-2 border-l-2 border-cyan-400 rounded-bl-[1rem]" />
          <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-cyan-400 rounded-br-[1rem]" />

          {/* Random Binary Background overlay */}
          <div className="absolute inset-0 opacity-[0.03] pointer-events-none select-none text-[8px] break-all text-cyan-400 overflow-hidden leading-tight font-mono">
            {Array.from({ length: 1500 }).map(() => Math.round(Math.random())).join('')}
          </div>

          <motion.div 
            className="text-center mb-10 relative z-10"
            variants={containerVariants}
            initial="hidden"
            animate="visible"
          >
            {/* Crazy Animated Logo */}
            <motion.div variants={itemVariants} className="relative inline-flex items-center justify-center w-28 h-28 mb-6 mx-auto">
              {/* Outer rotating dashed ring */}
              <motion.div 
                className="absolute inset-0 border-2 border-dashed border-cyan-500/40 rounded-full"
                animate={{ rotate: 360 }}
                transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
              />
              {/* Inner fast rotating ring */}
              <motion.div 
                className="absolute inset-2 border-2 border-dotted border-blue-500/60 rounded-full"
                animate={{ rotate: -360 }}
                transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
              />
              {/* Center pulsing glow */}
              <div className="absolute inset-4 bg-cyan-500/20 blur-xl rounded-full animate-pulse" />
              
              <Shield className="w-12 h-12 text-cyan-400 drop-shadow-[0_0_15px_rgba(34,211,238,0.8)] relative z-10" />
            </motion.div>

            <motion.h1 
              variants={glitchVariants} 
              whileHover="hover"
              className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 via-blue-400 to-purple-400 tracking-tighter mb-2 cursor-crosshair uppercase"
            >
              SecureEye_OS
            </motion.h1>
            <motion.div variants={itemVariants} className="flex items-center justify-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400 animate-pulse" />
              <p className="text-[11px] font-bold text-emerald-400/80 tracking-[0.3em] uppercase">
                Neural Uplink Active
              </p>
            </motion.div>
          </motion.div>

          <motion.form 
            onSubmit={handleSubmit} 
            className="space-y-6 relative z-10"
            variants={containerVariants}
            initial="hidden"
            animate="visible"
          >
            <motion.div variants={itemVariants} className="space-y-2">
              <label className="text-[10px] font-bold text-cyan-400/80 uppercase tracking-widest ml-1 flex items-center gap-2">
                <Terminal className="w-3 h-3" /> Identity Matrix
              </label>
              <div className="relative group">
                <div className="absolute inset-0 bg-cyan-500/10 blur-md opacity-0 group-focus-within:opacity-100 transition-opacity duration-300" />
                <User className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-700 group-focus-within:text-cyan-400 transition-colors z-10" />
                <input
                  className="w-full bg-[#020813] border border-cyan-900/50 rounded-none pl-11 pr-4 py-3.5 text-cyan-100 placeholder-cyan-900 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all relative z-10 font-mono text-sm"
                  placeholder="USER_ID"
                  value={form.username}
                  onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                  required
                  autoFocus
                />
                {/* Cyber accent line */}
                <div className="absolute bottom-0 left-0 h-[2px] bg-cyan-400 w-0 group-focus-within:w-full transition-all duration-500 z-20" />
              </div>
            </motion.div>

            <motion.div variants={itemVariants} className="space-y-2">
              <label className="text-[10px] font-bold text-cyan-400/80 uppercase tracking-widest ml-1 flex items-center gap-2">
                <Fingerprint className="w-3 h-3" /> Auth Token
              </label>
              <div className="relative group">
                <div className="absolute inset-0 bg-cyan-500/10 blur-md opacity-0 group-focus-within:opacity-100 transition-opacity duration-300" />
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-700 group-focus-within:text-cyan-400 transition-colors z-10" />
                <input
                  className="w-full bg-[#020813] border border-cyan-900/50 rounded-none pl-11 pr-12 py-3.5 text-cyan-100 placeholder-cyan-900 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all relative z-10 font-mono tracking-[0.3em] text-sm"
                  type={showPass ? 'text' : 'password'}
                  placeholder="••••••••"
                  value={form.password}
                  onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                  required
                />
                <button type="button" onClick={() => setShowPass(v => !v)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-cyan-700 hover:text-cyan-400 transition-colors z-10">
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <div className="absolute bottom-0 left-0 h-[2px] bg-cyan-400 w-0 group-focus-within:w-full transition-all duration-500 z-20" />
              </div>
            </motion.div>

            <motion.div variants={itemVariants} className="pt-4">
              <button 
                type="submit" 
                disabled={loading} 
                className="w-full relative group overflow-hidden bg-cyan-500/10 border border-cyan-500/50 hover:border-cyan-400 transition-colors"
              >
                {/* Glitch hover background */}
                <span className="absolute inset-0 w-0 bg-cyan-400 group-hover:w-full transition-all duration-500 ease-in-out opacity-20" />
                
                <div className="relative px-8 py-4 flex items-center justify-center gap-3">
                  {loading ? (
                    <>
                      <div className="w-5 h-5 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
                      <span className="text-cyan-400 tracking-[0.2em] uppercase font-bold text-xs">Authenticating...</span>
                    </>
                  ) : (
                    <>
                      <span className="text-cyan-400 group-hover:text-cyan-100 tracking-[0.2em] uppercase font-bold text-xs transition-colors">Establish Connection</span>
                      <ChevronRight className="w-4 h-4 text-cyan-500 group-hover:text-cyan-100 group-hover:translate-x-2 transition-all" />
                    </>
                  )}
                </div>
              </button>
            </motion.div>
          </motion.form>

          {/* Quick Access Demo */}
          <motion.div 
            className="mt-8 pt-6 border-t border-cyan-900/50 relative z-10"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.2, duration: 0.5 }}
          >
            <div className="flex items-center gap-2 mb-4 justify-center">
              <p className="text-[9px] font-bold text-cyan-600 uppercase tracking-[0.3em]">Load Simulation Profiles</p>
            </div>
            <div className="grid grid-cols-3 gap-2">
              {[
                { role: 'SYS_ADMIN', user: 'admin', pass: 'Admin@12345', color: 'text-red-400', border: 'border-red-900/50 hover:border-red-500 bg-red-950/20', hover: 'hover:bg-red-500/10' },
                { role: 'ANALYST', user: 'analyst', pass: 'Analyst@12345', color: 'text-blue-400', border: 'border-blue-900/50 hover:border-blue-500 bg-blue-950/20', hover: 'hover:bg-blue-500/10' },
                { role: 'VIEWER', user: 'viewer', pass: 'Viewer@12345', color: 'text-emerald-400', border: 'border-emerald-900/50 hover:border-emerald-500 bg-emerald-950/20', hover: 'hover:bg-emerald-500/10' },
              ].map(c => (
                <motion.button 
                  key={c.role}
                  whileHover={{ scale: 1.05, y: -2 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => setForm({ username: c.user, password: c.pass })}
                  className={`relative overflow-hidden border ${c.border} ${c.hover} transition-all group p-2 flex flex-col items-center justify-center`}
                >
                  <span className={`text-[9px] font-black tracking-widest ${c.color} relative z-10 mb-0.5`}>{c.role}</span>
                  <span className="text-[8px] font-mono text-cyan-600 relative z-10">{c.user}</span>
                </motion.button>
              ))}
            </div>
          </motion.div>
        </div>

        <motion.div 
          className="text-center mt-6 space-y-2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.5, duration: 1 }}
        >
          <p className="text-[10px] font-mono text-cyan-600/50 uppercase tracking-[0.3em]">
            Warning: Restricted System Access
          </p>
        </motion.div>
      </motion.div>
    </div>
  )
}
