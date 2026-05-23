import { useEffect, useState, useRef, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Network, Plus, Trash2, Search, Globe, ExternalLink, Radar,
  Shield, AlertTriangle, Hash, Link2, Cpu, Zap, Eye, X,
  ChevronDown, Activity, Database, ScanLine, Lock, Filter,
  RefreshCw, Rss, TrendingUp, BarChart2, ChevronLeft, ChevronRight,
  FlaskConical, CheckCircle2, XCircle, Clock, Gauge, Copy, Check
} from 'lucide-react'
import api from '../services/api'
import { useAuth } from '../context/AuthContext'
import { formatDateTime, truncate } from '../utils/helpers'
import toast from 'react-hot-toast'

/* ─────────────── type config ─────────────── */
const TYPE_CONFIG = {
  ip:     { label: 'IP',     color: '#a855f7', glow: 'rgba(168,85,247,0.4)',  bg: 'rgba(168,85,247,0.08)',  border: 'rgba(168,85,247,0.3)',  Icon: Cpu   },
  domain: { label: 'DOMAIN', color: '#06b6d4', glow: 'rgba(6,182,212,0.4)',   bg: 'rgba(6,182,212,0.08)',   border: 'rgba(6,182,212,0.3)',   Icon: Globe },
  hash:   { label: 'HASH',   color: '#eab308', glow: 'rgba(234,179,8,0.4)',   bg: 'rgba(234,179,8,0.08)',   border: 'rgba(234,179,8,0.3)',   Icon: Hash  },
  url:    { label: 'URL',    color: '#22c55e', glow: 'rgba(34,197,94,0.4)',   bg: 'rgba(34,197,94,0.08)',   border: 'rgba(34,197,94,0.3)',   Icon: Link2 },
}

const SEV_CONFIG = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)',  glow: 'rgba(239,68,68,0.4)', label: 'CRITICAL' },
  high:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)', glow: 'rgba(249,115,22,0.4)', label: 'HIGH' },
  medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.12)',  border: 'rgba(234,179,8,0.3)',  glow: 'rgba(234,179,8,0.4)',  label: 'MEDIUM' },
  low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  border: 'rgba(34,197,94,0.3)',  glow: 'rgba(34,197,94,0.4)',  label: 'LOW' },
}

const SOURCE_CONFIG = {
  // abuse.ch
  'URLHaus':          { color: '#f97316', icon: '🔗', group: 'abuse.ch' },
  'FeodoTracker':     { color: '#ef4444', icon: '🤖', group: 'abuse.ch' },
  'FeodoDomains':     { color: '#dc2626', icon: '🌐', group: 'abuse.ch' },
  'MalwareBazaar':    { color: '#eab308', icon: '☣️', group: 'abuse.ch' },
  'ThreatFox':        { color: '#a855f7', icon: '🦊', group: 'abuse.ch' },
  'SSL Blacklist':    { color: '#06b6d4', icon: '🔒', group: 'abuse.ch' },
  // IP reputation
  'DShield/SANS':     { color: '#3b82f6', icon: '🛡️', group: 'IP Intel' },
  'Blocklist.de':     { color: '#6366f1', icon: '🚫', group: 'IP Intel' },
  'Spamhaus DROP':    { color: '#8b5cf6', icon: '📵', group: 'IP Intel' },
  'C2 Tracker':       { color: '#ec4899', icon: '🎯', group: 'IP Intel' },
  'Emerging Threats': { color: '#f43f5e', icon: '⚡', group: 'IP Intel' },
  'Tor Exits':        { color: '#64748b', icon: '🧅', group: 'IP Intel' },
  // Phishing
  'OpenPhish':        { color: '#22d3ee', icon: '🎣', group: 'Phishing' },
  'PhishTank':        { color: '#10b981', icon: '🐟', group: 'Phishing' },
  // Vulnerabilities
  // CISA KEV removed — CVEs are not IOCs
}

const getTypeCfg = (t) => TYPE_CONFIG[t?.toLowerCase()] || {
  label: (t || 'IOC').toUpperCase(), color: '#94a3b8',
  glow: 'rgba(148,163,184,0.4)', bg: 'rgba(148,163,184,0.08)',
  border: 'rgba(148,163,184,0.3)', Icon: Shield
}

const PAGE_SIZE = 50

/* ─────────────── TypeBadge ─────────────── */
function TypeBadge({ type, large }) {
  const cfg = getTypeCfg(type)
  const { Icon } = cfg
  return (
    <span
      className="inline-flex items-center gap-1.5 font-black tracking-widest uppercase rounded-lg transition-all"
      style={{
        fontSize: large ? 11 : 10,
        padding: large ? '5px 10px' : '3px 8px',
        color: cfg.color,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        boxShadow: `0 0 12px ${cfg.glow}`,
      }}
    >
      <Icon style={{ width: large ? 12 : 10, height: large ? 12 : 10 }} />
      {cfg.label}
    </span>
  )
}

/* ─────────────── SeverityBadge ─────────────── */
function SeverityBadge({ severity }) {
  const cfg = SEV_CONFIG[severity] || SEV_CONFIG.low
  return (
    <span
      className="inline-flex items-center gap-1 font-black text-[10px] tracking-widest uppercase px-2.5 py-1 rounded-lg"
      style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`, boxShadow: `0 0 8px ${cfg.glow}` }}
    >
      {severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : severity === 'medium' ? '🟡' : '🟢'} {cfg.label}
    </span>
  )
}

/* ─────────────── Animated BG Grid ─────────────── */
function CyberGrid() {
  return (
    <div className="fixed inset-0 pointer-events-none overflow-hidden" style={{ zIndex: 0 }}>
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: `
          linear-gradient(rgba(6,182,212,0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(6,182,212,0.03) 1px, transparent 1px)
        `,
        backgroundSize: '60px 60px',
        maskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, black 30%, transparent 100%)',
      }} />
      <div style={{
        position: 'absolute', top: '10%', left: '5%', width: 600, height: 600,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(168,85,247,0.06) 0%, transparent 70%)',
        animation: 'pulse 6s ease-in-out infinite',
      }} />
      <div style={{
        position: 'absolute', bottom: '15%', right: '5%', width: 500, height: 500,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(6,182,212,0.06) 0%, transparent 70%)',
        animation: 'pulse 8s ease-in-out infinite 2s',
      }} />
    </div>
  )
}

/* ─────────────── Stat Pill ─────────────── */
function StatPill({ icon: Icon, label, value, color, glow }) {
  return (
    <div className="flex items-center gap-3 rounded-2xl px-5 py-3 relative overflow-hidden"
      style={{ background: 'rgba(15,23,42,0.8)', border: `1px solid ${color}22`, backdropFilter: 'blur(20px)' }}>
      <div className="w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0"
        style={{ background: `${color}15`, boxShadow: `0 0 20px ${glow}` }}>
        <Icon style={{ width: 16, height: 16, color }} />
      </div>
      <div>
        <div className="text-xs font-bold uppercase tracking-widest" style={{ color: `${color}99` }}>{label}</div>
        <div className="text-xl font-black text-white">{value}</div>
      </div>
    </div>
  )
}

/* ─────────────── Live Result Row ─────────────── */
function VerdictBadge({ description }) {
  if (!description) return null
  const isMal = description.includes('🔴')
  const isSus = description.includes('🟡')
  const isClean = description.includes('🟢')
  if (!isMal && !isSus && !isClean) return null
  const label = isMal ? 'MALICIOUS' : isSus ? 'SUSPICIOUS' : 'CLEAN'
  const color = isMal ? '#ef4444' : isSus ? '#f59e0b' : '#22c55e'
  const bg = isMal ? 'rgba(239,68,68,0.1)' : isSus ? 'rgba(245,158,11,0.1)' : 'rgba(34,197,94,0.1)'
  const border = isMal ? 'rgba(239,68,68,0.3)' : isSus ? 'rgba(245,158,11,0.3)' : 'rgba(34,197,94,0.3)'
  return (
    <span className="inline-flex items-center gap-1 font-black text-[10px] tracking-widest uppercase px-2.5 py-1 rounded-lg"
      style={{ color, background: bg, border: `1px solid ${border}`, boxShadow: `0 0 10px ${bg}` }}>
      <span>{isMal ? '🔴' : isSus ? '🟡' : '🟢'}</span> {label}
    </span>
  )
}

function ExternalIOCRow({ item, index }) {
  const cfg = getTypeCfg(item.ioc_type)
  const description = item.description || ''

  const hasBadge = description.startsWith('🔴') || description.startsWith('🟡') || description.startsWith('🟢')
  const cleanDesc = hasBadge ? description.replace(/^[🔴🟡🟢]\s*(MALICIOUS|SUSPICIOUS|CLEAN)\s*\|\s*Confidence:\s*\d+%\s*\|\s*/i, '') : description

  return (
    <div
      className="group relative rounded-2xl p-5 transition-all duration-300 hover:-translate-y-0.5"
      style={{
        background: 'rgba(15,23,42,0.85)',
        border: `1px solid rgba(255,255,255,0.07)`,
        backdropFilter: 'blur(20px)',
        animation: 'fadeSlideIn 0.4s ease both',
        animationDelay: `${index * 60}ms`,
      }}
    >
      <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{ boxShadow: `inset 0 0 40px ${cfg.glow}15`, border: `1px solid ${cfg.border}` }} />

      <div className="relative">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <TypeBadge type={item.ioc_type} />
            <span className="text-xs font-black text-white/70 bg-white/5 border border-white/10 px-2.5 py-1 rounded-lg uppercase tracking-wide">
              {item.source_name}
            </span>
            {hasBadge && <VerdictBadge description={description} />}
          </div>
          {item.source_url && (
            <a href={item.source_url} target="_blank" rel="noopener noreferrer"
              className="flex-shrink-0 flex items-center gap-1 text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-xl transition-all hover:scale-105"
              style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}` }}>
              <ExternalLink className="w-3 h-3" /> View
            </a>
          )}
        </div>

        <div className="font-mono text-sm break-all mb-2 leading-relaxed" style={{ color: cfg.color }}>
          {item.value}
        </div>

        {cleanDesc && (
          <p className="text-xs text-slate-400 leading-relaxed">
            {cleanDesc.split(' | ').map((part, i) => (
              <span key={i} className="inline-block">
                {i > 0 && <span className="text-slate-600 mx-1">|</span>}
                <span>{part}</span>
              </span>
            ))}
          </p>
        )}

        {(item.tags || []).length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {(item.tags || []).filter(Boolean).slice(0, 6).map((t, i) => (
              <span key={i} className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-md"
                style={{ background: 'rgba(239,68,68,0.08)', color: '#f87171', border: '1px solid rgba(239,68,68,0.15)' }}>
                {t}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

/* ─────────────── Raw Feed IOC Row ─────────────── */
function RawFeedRow({ ioc, index }) {
  const cfg = getTypeCfg(ioc.ioc_type)
  const sevCfg = SEV_CONFIG[ioc.severity] || SEV_CONFIG.low
  const srcCfg = SOURCE_CONFIG[ioc.feed] || { color: '#94a3b8', icon: '📡' }
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className="group relative rounded-2xl overflow-hidden transition-all duration-300 hover:-translate-y-px cursor-pointer"
      style={{
        background: 'rgba(10,17,35,0.9)',
        border: `1px solid rgba(255,255,255,0.06)`,
        borderLeft: `3px solid ${sevCfg.color}`,
        backdropFilter: 'blur(20px)',
        animation: 'fadeSlideIn 0.35s ease both',
        animationDelay: `${Math.min(index * 20, 600)}ms`,
      }}
      onClick={() => setExpanded(e => !e)}
    >
      {/* Hover glow */}
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-400 pointer-events-none"
        style={{ boxShadow: `inset 0 0 30px ${sevCfg.color}08` }} />

      {/* Main row */}
      <div className="relative flex items-center gap-3 px-4 py-3">
        {/* Severity */}
        <div className="flex-shrink-0">
          <SeverityBadge severity={ioc.severity} />
        </div>

        {/* Type */}
        <div className="flex-shrink-0">
          <TypeBadge type={ioc.ioc_type} />
        </div>

        {/* Value */}
        <div className="flex-1 min-w-0">
          <div className="font-mono text-sm truncate" style={{ color: cfg.color }}>
            {ioc.value}
          </div>
          {ioc.threat && (
            <div className="text-xs text-slate-500 truncate mt-0.5">{ioc.threat}</div>
          )}
        </div>

        {/* Source badge */}
        <div className="flex-shrink-0 hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-xl text-[10px] font-black uppercase tracking-wide"
          style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', color: srcCfg.color }}>
          <span>{srcCfg.icon}</span>
          {ioc.feed}
        </div>

        {/* Country */}
        {ioc.country && (
          <div className="flex-shrink-0 hidden md:block text-xs text-slate-500 font-medium">
            {ioc.country}
          </div>
        )}

        {/* Date */}
        <div className="flex-shrink-0 hidden lg:block text-[11px] text-slate-600 whitespace-nowrap">
          {ioc.first_seen ? new Date(ioc.first_seen).toLocaleDateString() : '—'}
        </div>

        {/* External link */}
        {ioc.source_url && (
          <a href={ioc.source_url} target="_blank" rel="noopener noreferrer"
            onClick={e => e.stopPropagation()}
            className="flex-shrink-0 p-1.5 rounded-lg transition-all hover:scale-110"
            style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}` }}>
            <ExternalLink className="w-3 h-3" />
          </a>
        )}

        {/* Expand indicator */}
        <ChevronDown className="w-3 h-3 text-slate-600 flex-shrink-0 transition-transform duration-200"
          style={{ transform: expanded ? 'rotate(180deg)' : 'none' }} />
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3 text-xs">
            {ioc.status && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">Status</div>
                <div className="text-white font-semibold">{ioc.status}</div>
              </div>
            )}
            {ioc.country && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">Country</div>
                <div className="text-white font-semibold">{ioc.country}</div>
              </div>
            )}
            {ioc.asn && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">ASN</div>
                <div className="text-white font-mono">{ioc.asn}</div>
              </div>
            )}
            {ioc.reporter && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">Reporter</div>
                <div className="text-white font-semibold">{ioc.reporter}</div>
              </div>
            )}
            {ioc.confidence && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">Confidence</div>
                <div className="text-white font-semibold">{ioc.confidence}%</div>
              </div>
            )}
            {ioc.file_type && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">File Type</div>
                <div className="text-white font-mono text-[11px]">{ioc.file_type}</div>
              </div>
            )}
            {ioc.file_size && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">File Size</div>
                <div className="text-white font-semibold">{(ioc.file_size / 1024).toFixed(1)} KB</div>
              </div>
            )}
            {ioc.first_seen && (
              <div>
                <div className="text-slate-600 uppercase tracking-wide text-[10px] mb-0.5">First Seen</div>
                <div className="text-white font-semibold">{new Date(ioc.first_seen).toLocaleString()}</div>
              </div>
            )}
          </div>
          {/* Tags */}
          {(ioc.tags || []).length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-3">
              {ioc.tags.filter(Boolean).map((t, i) => (
                <span key={i} className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-md"
                  style={{ background: `${sevCfg.color}10`, color: sevCfg.color, border: `1px solid ${sevCfg.color}25` }}>
                  {t}
                </span>
              ))}
            </div>
          )}
          {/* Full hash */}
          {ioc.ioc_type === 'hash' && (
            <div className="mt-3 p-2 rounded-xl font-mono text-[11px] break-all text-slate-400"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
              {ioc.value}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ─────────────── IOC Table Row ─────────────── */
function IOCTableRow({ ioc, onDelete, onSandbox, isAdmin, index }) {
  const cfg = getTypeCfg(ioc.ioc_type)
  const [hovered, setHovered] = useState(false)

  return (
    <tr
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        background: hovered ? `${cfg.bg}` : 'transparent',
        transition: 'all 0.2s ease',
        animation: `fadeSlideIn 0.4s ease both`,
        animationDelay: `${index * 30}ms`,
      }}
    >
      <td className="px-5 py-3.5">
        <TypeBadge type={ioc.ioc_type} />
      </td>
      <td className="px-5 py-3.5 max-w-[260px]">
        <span className="font-mono text-sm break-all" style={{ color: hovered ? cfg.color : '#cbd5e1' }}>
          {ioc.value}
        </span>
      </td>
      <td className="px-5 py-3.5">
        <span className="text-xs text-slate-400 bg-white/5 border border-white/8 px-2 py-1 rounded-lg">
          {ioc.source || '—'}
        </span>
      </td>
      <td className="px-5 py-3.5 whitespace-nowrap text-xs text-slate-500">
        {formatDateTime(ioc.first_seen)}
      </td>
      <td className="px-5 py-3.5">
        <div className="flex flex-wrap gap-1">
          {(ioc.tags || []).map((t, i) => (
            <span key={i} className="text-xs px-2 py-0.5 rounded-md font-medium"
              style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>
              {t}
            </span>
          ))}
        </div>
      </td>
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-2">
          {ioc.ioc_type === 'hash' && (
            <button onClick={() => onSandbox(ioc.value)}
              className="p-1.5 rounded-lg transition-all hover:scale-110"
              style={{ color: '#60a5fa', background: 'rgba(96,165,250,0.1)', border: '1px solid rgba(96,165,250,0.2)' }}
              title="Sandbox Scan">
              <Radar className="w-3.5 h-3.5" />
            </button>
          )}
          {isAdmin && (
            <button onClick={() => onDelete(ioc.id)}
              className="p-1.5 rounded-lg transition-all hover:scale-110"
              style={{ color: '#94a3b8', background: 'transparent', border: '1px solid transparent' }}
              onMouseEnter={e => {
                e.currentTarget.style.color = '#f87171'
                e.currentTarget.style.background = 'rgba(239,68,68,0.1)'
                e.currentTarget.style.border = '1px solid rgba(239,68,68,0.2)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.color = '#94a3b8'
                e.currentTarget.style.background = 'transparent'
                e.currentTarget.style.border = '1px solid transparent'
              }}>
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </td>
    </tr>
  )
}

/* ─────────────── Add IOC Modal ─────────────── */
function AddIOCModal({ onClose, onAdd }) {
  const [form, setForm] = useState({ value: '', ioc_type: 'ip', source: '', tags: [] })
  const [saving, setSaving] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setSaving(true)
    await onAdd(form)
    setSaving(false)
  }

  const typeOptions = [
    { value: 'ip', label: 'IP Address', Icon: Cpu },
    { value: 'domain', label: 'Domain', Icon: Globe },
    { value: 'hash', label: 'File Hash', Icon: Hash },
    { value: 'url', label: 'URL', Icon: Link2 },
  ]

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ backdropFilter: 'blur(8px)', background: 'rgba(2,6,23,0.85)' }}>
      <div className="relative w-full max-w-lg mx-4 rounded-3xl p-8 overflow-hidden"
        style={{ background: 'rgba(10,17,35,0.95)', border: '1px solid rgba(168,85,247,0.25)', boxShadow: '0 0 80px rgba(168,85,247,0.15), 0 40px 80px rgba(0,0,0,0.6)' }}>
        
        <div className="absolute -top-px left-1/4 right-1/4 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(168,85,247,0.8), transparent)' }} />

        <div className="flex items-center justify-between mb-7">
          <div>
            <h2 className="text-xl font-black text-white flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center" style={{ background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)' }}>
                <Plus className="w-4 h-4" style={{ color: '#a855f7' }} />
              </div>
              Add Indicator
            </h2>
            <p className="text-xs text-slate-500 mt-1 ml-10">Register a new threat indicator for tracking</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 rounded-xl flex items-center justify-center text-slate-500 hover:text-white transition-colors" style={{ background: 'rgba(255,255,255,0.05)' }}>
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 block">IOC Type</label>
            <div className="grid grid-cols-4 gap-2">
              {typeOptions.map(({ value, label, Icon: Ic }) => {
                const cfg = getTypeCfg(value)
                const active = form.ioc_type === value
                return (
                  <button key={value} type="button" onClick={() => setForm(f => ({ ...f, ioc_type: value }))}
                    className="flex flex-col items-center gap-1.5 p-3 rounded-2xl transition-all duration-200"
                    style={{
                      background: active ? cfg.bg : 'rgba(255,255,255,0.03)',
                      border: `1px solid ${active ? cfg.border : 'rgba(255,255,255,0.06)'}`,
                      boxShadow: active ? `0 0 20px ${cfg.glow}` : 'none',
                    }}>
                    <Ic style={{ width: 16, height: 16, color: active ? cfg.color : '#475569' }} />
                    <span className="text-[10px] font-bold uppercase tracking-wide" style={{ color: active ? cfg.color : '#475569' }}>{value}</span>
                  </button>
                )
              })}
            </div>
          </div>

          <div>
            <label className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 block">IOC Value</label>
            <input
              required
              className="w-full rounded-2xl px-4 py-3 font-mono text-sm text-white placeholder-slate-600 focus:outline-none transition-all"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', boxShadow: 'inset 0 2px 8px rgba(0,0,0,0.3)' }}
              placeholder="e.g. 192.168.1.100, evil.com, abc123..."
              value={form.value}
              onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
              onFocus={e => { e.target.style.borderColor = 'rgba(168,85,247,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.1), inset 0 2px 8px rgba(0,0,0,0.3)' }}
              onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.08)'; e.target.style.boxShadow = 'inset 0 2px 8px rgba(0,0,0,0.3)' }}
            />
          </div>

          <div>
            <label className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 block">Source (optional)</label>
            <input
              className="w-full rounded-2xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none transition-all"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', boxShadow: 'inset 0 2px 8px rgba(0,0,0,0.3)' }}
              placeholder="e.g. Internal Analysis, URLHaus..."
              value={form.source}
              onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
              onFocus={e => { e.target.style.borderColor = 'rgba(168,85,247,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.1), inset 0 2px 8px rgba(0,0,0,0.3)' }}
              onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.08)'; e.target.style.boxShadow = 'inset 0 2px 8px rgba(0,0,0,0.3)' }}
            />
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="flex-1 py-3 rounded-2xl text-sm font-bold text-slate-400 hover:text-white transition-colors"
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
              Cancel
            </button>
            <button type="submit" disabled={saving}
              className="flex-1 py-3 rounded-2xl text-sm font-black text-white transition-all hover:scale-[1.02] disabled:opacity-50"
              style={{ background: 'linear-gradient(135deg, #a855f7, #7c3aed)', boxShadow: '0 0 30px rgba(168,85,247,0.3)' }}>
              {saving ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Adding...
                </span>
              ) : 'Register IOC'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

/* ─────────────── Scanning Loader ─────────────── */
function ScanningLoader({ label = 'Scanning Database' }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 gap-6">
      <div className="relative w-24 h-24">
        <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20 animate-ping" />
        <div className="absolute inset-2 rounded-full border-2 border-cyan-500/30" style={{ animation: 'spin 2s linear infinite' }} />
        <div className="absolute inset-4 rounded-full border border-cyan-500/50" style={{ animation: 'spin 1.5s linear infinite reverse' }} />
        <div className="absolute inset-0 flex items-center justify-center">
          <ScanLine className="w-8 h-8 text-cyan-400 animate-pulse" />
        </div>
      </div>
      <div className="text-center">
        <div className="text-sm font-bold text-cyan-400 uppercase tracking-widest">{label}</div>
        <div className="text-xs text-slate-500 mt-1">Fetching threat indicators...</div>
      </div>
    </div>
  )
}

/* ─────────────── Raw Feed Section ─────────────── */
function RawIOCFeed() {
  const [feedData, setFeedData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [typeFilter, setTypeFilter] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [page, setPage] = useState(0)
  const [lastRefresh, setLastRefresh] = useState(null)

  const loadFeed = useCallback(async () => {
    setLoading(true)
    setPage(0)
    try {
      const params = { limit: 500 }
      if (typeFilter) params.ioc_type = typeFilter
      if (sevFilter) params.severity = sevFilter
      if (sourceFilter) params.source = sourceFilter
      const r = await api.get('/admin/iocs/raw-feed', { params })
      setFeedData(r.data)
      setLastRefresh(new Date())
    } catch (e) {
      toast.error('Failed to load raw IOC feed')
    } finally {
      setLoading(false)
    }
  }, [typeFilter, sevFilter, sourceFilter])

  // Auto-load on first render
  useEffect(() => { loadFeed() }, [])

  const iocs = feedData?.iocs || []
  const totalPages = Math.ceil(iocs.length / PAGE_SIZE)
  const pageIocs = iocs.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  const SOURCES = [
    // abuse.ch
    'URLHaus', 'FeodoTracker', 'FeodoDomains', 'MalwareBazaar', 'ThreatFox', 'SSL Blacklist',
    // IP intel
    'DShield/SANS', 'Blocklist.de', 'Spamhaus DROP', 'C2 Tracker', 'Emerging Threats', 'Tor Exits',
    // Phishing
    'OpenPhish', 'PhishTank',
  ]

  return (
    <section>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-4 mb-5">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl flex items-center justify-center"
            style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)', boxShadow: '0 0 20px rgba(239,68,68,0.2)' }}>
            <Rss className="w-4 h-4" style={{ color: '#ef4444' }} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-red-400 animate-pulse" style={{ boxShadow: '0 0 8px rgba(239,68,68,0.8)' }} />
              <span className="text-xs font-black uppercase tracking-widest text-red-400">Live Raw IOC Feed</span>
            </div>
            <p className="text-[11px] text-slate-600 mt-0.5">
              Real-time from: URLHaus · FeodoTracker · MalwareBazaar · ThreatFox · SSL Blacklist
            </p>
          </div>
          {feedData && (
            <span className="text-xs font-bold px-2.5 py-1 rounded-lg"
              style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
              {feedData.total.toLocaleString()} IOCs
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 ml-auto flex-wrap">
          {lastRefresh && (
            <span className="text-[11px] text-slate-600">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button onClick={loadFeed} disabled={loading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition-all hover:scale-105 disabled:opacity-50"
            style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Severity summary bar */}
      {feedData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
          {Object.entries(SEV_CONFIG).map(([sev, cfg]) => (
            <button key={sev}
              onClick={() => { setSevFilter(sevFilter === sev ? '' : sev); setPage(0) }}
              className="flex items-center justify-between px-4 py-2.5 rounded-2xl transition-all hover:scale-[1.02]"
              style={{
                background: sevFilter === sev ? cfg.bg : 'rgba(10,17,35,0.8)',
                border: `1px solid ${sevFilter === sev ? cfg.border : 'rgba(255,255,255,0.06)'}`,
                boxShadow: sevFilter === sev ? `0 0 20px ${cfg.color}20` : 'none',
              }}>
              <span className="text-xs font-black uppercase tracking-widest" style={{ color: cfg.color }}>{cfg.label}</span>
              <span className="text-lg font-black text-white">{feedData.severity_counts[sev] || 0}</span>
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 mb-4">
        {/* Type filter */}
        <div className="relative">
          <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0) }}
            className="h-9 pl-3 pr-8 rounded-xl text-xs text-slate-300 focus:outline-none appearance-none cursor-pointer"
            style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', minWidth: 110 }}>
            <option value="">All Types</option>
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="hash">File Hash</option>
            <option value="url">URL</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500 pointer-events-none" />
        </div>

        {/* Source filter — grouped dropdown */}
        <div className="relative">
          <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(0) }}
            className="h-9 pl-3 pr-8 rounded-xl text-xs text-slate-300 focus:outline-none appearance-none cursor-pointer"
            style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', minWidth: 160 }}>
            <option value="">All Sources</option>
            <optgroup label="── abuse.ch ──">
              <option value="URLHaus">🔗 URLHaus</option>
              <option value="FeodoTracker">🤖 FeodoTracker (IPs)</option>
              <option value="FeodoDomains">🌐 FeodoDomains</option>
              <option value="MalwareBazaar">☣️ MalwareBazaar</option>
              <option value="ThreatFox">🦊 ThreatFox</option>
              <option value="SSL Blacklist">🔒 SSL Blacklist</option>
            </optgroup>
            <optgroup label="── IP Intelligence ──">
              <option value="DShield/SANS">🛡️ DShield / SANS</option>
              <option value="Blocklist.de">🚫 Blocklist.de</option>
              <option value="Spamhaus DROP">📵 Spamhaus DROP</option>
              <option value="C2 Tracker">🎯 C2 Tracker</option>
              <option value="Emerging Threats">⚡ Emerging Threats</option>
              <option value="Tor Exits">🧅 Tor Exit Nodes</option>
            </optgroup>
            <optgroup label="── Phishing ──">
              <option value="OpenPhish">🎣 OpenPhish</option>
              <option value="PhishTank">🐟 PhishTank</option>
            </optgroup>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500 pointer-events-none" />
        </div>

        {/* Clear filters */}
        {(typeFilter || sevFilter || sourceFilter) && (
          <button
            onClick={() => { setTypeFilter(''); setSevFilter(''); setSourceFilter(''); setPage(0) }}
            className="h-9 px-3 rounded-xl text-xs font-bold text-slate-500 hover:text-white transition-colors"
            style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <X className="w-3 h-3 inline mr-1" />Clear
          </button>
        )}
      </div>

      {/* Feed content */}
      {loading ? (
        <ScanningLoader label="Pulling Live Threat Feeds" />
      ) : iocs.length === 0 ? (
        <div className="rounded-3xl p-10 text-center"
          style={{ background: 'rgba(10,17,35,0.7)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <Rss className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <div className="text-sm font-bold text-slate-500">No IOCs found</div>
          <div className="text-xs text-slate-600 mt-1">Try changing filters or refresh the feed</div>
        </div>
      ) : (
        <>
          {/* Source stats header */}
          {feedData?.sources && (
            <div className="flex flex-wrap gap-2 mb-3">
              {Object.entries(feedData.sources).map(([src, info]) => {
                const srcCfg = SOURCE_CONFIG[src] || { color: '#94a3b8', icon: '📡' }
                return (
                  <div key={src} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px]"
                    style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <span>{srcCfg.icon}</span>
                    <span style={{ color: srcCfg.color }}>{src}</span>
                    <span className="text-slate-500">·</span>
                    <span className="text-white font-bold">{info.count}</span>
                  </div>
                )
              })}
            </div>
          )}

          {/* IOC list */}
          <div className="space-y-1.5">
            {pageIocs.map((ioc, i) => (
              <RawFeedRow key={`${ioc.feed}-${ioc.value}-${i}`} ioc={ioc} index={i} />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 px-1">
              <span className="text-xs text-slate-500">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, iocs.length)} of {iocs.length.toLocaleString()}
              </span>
              <div className="flex items-center gap-2">
                <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                  className="p-2 rounded-xl disabled:opacity-30 transition-all hover:scale-105"
                  style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}>
                  <ChevronLeft className="w-4 h-4 text-white" />
                </button>
                <span className="text-xs font-bold text-white px-3 py-1.5 rounded-xl"
                  style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', color: '#ef4444' }}>
                  {page + 1} / {totalPages}
                </span>
                <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}
                  className="p-2 rounded-xl disabled:opacity-30 transition-all hover:scale-105"
                  style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}>
                  <ChevronRight className="w-4 h-4 text-white" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}

/* ─────────────── Enriched IOC Feed ─────────────── */
function RiskScoreBar({ score, label }) {
  const colorMap = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', safe: '#06b6d4'
  }
  const color = colorMap[label] || '#94a3b8'
  const width = Math.max(2, score || 0)
  return (
    <div className="flex items-center gap-3">
      {/* Score number */}
      <div className="text-2xl font-black tabular-nums flex-shrink-0" style={{ color, minWidth: 48 }}>
        {score != null ? Math.round(score) : '—'}
      </div>
      {/* Bar */}
      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${width}%`,
            background: `linear-gradient(90deg, ${color}88, ${color})`,
            boxShadow: `0 0 8px ${color}60`,
          }}
        />
      </div>
      {/* Label */}
      <span className="text-[10px] font-black uppercase tracking-widest flex-shrink-0 px-2 py-0.5 rounded-lg"
        style={{ color, background: `${color}12`, border: `1px solid ${color}25` }}>
        {label?.toUpperCase() || '—'}
      </span>
    </div>
  )
}

function EnrichedIOCCard({ ioc, index }) {
  const cfg = getTypeCfg(ioc.ioc_type)
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  
  const score = ioc.risk_score ?? ioc.threat_score
  const label = ioc.risk_label || ioc.enrichment_data?.risk_label || 'low'
  const colorMap = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', safe: '#06b6d4', error: '#94a3b8' }
  const borderColor = colorMap[label] || '#94a3b8'

  return (
    <div
      className="group relative rounded-2xl overflow-hidden transition-all duration-300 hover:-translate-y-px cursor-pointer"
      style={{
        background: 'rgba(10,17,35,0.9)',
        border: `1px solid rgba(255,255,255,0.06)`,
        borderLeft: `3px solid ${borderColor}`,
        backdropFilter: 'blur(20px)',
        animation: 'fadeSlideIn 0.35s ease both',
        animationDelay: `${Math.min(index * 25, 500)}ms`,
      }}
      onClick={() => setExpanded(e => !e)}
    >
      {/* Hover glow */}
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-400 pointer-events-none"
        style={{ boxShadow: `inset 0 0 30px ${borderColor}08` }} />

      {/* Main content */}
      <div className="relative p-4">
        {/* Top row: Type + Value + Score */}
        <div className="flex items-start gap-4 mb-3">
          {/* Left: type + value */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <TypeBadge type={ioc.ioc_type} />
              <span className="text-[10px] font-black px-2 py-0.5 rounded-lg uppercase tracking-wide"
                style={{ background: 'rgba(255,255,255,0.04)', color: '#64748b', border: '1px solid rgba(255,255,255,0.08)' }}>
                {ioc.feed}
              </span>
              {ioc.threat && (
                <span className="text-[10px] text-slate-500 truncate max-w-[200px]">{ioc.threat}</span>
              )}
            </div>
            <div className="flex items-center gap-2 group/copy">
              <div className="font-mono text-sm break-all leading-relaxed" style={{ color: cfg.color }}>
                {ioc.ioc_type === 'hash' ? (
                  <>{ioc.value.slice(0, 16)}<span className="text-slate-600">…</span>{ioc.value.slice(-8)}</>
                ) : ioc.value}
              </div>
              <button 
                onClick={(e) => {
                  e.stopPropagation();
                  navigator.clipboard.writeText(ioc.value);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                  toast.success('IOC copied to clipboard');
                }}
                className="p-1.5 rounded-lg opacity-0 group-hover/copy:opacity-100 transition-all hover:bg-white/10"
                style={{ color: cfg.color }}
                title="Copy IOC"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Right: Risk score */}
          <div className="flex-shrink-0 w-48">
            <div className="text-[9px] font-black uppercase tracking-widest text-slate-600 mb-1.5">Risk Score</div>
            <RiskScoreBar score={score} label={label} />
          </div>

          {/* External link */}
          {ioc.source_url && (
            <a href={ioc.source_url} target="_blank" rel="noopener noreferrer"
              onClick={e => e.stopPropagation()}
              className="flex-shrink-0 p-1.5 rounded-lg transition-all hover:scale-110"
              style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}` }}>
              <ExternalLink className="w-3 h-3" />
            </a>
          )}

          <ChevronDown className="w-3 h-3 text-slate-600 flex-shrink-0 transition-transform duration-200 self-start mt-2"
            style={{ transform: expanded ? 'rotate(180deg)' : 'none' }} />
        </div>

        {/* Source confirmation row — VT-style detection ratio */}
        <div className="flex flex-wrap items-center gap-1.5">
          {/* Detection ratio badge */}
          {ioc.detection_ratio && (
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-xl text-xs font-black"
              style={{
                background: ioc.confirmation_count > 0 ? 'rgba(239,68,68,0.12)' : 'rgba(255,255,255,0.04)',
                border: `1px solid ${ioc.confirmation_count > 0 ? 'rgba(239,68,68,0.3)' : 'rgba(255,255,255,0.1)'}`,
                color: ioc.confirmation_count > 0 ? '#ef4444' : '#64748b',
              }}>
              <Shield className="w-3 h-3" />
              {ioc.detection_ratio} detected
            </div>
          )}
          {(ioc.source_details || []).map((src, i) => (
            <div key={i} className="flex items-center gap-1 px-2 py-0.5 rounded-lg text-[10px] font-bold"
              style={{
                background: src.found ? 'rgba(34,197,94,0.08)' : 'rgba(255,255,255,0.04)',
                border: `1px solid ${src.found ? 'rgba(34,197,94,0.2)' : 'rgba(255,255,255,0.07)'}`,
                color: src.found ? '#22c55e' : '#475569',
              }}>
              {src.found
                ? <CheckCircle2 className="w-2.5 h-2.5" />
                : <XCircle className="w-2.5 h-2.5" />}
              {src.source}
            </div>
          ))}
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-4 border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
          <div className="pt-3 space-y-2">
            {(ioc.source_details || []).filter(s => s.found && s.summary).map((src, i) => (
              <div key={i} className="flex gap-3 text-xs">
                <span className="text-slate-600 font-bold flex-shrink-0 w-24">{src.source}</span>
                <span className="text-slate-400">{src.summary}</span>
              </div>
            ))}
          </div>
          {/* Full hash */}
          {ioc.ioc_type === 'hash' && (
            <div className="mt-3 p-2 rounded-xl font-mono text-[11px] break-all text-slate-400"
              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
              {ioc.value}
            </div>
          )}
          {/* Tags */}
          {(ioc.tags || []).length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-3">
              {ioc.tags.filter(Boolean).slice(0, 6).map((t, i) => (
                <span key={i} className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-md"
                  style={{ background: `${borderColor}10`, color: borderColor, border: `1px solid ${borderColor}20` }}>
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function EnrichedIOCFeed() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [typeFilter, setTypeFilter] = useState('')
  const [labelFilter, setLabelFilter] = useState('')
  const [rateStatus, setRateStatus] = useState(null)
  const [budgetStatus, setBudgetStatus] = useState(null)
  const [cacheStats, setCacheStats] = useState(null)
  const [page, setPage] = useState(0)
  const [manualSearchInput, setManualSearchInput] = useState('')
  const [manualResult, setManualResult] = useState(null)
  const [manualLoading, setManualLoading] = useState(false)
  const [feedMode, setFeedMode] = useState('auto') // 'auto' or 'scan'
  const EPAGE = 25

  const loadEnriched = useCallback(async (options = {}) => {
    setLoading(true)
    if (!options.cachedOnly) setPage(0)
    try {
      const params = { limit: 100 }
      if (typeFilter) params.ioc_type = typeFilter
      if (labelFilter) params.severity = labelFilter
      if (options.cachedOnly) params.cached_only = true

      const [enrichRes, rateRes] = await Promise.all([
        api.get(options.auto ? '/admin/iocs/auto-enriched' : '/admin/iocs/enriched-feed', { params }),
        api.get('/admin/iocs/enrichment-rate-status'),
      ])
      
      // Auto-enriched endpoint returns { data: [...] } instead of { enriched: [...] }
      if (options.auto) {
         setData({ enriched: enrichRes.data.data, enriched_count: enrichRes.data.data.length, false_positives_removed: 0 })
      } else {
         setData(enrichRes.data)
      }
      
      // New response: { rate_limits, api_budgets, cache }
      const rs = rateRes.data
      setRateStatus(rs.rate_limits || rs)   // fallback for old format
      setBudgetStatus(rs.api_budgets || null)
      setCacheStats(rs.cache || null)
    } catch (e) {
      toast.error('Enrichment/Feed failed — check backend logs')
    } finally {
      setLoading(false)
    }
  }, [typeFilter, labelFilter])

  const handleManualSearch = async (e) => {
    e.preventDefault()
    if (!manualSearchInput.trim()) return
    setManualLoading(true)
    setManualResult(null)
    try {
      const res = await api.get(`/admin/iocs/lookup/${encodeURIComponent(manualSearchInput.trim())}`)
      if (res.data.status === 'success') {
        setManualResult(res.data.data)
        toast.success('IOC Enriched Successfully!')
      } else {
        toast.error(res.data.error || 'Lookup failed')
      }
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Manual enrichment failed')
    } finally {
      setManualLoading(false)
    }
  }

  // Auto-load only cached enriched feed on mount to avoid API limits
  useEffect(() => {
    loadEnriched({ auto: true })
  }, [])

  const iocs = data?.enriched || []
  const filtered = labelFilter ? iocs.filter(i => i.risk_label === labelFilter) : iocs
  const totalPages = Math.ceil(filtered.length / EPAGE)
  const pageIocs = filtered.slice(page * EPAGE, (page + 1) * EPAGE)

  const RISK_LABELS = [
    { id: 'critical', color: '#ef4444', label: 'Critical' },
    { id: 'high',     color: '#f97316', label: 'High' },
    { id: 'medium',   color: '#eab308', label: 'Medium' },
    { id: 'low',      color: '#22c55e', label: 'Low' },
    { id: 'safe',     color: '#06b6d4', label: 'Safe' },
  ]

  // Risk distribution from enriched data
  const riskDist = iocs.reduce((acc, i) => {
    acc[i.risk_label] = (acc[i.risk_label] || 0) + 1
    return acc
  }, {})

  return (
    <section>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-4 mb-5">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl flex items-center justify-center"
            style={{ background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)', boxShadow: '0 0 20px rgba(168,85,247,0.2)' }}>
            <FlaskConical className="w-4 h-4" style={{ color: '#a855f7' }} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" style={{ boxShadow: '0 0 8px rgba(168,85,247,0.8)' }} />
              <span className="text-xs font-black uppercase tracking-widest text-purple-400">Enriched IOC Intelligence</span>
            </div>
            <p className="text-[11px] text-slate-600 mt-0.5">
              Shodan · AbuseIPDB · GreyNoise · URLHaus · ThreatFox · MalwareBazaar · OTX · ip-api
            </p>
          </div>
          {data && (
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold px-2.5 py-1 rounded-lg"
                style={{ background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
                {data.enriched_count} confirmed malicious
              </span>
              {data.false_positives_removed > 0 && (
                <span className="text-xs font-bold px-2.5 py-1 rounded-lg"
                  style={{ background: 'rgba(34,197,94,0.08)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.15)' }}>
                  {data.false_positives_removed} false positives removed
                </span>
              )}
            </div>
          )}
        </div>

        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => { setFeedMode('auto'); loadEnriched({ auto: true }) }} disabled={loading}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition-all hover:scale-105 disabled:opacity-50 ${feedMode === 'auto' ? 'opacity-100 ring-2 ring-purple-500' : 'opacity-60'}`}
            style={{ background: 'rgba(168,85,247,0.1)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.2)' }}>
            <Activity className="w-3.5 h-3.5" />
            Live Priority Feed
          </button>
          <button onClick={() => { setFeedMode('scan'); loadEnriched({ cachedOnly: false }) }} disabled={loading}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold transition-all hover:scale-105 disabled:opacity-50 ${feedMode === 'scan' ? 'opacity-100 ring-2 ring-purple-500' : 'opacity-60'}`}
            style={{ background: 'rgba(168,85,247,0.1)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.2)' }}>
            <FlaskConical className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Scanning...' : 'Scan All'}
          </button>
        </div>
      </div>

      {/* Manual Search Bar */}
      <div className="mb-5 bg-slate-900/80 p-4 rounded-2xl border border-white/5 backdrop-blur-xl">
        <div className="flex flex-col md:flex-row gap-4 items-center">
          <div className="flex-1 w-full relative">
            <Search className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
            <form onSubmit={handleManualSearch}>
              <input 
                type="text" 
                placeholder="On-Demand Enrichment: Paste any IP, Domain, URL, or Hash to instantly analyze it..."
                value={manualSearchInput}
                onChange={e => setManualSearchInput(e.target.value)}
                className="w-full pl-11 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-sm focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50 transition-all text-white placeholder-slate-500"
              />
            </form>
          </div>
          <button 
            onClick={handleManualSearch}
            disabled={manualLoading || !manualSearchInput.trim()}
            className="flex-shrink-0 w-full md:w-auto px-6 py-3 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold text-sm flex items-center justify-center gap-2 transition-all shadow-[0_0_20px_rgba(147,51,234,0.3)]"
          >
            {manualLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
            {manualLoading ? 'Analyzing...' : 'Scan IOC'}
          </button>
        </div>
        
        {/* Manual Result Display */}
        {manualResult && (
          <div className="mt-4 pt-4 border-t border-white/5">
            <h4 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3">Scan Result</h4>
            <EnrichedIOCCard ioc={manualResult} index={0} />
          </div>
        )}
      </div>



      {/* Risk distribution bar */}
      {iocs.length > 0 && (
        <div className="flex gap-2 mb-4 flex-wrap">
          {RISK_LABELS.map(({ id, color, label }) => (
            <button key={id}
              onClick={() => { setLabelFilter(labelFilter === id ? '' : id); setPage(0) }}
              className="flex items-center justify-between px-4 py-2 rounded-2xl transition-all hover:scale-[1.02]"
              style={{
                background: labelFilter === id ? `${color}15` : 'rgba(10,17,35,0.8)',
                border: `1px solid ${labelFilter === id ? color + '40' : 'rgba(255,255,255,0.06)'}`,
                boxShadow: labelFilter === id ? `0 0 20px ${color}15` : 'none',
              }}>
              <span className="text-xs font-black uppercase tracking-widest mr-3" style={{ color }}>{label}</span>
              <span className="text-base font-black text-white">{riskDist[id] || 0}</span>
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 mb-4">
        <div className="relative">
          <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0) }}
            className="h-9 pl-3 pr-8 rounded-xl text-xs text-slate-300 focus:outline-none appearance-none cursor-pointer"
            style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', minWidth: 110 }}>
            <option value="">All Types</option>
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="hash">File Hash</option>
            <option value="url">URL</option>
          </select>
          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500 pointer-events-none" />
        </div>
        {(typeFilter || labelFilter) && (
          <button onClick={() => { setTypeFilter(''); setLabelFilter(''); setPage(0) }}
            className="h-9 px-3 rounded-xl text-xs font-bold text-slate-500 hover:text-white"
            style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <X className="w-3 h-3 inline mr-1" />Clear
          </button>
        )}
        {data?.rate_limited_count > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs"
            style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', color: '#fcd34d' }}>
            <Clock className="w-3 h-3" />
            {data.rate_limited_count} IOCs rate-limited (200/type/hr cap)
          </div>
        )}
      </div>

      {/* Content */}
      {loading && !data ? (
        <ScanningLoader label="Enriching IOCs from 8 Sources" />
      ) : !data && !loading ? (
        <div className="rounded-3xl p-10 text-center"
          style={{ background: 'rgba(10,17,35,0.7)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <Gauge className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <div className="text-sm font-bold text-slate-500">Failed to automatically enrich IOCs</div>
        </div>
      ) : filtered.length === 0 ? (
        <div className="rounded-3xl p-10 text-center"
          style={{ background: 'rgba(10,17,35,0.7)', border: '1px solid rgba(255,255,255,0.05)' }}>
          <Gauge className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <div className="text-sm font-bold text-slate-500">
            {typeFilter || labelFilter 
              ? "No enriched IOCs match filters" 
              : "Cache is empty. Click 'Enrich IOCs' to scan the live raw feed."}
          </div>
        </div>
      ) : (
        <>
          <div className="space-y-2">
            {pageIocs.map((ioc, i) => (
              <EnrichedIOCCard key={`${ioc.value}-${i}`} ioc={ioc} index={i} />
            ))}
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 px-1">
              <span className="text-xs text-slate-500">
                Showing {page * EPAGE + 1}–{Math.min((page + 1) * EPAGE, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-2">
                <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                  className="p-2 rounded-xl disabled:opacity-30" style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}>
                  <ChevronLeft className="w-4 h-4 text-white" />
                </button>
                <span className="text-xs font-bold text-white px-3 py-1.5 rounded-xl"
                  style={{ background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.2)', color: '#a855f7' }}>
                  {page + 1} / {totalPages}
                </span>
                <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}
                  className="p-2 rounded-xl disabled:opacity-30" style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}>
                  <ChevronRight className="w-4 h-4 text-white" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}

/* ─────────────── MAIN COMPONENT ─────────────── */

export default function IOCManagement() {
  const { isAnalyst, isAdmin } = useAuth()
  const location = useLocation()

  const [localIocs, setLocalIocs] = useState([])
  const [stats, setStats] = useState({ tracked: 0, ips: 0, urls: 0, hashes: 0, domains: 0, raw_osint: '0' })
  const [externalItems, setExternalItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState(location.state?.search || '')
  const [typeFilter, setTypeFilter] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [configurationHint, setConfigurationHint] = useState('')
  const [activeTab, setActiveTab] = useState('feed') // 'feed' | 'enriched' | 'search' | 'tracked'
  const inputRef = useRef(null)

  const loadTrackedIocs = async () => {
    setLoading(true)
    try {
      const params = {}
      if (typeFilter) params.ioc_type = typeFilter
      const [r, statsRes] = await Promise.all([
        api.get('/admin/iocs', { params }),
        api.get('/admin/iocs/stats')
      ])
      setLocalIocs(r.data)
      setStats(statsRes.data)
      setExternalItems([])
      setConfigurationHint('')
    } catch {
      toast.error('Failed to load IOCs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (search && location.state?.search) {
      const autoSearch = async () => {
        setLoading(true)
        setActiveTab('search')
        try {
          const params = { search: search.trim() }
          if (typeFilter) params.ioc_type = typeFilter
          const r = await api.get('/admin/iocs/live-search', { params })
          setLocalIocs(r.data.local_items)
          setExternalItems(r.data.external_items)
          setConfigurationHint(r.data.configuration_hint || '')
        } catch {
          toast.error('Failed to search IOCs')
        } finally {
          setLoading(false)
        }
      }
      autoSearch()
      window.history.replaceState({}, document.title)
    } else {
      loadTrackedIocs()
    }
  }, [typeFilter])

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!search.trim()) { loadTrackedIocs(); setActiveTab('tracked'); return }
    setLoading(true)
    setActiveTab('search')
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

  const addIOC = async (form) => {
    try {
      const r = await api.post('/admin/iocs', form)
      setLocalIocs(prev => [r.data, ...prev])
      setShowForm(false)
      toast.success('IOC registered successfully')
    } catch {
      toast.error('Failed to add IOC')
    }
  }

  const deleteIOC = async (id) => {
    if (!confirm('Permanently remove this indicator?')) return
    try {
      await api.delete(`/admin/iocs/${id}`)
      setLocalIocs(prev => prev.filter(i => i.id !== id))
      toast.success('IOC removed')
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

  const TABS = [
    { id: 'feed',    label: 'Live Raw Feed',      icon: Rss,      color: '#ef4444' },
    { id: 'search',  label: 'Live Search',         icon: Radar,    color: '#06b6d4' },
    { id: 'tracked', label: 'Tracked Indicators',  icon: Database, color: '#22c55e' },
  ]

  return (
    <>
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(10px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes slideDown {
          from { opacity: 0; transform: translateY(-16px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes scanLine {
          0%   { transform: translateX(-100%); }
          100% { transform: translateX(400%); }
        }
      `}</style>

      <CyberGrid />

      <div className="relative space-y-6" style={{ zIndex: 1 }}>

        {/* ── HEADER ── */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between"
          style={{ animation: 'slideDown 0.5s ease both' }}>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-2xl flex items-center justify-center relative"
                style={{ background: 'linear-gradient(135deg, rgba(6,182,212,0.2), rgba(168,85,247,0.2))', border: '1px solid rgba(6,182,212,0.3)', boxShadow: '0 0 30px rgba(6,182,212,0.2)' }}>
                <Network className="w-5 h-5 text-cyan-400" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-400 rounded-full border-2 border-slate-950 animate-pulse" />
              </div>
              <div>
                <h1 className="text-3xl font-black text-white tracking-tight">IOC Management</h1>
                <p className="text-xs text-slate-500 font-medium uppercase tracking-widest mt-0.5">
                  Threat Indicator Intelligence Repository
                </p>
              </div>
            </div>
          </div>

          {isAnalyst && (
            <button onClick={() => setShowForm(true)}
              className="flex items-center gap-2 px-6 py-3 rounded-2xl font-black text-sm text-white transition-all hover:scale-105"
              style={{ background: 'linear-gradient(135deg, #a855f7, #7c3aed)', boxShadow: '0 0 30px rgba(168,85,247,0.3)', border: '1px solid rgba(168,85,247,0.4)' }}>
              <Plus className="w-4 h-4" /> Add IOC
            </button>
          )}
        </div>

        {/* ── STAT PILLS ── */}
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-3"
          style={{ animation: 'slideDown 0.55s ease both' }}>
          <StatPill icon={Database} label="Tracked IOCs" value={stats.tracked} color="#06b6d4" glow="rgba(6,182,212,0.3)" />
          <StatPill icon={Cpu} label="IP Addresses" value={stats.ips} color="#a855f7" glow="rgba(168,85,247,0.3)" />
          <StatPill icon={Globe} label="Domains" value={stats.domains} color="#3b82f6" glow="rgba(59,130,246,0.3)" />
          <StatPill icon={Link2} label="URLs" value={stats.urls} color="#22c55e" glow="rgba(34,197,94,0.3)" />
          <StatPill icon={Hash} label="File Hashes" value={stats.hashes} color="#eab308" glow="rgba(234,179,8,0.3)" />
          <StatPill icon={Rss} label="Raw OSINT IOCs" value={stats.raw_osint} color="#f43f5e" glow="rgba(244,63,94,0.3)" />
        </div>

        {/* ── SEARCH BAR ── */}
        <form onSubmit={handleSearch}
          className="flex flex-col sm:flex-row gap-3 rounded-3xl p-4"
          style={{ background: 'rgba(10,17,35,0.8)', border: '1px solid rgba(255,255,255,0.06)', backdropFilter: 'blur(20px)', animation: 'slideDown 0.6s ease both' }}>
          
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              ref={inputRef}
              className="w-full h-12 pl-11 pr-4 rounded-2xl text-sm text-white placeholder-slate-500 focus:outline-none transition-all"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
              placeholder="Search IOC values or run live threat intel lookup..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              onFocus={e => { e.target.style.borderColor = 'rgba(6,182,212,0.4)'; e.target.style.boxShadow = '0 0 0 3px rgba(6,182,212,0.08)' }}
              onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.08)'; e.target.style.boxShadow = 'none' }}
            />
            {search && (
              <button type="button" onClick={() => { setSearch(''); loadTrackedIocs() }}
                className="absolute right-3 top-1/2 -translate-y-1/2 w-6 h-6 rounded-full flex items-center justify-center text-slate-500 hover:text-white transition-colors"
                style={{ background: 'rgba(255,255,255,0.06)' }}>
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
            <select
              className="h-12 pl-9 pr-9 rounded-2xl text-sm text-slate-300 focus:outline-none transition-all appearance-none cursor-pointer"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', minWidth: 140 }}
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}>
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="hash">File Hash</option>
              <option value="url">URL</option>
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
          </div>

          <button type="submit"
            className="h-12 px-8 rounded-2xl text-sm font-black text-white transition-all hover:scale-[1.03] flex items-center gap-2"
            style={{ background: 'linear-gradient(135deg, #0891b2, #7c3aed)', boxShadow: '0 0 25px rgba(8,145,178,0.25)' }}>
            <Zap className="w-4 h-4" /> Scan
          </button>
        </form>

        {configurationHint && (
          <div className="flex items-start gap-3 rounded-2xl p-4 text-sm"
            style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', color: '#fcd34d' }}>
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            {configurationHint}
          </div>
        )}

        {/* ── TABS ── */}
        <div className="flex gap-2 rounded-2xl p-1 flex-wrap" style={{ background: 'rgba(10,17,35,0.8)', border: '1px solid rgba(255,255,255,0.06)', width: 'fit-content' }}>
          {[
            { id: 'feed',     label: 'Live Raw Feed',         icon: Rss,          color: '#ef4444' },
            { id: 'enriched', label: 'Enriched + Risk Score', icon: FlaskConical, color: '#a855f7' },
            { id: 'search',   label: 'Live Search',           icon: Radar,        color: '#06b6d4' },
            { id: 'tracked',  label: 'Tracked',               icon: Database,     color: '#22c55e' },
          ].map(tab => {
            const Icon = tab.icon
            const active = activeTab === tab.id
            return (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all duration-200"
                style={{
                  background: active ? `${tab.color}15` : 'transparent',
                  color: active ? tab.color : '#475569',
                  border: `1px solid ${active ? tab.color + '30' : 'transparent'}`,
                  boxShadow: active ? `0 0 20px ${tab.color}15` : 'none',
                }}>
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            )
          })}
        </div>

        {/* ── TAB CONTENT ── */}
        <div>

          {/* TAB: Raw IOC Feed */}
          {activeTab === 'feed' && <RawIOCFeed />}

          {/* TAB: Enriched IOC Feed */}
          {activeTab === 'enriched' && <EnrichedIOCFeed />}

          {/* TAB: Live Search Results */}
          {activeTab === 'search' && (
            <section>
              <div className="flex items-center gap-3 mb-4">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" style={{ boxShadow: '0 0 8px rgba(6,182,212,0.8)' }} />
                  <span className="text-xs font-black uppercase tracking-widest text-cyan-400">Live Threat Intel</span>
                </div>
                <span className="text-xs font-bold px-2 py-0.5 rounded-lg"
                  style={{ background: 'rgba(6,182,212,0.1)', color: '#06b6d4', border: '1px solid rgba(6,182,212,0.2)' }}>
                  {externalItems.length} results
                </span>
              </div>

              {loading ? (
                <ScanningLoader />
              ) : externalItems.length === 0 ? (
                <div className="rounded-3xl p-10 text-center"
                  style={{ background: 'rgba(10,17,35,0.7)', border: '1px solid rgba(255,255,255,0.05)', backdropFilter: 'blur(20px)' }}>
                  <Radar className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                  <div className="text-sm font-bold text-slate-500">No live IOC matches found</div>
                  <div className="text-xs text-slate-600 mt-1">Search for an IOC value above to run a live threat intel lookup</div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {externalItems.map((item, i) => (
                    <ExternalIOCRow key={`${item.source_url || item.value}-${i}`} item={item} index={i} />
                  ))}
                </div>
              )}
            </section>
          )}

          {/* TAB: Tracked Indicators */}
          {activeTab === 'tracked' && (
            <section>
              <div className="flex items-center gap-3 mb-4">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-400" style={{ boxShadow: '0 0 8px rgba(34,197,94,0.8)' }} />
                  <span className="text-xs font-black uppercase tracking-widest text-emerald-400">Tracked Indicators</span>
                </div>
                <span className="text-xs font-bold px-2 py-0.5 rounded-lg"
                  style={{ background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.2)' }}>
                  {localIocs.length} total
                </span>
              </div>

              {loading ? (
                <ScanningLoader />
              ) : localIocs.length === 0 ? (
                <div className="rounded-3xl p-10 text-center"
                  style={{ background: 'rgba(10,17,35,0.7)', border: '1px solid rgba(255,255,255,0.05)', backdropFilter: 'blur(20px)' }}>
                  <Shield className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                  <div className="text-sm font-bold text-slate-500">No IOCs tracked yet</div>
                  <div className="text-xs text-slate-600 mt-1">Add your first indicator using the button above</div>
                </div>
              ) : (
                <div className="rounded-3xl overflow-hidden"
                  style={{ background: 'rgba(10,17,35,0.85)', border: '1px solid rgba(255,255,255,0.06)', backdropFilter: 'blur(20px)' }}>

                  <div className="h-px w-full relative overflow-hidden">
                    <div className="absolute inset-0" style={{ background: 'linear-gradient(90deg, transparent 0%, rgba(6,182,212,0.6) 50%, transparent 100%)', animation: 'scanLine 3s ease-in-out infinite' }} />
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                          {['Type', 'Value', 'Source', 'First Seen', 'Tags', 'Actions'].map((h) => (
                            <th key={h} className="px-5 py-4 text-left text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {localIocs.map((ioc, i) => (
                          <IOCTableRow
                            key={ioc.id}
                            ioc={ioc}
                            index={i}
                            isAdmin={isAdmin}
                            onDelete={deleteIOC}
                            onSandbox={checkSandbox}
                          />
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <div className="px-5 py-3 flex items-center justify-between border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                    <span className="text-xs text-slate-500">Showing {localIocs.length} indicators</span>
                    <div className="flex items-center gap-1.5">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span className="text-xs text-emerald-500 font-bold">Live Database</span>
                    </div>
                  </div>
                </div>
              )}
            </section>
          )}
        </div>
      </div>

      {showForm && <AddIOCModal onClose={() => setShowForm(false)} onAdd={addIOC} />}
    </>
  )
}
