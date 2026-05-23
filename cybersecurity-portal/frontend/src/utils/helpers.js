export const SEVERITY_CONFIG = {
  critical:      { label: 'Critical',  color: 'text-red-400',     bg: 'bg-red-900/40',     border: 'border-red-700/50',     hex: '#ef4444', dot: '🔴' },
  high:          { label: 'High',      color: 'text-orange-400',  bg: 'bg-orange-900/40',  border: 'border-orange-700/50',  hex: '#f97316', dot: '🟠' },
  medium:        { label: 'Medium',    color: 'text-yellow-400',  bg: 'bg-yellow-900/40',  border: 'border-yellow-700/50',  hex: '#eab308', dot: '🟡' },
  low:           { label: 'Low',       color: 'text-green-400',   bg: 'bg-green-900/40',   border: 'border-green-700/50',   hex: '#22c55e', dot: '🟢' },
  informational: { label: 'Info',      color: 'text-blue-400',    bg: 'bg-blue-900/40',    border: 'border-blue-700/50',    hex: '#3b82f6', dot: '🔵' },
}

export const STATUS_CONFIG = {
  pending:   {
    label: 'Pending Review',
    color: 'text-amber-300',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    glow: '',
    dot: 'bg-amber-400',
  },
  published: {
    label: 'Published',
    color: 'text-emerald-300',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    glow: 'shadow-[0_0_10px_rgba(16,185,129,0.15)]',
    dot: 'bg-emerald-400',
  },
  archived:  {
    label: 'Archived',
    color: 'text-slate-400',
    bg: 'bg-slate-500/10',
    border: 'border-slate-600/30',
    glow: '',
    dot: 'bg-slate-500',
  },
  rejected:  {
    label: 'Rejected',
    color: 'text-red-300',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    glow: '',
    dot: 'bg-red-500',
  },
}

export const IOC_TYPE_CONFIG = {
  ip:     { label: 'IP Address', color: 'text-purple-400' },
  domain: { label: 'Domain',     color: 'text-cyan-400'   },
  hash:   { label: 'File Hash',  color: 'text-yellow-400' },
  url:    { label: 'URL',        color: 'text-green-400'  },
}

export function severityBadge(severity) {
  return `badge-${severity}`
}

export function formatDate(dateStr) {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric'
  })
}

export function formatDateTime(dateStr) {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  })
}

export function timeAgo(dateStr) {
  if (!dateStr) return '—'
  const diff = Date.now() - new Date(dateStr).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export function cvssColor(score) {
  if (!score) return 'text-slate-400'
  if (score >= 9.0) return 'text-red-400'
  if (score >= 7.0) return 'text-orange-400'
  if (score >= 4.0) return 'text-yellow-400'
  return 'text-green-400'
}

export function truncate(str, n = 80) {
  if (!str) return ''
  return str.length > n ? str.slice(0, n) + '…' : str
}

export function formatMarkdown(text) {
  if (!text) return ''
  // Convert **text** to styled <strong> tags
  return text.replace(/\*\*(.*?)\*\*/g, '<strong class="text-slate-100 font-bold">$1</strong>')
}

export function formatAIReport(text) {
  if (!text) return ''
  
  let html = text
  
  // Strip out [ANALYST ESTIMATE] strings entirely
  html = html.replace(/\[ANALYST ESTIMATE\]\s*-?\s*/gi, '')

  // Escape HTML tags to prevent breaking
  html = html.replace(/</g, "&lt;").replace(/>/g, "&gt;")

  // Replace `- ` bullet points with a styled dot `•`
  html = html.replace(/^-\s+/gm, '<span class="text-cyan-500 mr-2 text-[16px] font-black leading-none">•</span>')

  // Replace divider lines
  html = html.replace(/={10,}/g, '<hr class="my-6 border-blue-900/40" />')
  
  // Replace [KEY: VALUE] tags
  html = html.replace(/\[([^\]:]+):\s*([^\]]+)\]/g, '<span class="inline-block bg-blue-950/50 border border-blue-900/50 text-blue-300 px-2 py-1 rounded text-[11px] uppercase tracking-widest mr-2 mb-2 font-bold">$1: <span class="text-white">$2</span></span>')

  // Format known section headers
  const headers = [
    'EXECUTIVE OVERVIEW',
    'THREAT ACTOR PROFILE',
    'MITRE ATT&CK MAPPING',
    'TECHNICAL ANALYSIS',
    'INDICATORS OF COMPROMISE',
    'IMPACT ASSESSMENT',
    'REMEDIATION DIRECTIVES',
    'ANALYST VERDICT',
    'INTELLIGENCE REFERENCES',
    'SECURE THREAT INTELLIGENCE BRIEF'
  ]
  
  headers.forEach(header => {
    const regex = new RegExp(`^${header}$`, 'gm')
    html = html.replace(regex, `<h4 class="text-cyan-400 font-black text-sm mt-8 mb-4 tracking-[0.2em] uppercase border-b border-blue-900/40 pb-2">${header}</h4>`)
  })

  // Format URLs
  const urlRegex = /(https?:\/\/[^\s]+)/g
  html = html.replace(urlRegex, '<a href="$1" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:text-cyan-300 underline underline-offset-2">$1</a>')

  return html
}
