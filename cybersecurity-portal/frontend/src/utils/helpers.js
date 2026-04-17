export const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'text-red-400', bg: 'bg-red-900/40', border: 'border-red-700/50', hex: '#ef4444', dot: '🔴' },
  high:     { label: 'High',     color: 'text-orange-400', bg: 'bg-orange-900/40', border: 'border-orange-700/50', hex: '#f97316', dot: '🟠' },
  medium:   { label: 'Medium',   color: 'text-yellow-400', bg: 'bg-yellow-900/40', border: 'border-yellow-700/50', hex: '#eab308', dot: '🟡' },
  low:      { label: 'Low',      color: 'text-green-400',  bg: 'bg-green-900/40',  border: 'border-green-700/50',  hex: '#22c55e', dot: '🟢' },
  informational: { label: 'Info', color: 'text-blue-400', bg: 'bg-blue-900/40', border: 'border-blue-700/50', hex: '#3b82f6', dot: '🔵' },
}

export const STATUS_CONFIG = {
  pending:   { label: 'Pending Review', color: 'text-yellow-400', bg: 'bg-yellow-900/30' },
  published: { label: 'Published',      color: 'text-green-400',  bg: 'bg-green-900/30'  },
  archived:  { label: 'Archived',       color: 'text-slate-400',  bg: 'bg-slate-800/50'  },
  rejected:  { label: 'Rejected',       color: 'text-red-400',    bg: 'bg-red-900/30'    },
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
