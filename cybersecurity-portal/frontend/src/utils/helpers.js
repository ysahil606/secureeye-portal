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

  let raw = text

  // 1. Strip noise
  raw = raw.replace(/\[ANALYST ESTIMATE\]\s*-?\s*/gi, '')

  // 2. NORMALIZE INLINE MARKERS
  //    AI often outputs "## Heading body text ## Next Heading" all inline.
  //    Insert \n\n before every ## so they become proper line starts.
  raw = raw.replace(/(###+\s+[A-Za-z])/g, '\n\n$1')
  // Insert newline before inline bullet "• "
  raw = raw.replace(/\s•\s/g, '\n• ')
  // Insert newline after sentence end before next ##
  raw = raw.replace(/([.!?])\s+(##)/g, '$1\n\n$2')

  // 3. Process line-by-line
  const lines = raw.split('\n')
  const parts = []

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim()
    if (!line) continue

    // Escape HTML
    line = line.replace(/</g, '&lt;').replace(/>/g, '&gt;')

    // ### Sub-heading
    if (/^###\s+/.test(line)) {
      const title = line.replace(/^###\s+/, '')
      parts.push(
        `<h5 class="text-indigo-300 font-black text-xs mt-6 mb-1 tracking-[0.15em] uppercase">${title}</h5>`
      )

    // ## Section heading
    } else if (/^##\s+/.test(line)) {
      const title = line.replace(/^##\s+/, '')
      parts.push(
        `<h4 class="text-cyan-400 font-black text-sm mt-8 mb-3 tracking-[0.15em] uppercase border-b border-cyan-900/40 pb-1.5">${title}</h4>`
      )

    // # Top-level heading
    } else if (/^#\s+/.test(line)) {
      const title = line.replace(/^#\s+/, '')
      parts.push(
        `<h3 class="text-white font-black text-base mt-8 mb-3 tracking-wide">${title}</h3>`
      )

    // Bullet point (•, *, -)
    } else if (/^[•*\-]\s/.test(line)) {
      const content = line
        .replace(/^[•*\-]\s+/, '')
        .replace(/\*\*(.*?)\*\*/g, '<strong class="text-slate-100 font-semibold">$1</strong>')
      parts.push(
        `<div class="flex gap-2 my-1.5 items-start">` +
          `<span class="text-cyan-400 font-black leading-6 shrink-0">•</span>` +
          `<span class="text-slate-300 text-sm leading-6">${content}</span>` +
        `</div>`
      )

    // Divider
    } else if (/^={6,}/.test(line)) {
      parts.push('<hr class="my-5 border-blue-900/40" />')

    // Normal paragraph text
    } else {
      const p = line
        .replace(/\*\*(.*?)\*\*/g, '<strong class="text-slate-100 font-semibold">$1</strong>')
        .replace(
          /\[([^\]:]+):\s*([^\]]+)\]/g,
          '<span class="inline-block bg-blue-950/60 border border-blue-800/60 text-blue-300 px-1.5 py-0.5 rounded text-[10px] uppercase tracking-widest mr-1 font-bold">$1: <span class="text-white">$2</span></span>'
        )
        .replace(
          /(https?:\/\/[^\s&<]+)/g,
          '<a href="$1" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:text-cyan-300 underline underline-offset-2 break-all">$1</a>'
        )
      parts.push(`<p class="text-sm text-slate-300 leading-7">${p}</p>`)
    }
  }

  return `<div class="space-y-1">${parts.join('')}</div>`
}
