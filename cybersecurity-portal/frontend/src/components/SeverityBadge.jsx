import clsx from 'clsx'

const SEV = {
  critical: {
    label: 'Critical',
    color: 'text-red-300',
    bg: 'bg-red-500/15',
    border: 'border-red-500/40',
    glow: 'shadow-[0_0_12px_rgba(239,68,68,0.25)]',
    dot: 'bg-red-500',
    pulse: true,
  },
  high: {
    label: 'High',
    color: 'text-orange-300',
    bg: 'bg-orange-500/15',
    border: 'border-orange-500/40',
    glow: 'shadow-[0_0_12px_rgba(249,115,22,0.2)]',
    dot: 'bg-orange-500',
    pulse: false,
  },
  medium: {
    label: 'Medium',
    color: 'text-yellow-300',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    glow: '',
    dot: 'bg-yellow-500',
    pulse: false,
  },
  low: {
    label: 'Low',
    color: 'text-emerald-300',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    glow: '',
    dot: 'bg-emerald-500',
    pulse: false,
  },
  informational: {
    label: 'Info',
    color: 'text-blue-300',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    glow: '',
    dot: 'bg-blue-400',
    pulse: false,
  },
}

export default function SeverityBadge({ severity, size = 'sm' }) {
  const key = (severity || 'informational').toLowerCase()
  const cfg = SEV[key] || SEV.informational

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-lg border font-black uppercase tracking-[0.15em] backdrop-blur-sm',
        cfg.bg, cfg.border, cfg.color, cfg.glow,
        size === 'lg' ? 'text-xs px-3.5 py-1.5' : 'text-[10px] px-2.5 py-1'
      )}
    >
      {/* Pulsing dot */}
      <span className="relative flex-shrink-0">
        <span className={clsx('block rounded-full', size === 'lg' ? 'w-2 h-2' : 'w-1.5 h-1.5', cfg.dot)} />
        {cfg.pulse && (
          <span className={clsx(
            'absolute inset-0 rounded-full animate-ping opacity-75',
            cfg.dot
          )} />
        )}
      </span>
      {cfg.label}
    </span>
  )
}
