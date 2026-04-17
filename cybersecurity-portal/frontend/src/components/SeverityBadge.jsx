import { SEVERITY_CONFIG } from '../utils/helpers'

export default function SeverityBadge({ severity, size = 'sm' }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.informational
  return (
    <span className={`badge-${severity} ${size === 'lg' ? 'text-sm px-3 py-1' : ''}`}>
      {cfg.dot} {cfg.label}
    </span>
  )
}
