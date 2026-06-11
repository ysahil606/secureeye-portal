import { useNavigate } from 'react-router-dom'
import { AlertTriangle, Shield, ExternalLink, Clock, Tag, Fingerprint, Activity, ChevronRight, Zap, Building2 } from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import { timeAgo, cvssColor, STATUS_CONFIG, formatMarkdown } from '../utils/helpers'
import clsx from 'clsx'

// ── CVSS circular SVG gauge ────────────────────────────────────────────────────
function CvssGauge({ score }) {
  const r = 18
  const circ = 2 * Math.PI * r
  const pct = Math.min(score / 10, 1)
  const color =
    score >= 9 ? '#ef4444' :
    score >= 7 ? '#f97316' :
    score >= 4 ? '#eab308' : '#22c55e'

  return (
    <div className="relative flex-shrink-0 flex items-center justify-center" style={{ width: 48, height: 48 }}>
      <svg width="48" height="48" viewBox="0 0 48 48" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="24" cy="24" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3.5" />
        <circle
          cx="24" cy="24" r={r} fill="none"
          stroke={color} strokeWidth="3.5"
          strokeDasharray={circ}
          strokeDashoffset={circ * (1 - pct)}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-sm font-black leading-none" style={{ color }}>{score.toFixed(1)}</span>
        <span className="text-[8px] font-bold text-slate-600 uppercase tracking-wider mt-0.5">CVSS</span>
      </div>
    </div>
  )
}

// ── Age indicator ─────────────────────────────────────────────────────────────
function AgeIndicator({ createdAt }) {
  const hours = (Date.now() - new Date(createdAt)) / 3600000
  if (hours < 24) return (
    <span className="flex items-center gap-1 text-[10px] font-black text-red-400 uppercase tracking-wider">
      <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse flex-shrink-0" />
      NEW
    </span>
  )
  if (hours < 168) return (
    <span className="flex items-center gap-1 text-[10px] font-bold text-orange-400">
      <Clock className="w-3 h-3" />
      {Math.floor(hours / 24)}d ago
    </span>
  )
  return (
    <span className="flex items-center gap-1 text-[10px] text-slate-500">
      <Clock className="w-3 h-3" />
      {timeAgo(createdAt)}
    </span>
  )
}

// ── Attack type chip ──────────────────────────────────────────────────────────
const ATTACK_COLORS = {
  'RCE':                   'bg-red-500/10 border-red-500/25 text-red-400',
  'SQLi':                  'bg-orange-500/10 border-orange-500/25 text-orange-400',
  'XSS':                   'bg-yellow-500/10 border-yellow-500/25 text-yellow-400',
  'SSRF':                  'bg-purple-500/10 border-purple-500/25 text-purple-400',
  'LFI':                   'bg-pink-500/10 border-pink-500/25 text-pink-400',
  'XXE':                   'bg-indigo-500/10 border-indigo-500/25 text-indigo-400',
  'Auth Bypass':           'bg-cyan-500/10 border-cyan-500/25 text-cyan-400',
  'Privilege Escalation':  'bg-blue-500/10 border-blue-500/25 text-blue-400',
  'DoS':                   'bg-rose-500/10 border-rose-500/25 text-rose-400',
  'Supply Chain':          'bg-emerald-500/10 border-emerald-500/25 text-emerald-400',
}

function AttackChip({ type }) {
  const cls = ATTACK_COLORS[type] || 'bg-slate-700/60 border-slate-600/50 text-slate-400'
  return (
    <span className={clsx('inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-black uppercase tracking-wide border', cls)}>
      {type}
    </span>
  )
}

// ── Main Card ─────────────────────────────────────────────────────────────────
export default function AdvisoryCard({ advisory, compact = false }) {
  const status = STATUS_CONFIG[advisory.status] || STATUS_CONFIG.pending
  const navigate = useNavigate()

  const isCritical = advisory.is_critical_alert
  const isZeroDay  = advisory.is_zero_day

  // Left border color by severity
  const borderAccent = {
    critical:      'before:bg-red-500',
    high:          'before:bg-orange-500',
    medium:        'before:bg-yellow-500',
    low:           'before:bg-green-500',
    informational: 'before:bg-blue-500',
  }[advisory.severity] || 'before:bg-slate-600'

  return (
    <article
      onClick={() => navigate(`/advisories/${advisory.id}`)}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate(`/advisories/${advisory.id}`) } }}
      role="link"
      tabIndex={0}
      className={clsx(
        'relative group cursor-pointer rounded-2xl border transition-all duration-300',
        'before:absolute before:left-0 before:top-3 before:bottom-3 before:w-0.5 before:rounded-full before:transition-all before:duration-300 before:group-hover:top-0 before:group-hover:bottom-0',
        borderAccent,
        isCritical
          ? 'border-red-900/40 bg-slate-950/90 hover:border-red-700/50 hover:shadow-[0_0_30px_rgba(239,68,68,0.12)]'
          : 'border-slate-800/70 bg-slate-900/80 hover:border-slate-700/60 hover:shadow-[0_8px_32px_rgba(0,0,0,0.4)]',
        'hover:-translate-y-0.5',
      )}
    >
      {/* Critical/0-day pill */}
      {(isCritical || isZeroDay) && (
        <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10">
          <div className={clsx(
            'px-3 py-0.5 rounded-full text-[9px] font-black uppercase tracking-widest flex items-center gap-1.5 border shadow-lg',
            isZeroDay
              ? 'bg-red-500/15 text-red-300 border-red-500/40'
              : 'bg-orange-500/15 text-orange-300 border-orange-500/40'
          )}>
            <Zap className="w-2.5 h-2.5" />
            {isZeroDay ? '0-Day — Actively Exploited' : 'Critical Alert'}
          </div>
        </div>
      )}

      <div className="pl-5 pr-4 pt-4 pb-4 relative">

        {/* Top row: badges + age + CVSS gauge */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">

            {/* Badge row */}
            <div className="flex flex-wrap items-center gap-1.5 mb-3">
              <SeverityBadge severity={advisory.severity} />

              <span className={clsx(
                'inline-flex items-center gap-1 text-[9px] uppercase font-black px-2 py-0.5 rounded border tracking-widest',
                status.bg, status.color, status.border
              )}>
                <span className={clsx('w-1 h-1 rounded-full flex-shrink-0', status.dot)} />
                {status.label}
              </span>

              {advisory.is_kev && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-purple-500/30 bg-purple-500/10 text-purple-300 text-[9px] font-black uppercase tracking-widest">
                  <Activity className="w-2.5 h-2.5" /> KEV
                </span>
              )}

              {advisory.source === 'external' && (
                <span className="text-[9px] uppercase font-black tracking-widest text-slate-600 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/50">
                  External
                </span>
              )}

              <div className="ml-auto">
                <AgeIndicator createdAt={advisory.created_at} />
              </div>
            </div>

            {/* Title */}
            <h3 className={clsx(
              'font-black leading-tight tracking-tight line-clamp-2 transition-colors duration-200 mb-2.5',
              compact ? 'text-sm' : 'text-base',
              isCritical
                ? 'text-red-100 group-hover:text-red-50'
                : 'text-slate-100 group-hover:text-white'
            )}>
              {advisory.title}
            </h3>

            {/* CVE chips */}
            {advisory.cve_ids?.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2.5">
                {advisory.cve_ids.slice(0, 4).map(cve => (
                  <span key={cve} className="inline-flex items-center gap-1 text-[9px] font-mono font-bold text-cyan-400 bg-cyan-950/30 px-1.5 py-0.5 rounded border border-cyan-800/30">
                    <Fingerprint className="w-2.5 h-2.5 opacity-60" />{cve}
                  </span>
                ))}
                {advisory.cve_ids.length > 4 && (
                  <span className="text-[9px] text-slate-600 font-bold px-1.5 py-0.5">+{advisory.cve_ids.length - 4}</span>
                )}
              </div>
            )}

            {/* Description */}
            {!compact && advisory.description && (
              <p className={clsx(
                'text-xs leading-relaxed line-clamp-2 mb-2.5',
                isCritical ? 'text-red-200/50' : 'text-slate-500'
              )}
                dangerouslySetInnerHTML={{ __html: formatMarkdown(advisory.description) }}
              />
            )}

            {/* Attack type chips */}
            {advisory.attack_types?.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2.5">
                {advisory.attack_types.slice(0, 4).map(t => <AttackChip key={t} type={t} />)}
                {advisory.attack_types.length > 4 && (
                  <span className="text-[9px] text-slate-600 font-bold px-1 py-0.5">+{advisory.attack_types.length - 4}</span>
                )}
              </div>
            )}
          </div>

          {/* CVSS gauge */}
          {advisory.cvss_score ? (
            <div className="flex-shrink-0 mt-1">
              <CvssGauge score={advisory.cvss_score} />
            </div>
          ) : null}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-3 pt-3 border-t border-white/5 mt-1">

          {/* Sector */}
          {advisory.sector && (
            <span className="flex items-center gap-1 text-[10px] font-semibold text-slate-500 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700/40">
              <Tag className="w-2.5 h-2.5 text-blue-400/70" />{advisory.sector.name}
            </span>
          )}

          {/* Vendors */}
          {advisory.affected_vendors?.length > 0 && (
            <div className="flex items-center gap-1">
              {advisory.affected_vendors.slice(0, 3).map((v, i) => (
                <span key={i} className="w-5 h-5 rounded-full bg-slate-700 border border-slate-600 flex items-center justify-center text-[8px] font-black text-slate-300 uppercase">
                  {v.charAt(0)}
                </span>
              ))}
              {advisory.affected_vendors.length > 3 && (
                <span className="text-[9px] text-slate-600 font-bold ml-0.5">+{advisory.affected_vendors.length - 3}</span>
              )}
            </div>
          )}

          {/* MITRE TTP count */}
          {advisory.mitre_ttps?.length > 0 && (
            <span className="flex items-center gap-1 text-[9px] font-mono font-bold text-cyan-500/70 bg-cyan-950/20 px-1.5 py-0.5 rounded border border-cyan-800/20">
              {advisory.mitre_ttps[0]}
              {advisory.mitre_ttps.length > 1 && <span className="text-slate-600">+{advisory.mitre_ttps.length - 1}</span>}
            </span>
          )}

          {/* APT group */}
          {advisory.apt_groups?.length > 0 && (
            <span className="text-[9px] font-bold text-rose-400/70 bg-rose-950/20 px-1.5 py-0.5 rounded border border-rose-800/20">
              {advisory.apt_groups[0]}
            </span>
          )}

          {/* Actions */}
          <div className="ml-auto flex items-center gap-1.5">
            {advisory.source_url && (
              <a href={advisory.source_url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                className="flex items-center gap-1 text-[10px] font-semibold text-slate-500 hover:text-white transition-colors bg-slate-800/50 hover:bg-slate-700/60 px-2 py-1 rounded-lg border border-slate-700/40">
                <ExternalLink className="w-3 h-3" /> Source
              </a>
            )}
            <div className="w-6 h-6 rounded-lg bg-slate-800/60 group-hover:bg-blue-500/15 border border-slate-700/40 group-hover:border-blue-500/30 flex items-center justify-center transition-all">
              <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-blue-400 transition-colors" />
            </div>
          </div>
        </div>
      </div>
    </article>
  )
}
