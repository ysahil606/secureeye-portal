import { useNavigate } from 'react-router-dom'
import { AlertTriangle, Shield, ExternalLink, Clock, Tag, Fingerprint, Activity, ChevronRight, Zap } from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import { timeAgo, truncate, cvssColor, STATUS_CONFIG, formatMarkdown } from '../utils/helpers'
import clsx from 'clsx'

export default function AdvisoryCard({ advisory, compact = false }) {
  const status = STATUS_CONFIG[advisory.status] || STATUS_CONFIG.pending
  const navigate = useNavigate()

  const isCritical = advisory.is_critical_alert
  const isZeroDay  = advisory.is_zero_day

  return (
    <article
      onClick={() => navigate(`/advisories/${advisory.id}`)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          navigate(`/advisories/${advisory.id}`)
        }
      }}
      role="link"
      tabIndex={0}
      className={clsx(
        'relative block p-[1px] rounded-2xl group transition-all duration-500 cursor-pointer',
        'hover:scale-[1.005] hover:-translate-y-0.5',
        isCritical ? 'hover:shadow-[0_0_40px_rgba(239,68,68,0.2)]' : 'hover:shadow-[0_0_40px_rgba(59,130,246,0.12)]'
      )}
    >
      {/* Animated Gradient Border on Hover */}
      <div className={clsx(
        'absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-700 blur-[2px]',
        isCritical
          ? 'bg-gradient-to-r from-red-600/60 via-orange-600/40 to-red-600/60'
          : 'bg-gradient-to-r from-blue-600/30 via-cyan-500/20 to-purple-600/30'
      )} />

      {/* Card Body */}
      <div className={clsx(
        'relative h-full rounded-2xl p-5 border backdrop-blur-xl transition-colors duration-500',
        isCritical
          ? 'bg-dark-950/95 border-red-900/40 group-hover:border-red-700/50'
          : 'bg-dark-900/85 border-white/5 group-hover:border-white/10'
      )}>

        {/* 0-Day / Critical floating pill */}
        {(isCritical || isZeroDay) && (
          <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10">
            <div className={clsx(
              'px-4 py-1 rounded-full text-[10px] font-black uppercase tracking-widest flex items-center gap-2 border shadow-lg',
              isZeroDay
                ? 'bg-red-500/20 text-red-300 border-red-500/50 shadow-red-900/30'
                : 'bg-orange-500/20 text-orange-300 border-orange-500/50 shadow-orange-900/30'
            )}>
              <Zap className="w-3 h-3" />
              {isZeroDay ? '0-Day — Actively Exploited' : 'Critical Alert — Immediate Action Required'}
            </div>
          </div>
        )}

        <div className="flex items-start justify-between gap-5 pt-2">
          <div className="flex-1 min-w-0">

            {/* Badge Row */}
            <div className="flex flex-wrap items-center gap-2 mb-4">
              <SeverityBadge severity={advisory.severity} />

              {/* Status Badge */}
              <span className={clsx(
                'inline-flex items-center gap-1.5 text-[10px] uppercase font-black px-2.5 py-1 rounded-lg border tracking-[0.15em]',
                status.bg, status.color, status.border, status.glow || ''
              )}>
                <span className={clsx('w-1.5 h-1.5 rounded-full flex-shrink-0', status.dot)} />
                {status.label}
              </span>

              {advisory.is_kev && (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-purple-500/30 bg-purple-500/10 text-purple-300 text-[10px] font-black uppercase tracking-[0.15em] shadow-[0_0_10px_rgba(168,85,247,0.1)]">
                  <Activity className="w-3 h-3" /> CISA KEV
                </span>
              )}

              {advisory.source === 'external' && (
                <span className="text-[10px] uppercase font-black tracking-[0.15em] text-slate-500 bg-dark-800/80 px-2.5 py-1 rounded-lg border border-white/5">
                  External
                </span>
              )}
            </div>

            {/* ── TITLE ── Premium gradient heading */}
            <h3 className={clsx(
              "font-black leading-tight tracking-tight line-clamp-2 transition-all duration-300 mb-3",
              compact ? "text-sm" : "text-lg",
              isCritical
                ? "text-transparent bg-clip-text bg-gradient-to-r from-red-200 via-orange-200 to-red-300 group-hover:from-red-100 group-hover:to-orange-100"
                : "text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-300 group-hover:from-white group-hover:via-blue-100 group-hover:to-cyan-200"
            )}>
              {advisory.title}
            </h3>

            {/* CVE Tags */}
            {advisory.cve_ids?.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mb-3">
                {advisory.cve_ids.slice(0, 3).map(cve => (
                  <span key={cve} className="inline-flex items-center gap-1.5 text-[10px] font-mono font-bold text-cyan-400 bg-cyan-950/40 px-2.5 py-1 rounded-md border border-cyan-800/40 hover:border-cyan-500/50 transition-colors">
                    <Fingerprint className="w-3 h-3 text-cyan-500/60" />
                    {cve}
                  </span>
                ))}
                {advisory.cve_ids.length > 3 && (
                  <span className="text-[10px] text-slate-500 font-bold px-2 py-1">
                    +{advisory.cve_ids.length - 3} more
                  </span>
                )}
              </div>
            )}

            {/* ── SUMMARY ── Premium styled description */}
            {!compact && advisory.description && (
              <div className="relative mt-1">
                <p className={clsx(
                  "text-[13px] leading-relaxed line-clamp-2 font-medium",
                  isCritical ? "text-red-200/60" : "text-slate-400"
                )} dangerouslySetInnerHTML={{ __html: formatMarkdown(advisory.description) }} />
                {/* Subtle left accent line */}
                <div className={clsx(
                  "absolute -left-2 top-0 bottom-0 w-[2px] rounded-full opacity-40",
                  isCritical ? "bg-red-500" : "bg-blue-500/60"
                )} />
              </div>
            )}
          </div>

          {/* CVSS Score Panel */}
          {advisory.cvss_score && (
            <div className="flex-shrink-0">
              <div className={clsx(
                "flex flex-col items-center justify-center min-w-[3.5rem] p-3 rounded-xl border transition-all duration-300",
                "bg-dark-950/60 border-white/5 group-hover:border-white/10 group-hover:bg-dark-900/80"
              )}>
                <div className={clsx('text-3xl font-black tracking-tighter leading-none', cvssColor(advisory.cvss_score))}>
                  {advisory.cvss_score.toFixed(1)}
                </div>
                <div className="text-[9px] font-black text-slate-600 uppercase tracking-widest mt-1.5">CVSS</div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-3 mt-5 pt-4 border-t border-white/5">
          {advisory.sector && (
            <span className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-400 bg-dark-800/60 px-2.5 py-1 rounded-md border border-white/5">
              <Tag className="w-3 h-3 text-blue-400/70" />
              {advisory.sector.name}
            </span>
          )}
          <span className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500">
            <Clock className="w-3.5 h-3.5 text-slate-600" />
            {timeAgo(advisory.created_at)}
          </span>
          {advisory.affected_vendors?.length > 0 && (
            <span className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500">
              <Shield className="w-3.5 h-3.5 text-purple-400/60" />
              {advisory.affected_vendors.slice(0, 2).join(', ')}
            </span>
          )}

          {/* Read more arrow */}
          <div className="ml-auto flex items-center gap-1">
            {advisory.source_url && (
              <a
                href={advisory.source_url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 hover:text-white transition-colors bg-white/5 hover:bg-white/10 px-3 py-1.5 rounded-lg border border-white/5"
              >
                <ExternalLink className="w-3.5 h-3.5" /> Source
              </a>
            )}
            <div className="w-7 h-7 rounded-lg bg-white/5 group-hover:bg-blue-500/20 border border-white/5 group-hover:border-blue-500/30 flex items-center justify-center transition-all ml-1">
              <ChevronRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-blue-400 transition-colors" />
            </div>
          </div>
        </div>
      </div>
    </article>
  )
}
