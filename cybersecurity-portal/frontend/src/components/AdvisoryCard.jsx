import { Link } from 'react-router-dom'
import { AlertTriangle, Shield, ExternalLink, Clock, Tag } from 'lucide-react'
import SeverityBadge from './SeverityBadge'
import { timeAgo, truncate, cvssColor, STATUS_CONFIG } from '../utils/helpers'
import clsx from 'clsx'

export default function AdvisoryCard({ advisory, compact = false }) {
  const status = STATUS_CONFIG[advisory.status] || STATUS_CONFIG.pending

  return (
    <Link to={`/advisories/${advisory.id}`}
      className={clsx(
        'card block p-4 hover:border-blue-500/50 hover:bg-dark-700/80 transition-all group',
        advisory.is_critical_alert && 'border-red-700/60 bg-red-950/20'
      )}>

      {/* Critical banner */}
      {advisory.is_critical_alert && (
        <div className="flex items-center gap-2 mb-3 text-red-400 text-xs font-semibold">
          <AlertTriangle className="w-3.5 h-3.5 threat-pulse" />
          CRITICAL ALERT — Immediate Action Required
        </div>
      )}

      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          {/* Badges row */}
          <div className="flex flex-wrap items-center gap-1.5 mb-2">
            <SeverityBadge severity={advisory.severity} />
            {advisory.is_kev && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-purple-900/60 text-purple-300 border border-purple-700/50">
                ⚠ KEV
              </span>
            )}
            {advisory.is_zero_day && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-900/60 text-red-300 border border-red-700/50">
                0-Day
              </span>
            )}
            {advisory.source === 'external' && (
             <span className="text-xs text-slate-500 bg-dark-800 px-2 py-0.5 rounded-full border border-dark-600">External</span>
            )}

            <span className={`text-xs px-2 py-0.5 rounded-full ${status.bg} ${status.color}`}>
              {status.label}
            </span>
          </div>

          {/* Title */}
          <h3 className="font-semibold text-white group-hover:text-blue-300 transition-colors leading-snug">
            {truncate(advisory.title, compact ? 70 : 120)}
          </h3>

          {/* CVE IDs */}
          {advisory.cve_ids?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {advisory.cve_ids.slice(0, 3).map(cve => (
                <span key={cve} className="text-xs font-mono text-blue-400 bg-blue-950/40 px-1.5 py-0.5 rounded border border-blue-800/50">
                  {cve}
                </span>
              ))}
              {advisory.cve_ids.length > 3 && (
                <span className="text-xs text-slate-500">+{advisory.cve_ids.length - 3} more</span>
              )}
            </div>
          )}

          {!compact && advisory.description && (
            <p className="text-sm text-slate-400 mt-2 leading-relaxed">
              {truncate(advisory.description, 140)}
            </p>
          )}
        </div>

        {/* CVSS score */}
        {advisory.cvss_score && (
          <div className="flex-shrink-0 text-center">
            <div className={`text-2xl font-bold ${cvssColor(advisory.cvss_score)}`}>
              {advisory.cvss_score.toFixed(1)}
            </div>
            <div className="text-xs text-slate-500">CVSS</div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center gap-4 mt-3 pt-3 border-t border-dark-600 text-xs text-slate-500">
        {advisory.sector && (
          <span className="flex items-center gap-1">
            <Tag className="w-3 h-3" /> {advisory.sector.name}
          </span>
        )}
        <span className="flex items-center gap-1">
          <Clock className="w-3 h-3" /> {timeAgo(advisory.created_at)}
        </span>
        {advisory.affected_vendors?.length > 0 && (
          <span className="flex items-center gap-1">
            <Shield className="w-3 h-3" /> {advisory.affected_vendors.slice(0,2).join(', ')}
          </span>
        )}
        {advisory.source_url && (
          <a href={advisory.source_url} target="_blank" rel="noopener noreferrer"
            onClick={e => e.stopPropagation()}
            className="ml-auto flex items-center gap-1 hover:text-blue-400 transition-colors">
            <ExternalLink className="w-3 h-3" /> Source
          </a>
        )}
      </div>
    </Link>
  )
}
