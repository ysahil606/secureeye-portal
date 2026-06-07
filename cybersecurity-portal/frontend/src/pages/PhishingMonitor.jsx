import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Search, Shield, AlertTriangle, CheckCircle, XCircle,
  Globe, Lock, ExternalLink, Loader2, Fish,
  ChevronRight, ChevronDown, X, RefreshCw, Copy, Info,
  Calendar, Server, Mail, Database, Eye, Zap,
  Clock, MapPin, Activity, Terminal, Image as ImageIcon,
} from 'lucide-react'
import clsx from 'clsx'

import { API_URL } from '../services/api'

const API = API_URL.replace(/\/api$/, '')  // strip trailing /api — PhishingMonitor adds its own paths

// ── Helpers ─────────────────────────────────────────────────────────────────
function getToken() {
  return localStorage.getItem('access_token') || ''
}

function domainAge(days) {
  if (days < 0) return null
  if (days === 0) return 'Today'
  if (days < 30) return `${days} days`
  if (days < 365) return `${Math.floor(days / 30)} months`
  return `${Math.floor(days / 365)} yrs ${Math.floor((days % 365) / 30)} mo`
}

// ── Risk Badge ───────────────────────────────────────────────────────────────
function RiskBadge({ risk, size = 'sm' }) {
  const styles = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    malicious: 'bg-red-500/20 text-red-400 border-red-500/30',
    suspicious: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    clean: 'bg-green-500/20 text-green-400 border-green-500/30',
  }
  const labels = {
    critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium',
    low: '🔵 Low', malicious: '☠️ Malicious', suspicious: '⚠️ Suspicious', clean: '✅ Clean',
  }
  const cls = styles[risk] || 'bg-slate-500/20 text-slate-400 border-slate-500/30'
  return (
    <span className={clsx(
      'inline-flex items-center font-semibold rounded-full border uppercase tracking-wide',
      size === 'sm' ? 'text-[10px] px-2 py-0.5' : 'text-xs px-3 py-1',
      cls
    )}>
      {labels[risk] || risk}
    </span>
  )
}

// ── Source Chip ──────────────────────────────────────────────────────────────
function SourceChip({ source }) {
  const icons = {
    'dnstwist': '🔀',
    'crt.sh': '🔐',
    'PhishTank': '🎣',
    'OpenPhish': '🐟',
    'PhishStats': '📊',
    'Phishing.Database': '🗄️',
    'URLScan.io': '🔍',
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-700/50 text-slate-300 border border-slate-600/30">
      <span>{icons[source] || '📡'}</span>
      {source}
    </span>
  )
}

// ── Verdict Engine Row ───────────────────────────────────────────────────────
function VerdictRow({ icon, name, data, verdictKey = 'verdict' }) {
  if (!data || Object.keys(data).length === 0) return null
  const verdict = data[verdictKey] || data.verdict || (data.hit ? 'malicious' : 'clean')
  const verdictStyle = {
    malicious: 'text-red-400',
    suspicious: 'text-orange-400',
    clean: 'text-green-400',
  }
  return (
    <div className="flex items-start gap-3 py-3 border-b border-white/5 last:border-0">
      <span className="text-xl mt-0.5">{icon}</span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-semibold text-white">{name}</span>
          <span className={clsx('text-xs font-bold uppercase', verdictStyle[verdict] || 'text-slate-400')}>
            {verdict === 'malicious' ? '☠️ Malicious' : verdict === 'suspicious' ? '⚠️ Suspicious' : '✅ Clean'}
          </span>
        </div>
        {/* Extra info per engine */}
        {name === 'VirusTotal' && data.malicious !== undefined && (
          <div className="text-xs text-slate-400 mt-1">
            {data.malicious}/{data.total_engines} engines flagged
            {data.categories?.length > 0 && ` · ${data.categories.join(', ')}`}
          </div>
        )}
        {name === 'AlienVault OTX' && (
          <div className="text-xs text-slate-400 mt-1">
            {data.pulses} pulses
            {data.country ? ` · ${data.country}` : ''}
            {data.asn ? ` · ${data.asn}` : ''}
          </div>
        )}
        {name === 'Pulsedive' && (
          <div className="text-xs text-slate-400 mt-1">
            Risk: {data.risk || 'unknown'}
            {data.threats?.length > 0 && ` · ${data.threats.join(', ')}`}
          </div>
        )}
        {name === 'URLhaus' && data.hit && (
          <div className="text-xs text-slate-400 mt-1">
            {data.count} URLs · {data.tags?.join(', ')}
          </div>
        )}
        {name === 'ThreatFox' && data.hit && (
          <div className="text-xs text-slate-400 mt-1">
            {data.ioc_count} IOCs · {data.malware_families?.join(', ')}
          </div>
        )}
      </div>
    </div>
  )
}

// ── DNS Record Block ─────────────────────────────────────────────────────────
function DnsBlock({ label, icon, records }) {
  if (!records || records.length === 0) return null
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
        {icon}
        <span>{label}</span>
      </div>
      <div className="space-y-1">
        {records.map((r, i) => (
          <div key={i} className="flex items-center gap-2 font-mono text-xs bg-slate-800/50 border border-white/5 rounded-lg px-3 py-2">
            <span className="text-cyan-400 truncate">{r}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Domain Detail Drawer ─────────────────────────────────────────────────────
function DomainDrawer({ domain, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [screenshotReady, setScreenshotReady] = useState(false)
  const pollRef = useRef(null)

  const fetchEnrichment = useCallback(async () => {
    if (!domain) return
    setLoading(true)
    setError(null)
    setData(null)
    setScreenshotReady(false)

    try {
      const r = await fetch(`${API}/api/phishing/enrich?domain=${encodeURIComponent(domain)}`, {
        headers: { Authorization: `Bearer ${getToken()}` }
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const json = await r.json()
      setData(json)

      // Poll for screenshot if pending
      if (json.screenshot?.status === 'pending' && json.screenshot?.scan_id) {
        let attempts = 0
        const poll = async () => {
          if (attempts++ > 10) return
          const pr = await fetch(`${API}/api/phishing/screenshot-status?scan_id=${json.screenshot.scan_id}`, {
            headers: { Authorization: `Bearer ${getToken()}` }
          })
          if (pr.ok) {
            const pd = await pr.json()
            if (pd.status === 'ready') {
              setData(prev => prev ? { ...prev, screenshot: pd } : prev)
              setScreenshotReady(true)
              return
            }
          }
          pollRef.current = setTimeout(poll, 5000)
        }
        pollRef.current = setTimeout(poll, 6000)
      } else if (json.screenshot?.status === 'ready') {
        setScreenshotReady(true)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [domain])

  useEffect(() => {
    fetchEnrichment()
    return () => { if (pollRef.current) clearTimeout(pollRef.current) }
  }, [fetchEnrichment])

  const verdictColor = {
    malicious: 'from-red-500/10 to-transparent border-red-500/20',
    suspicious: 'from-orange-500/10 to-transparent border-orange-500/20',
    clean: 'from-green-500/10 to-transparent border-green-500/20',
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

      {/* Drawer */}
      <div
        className="relative w-full max-w-xl h-full bg-[#0a0f1e] border-l border-white/10 overflow-y-auto flex flex-col animate-slideInRight"
        onClick={e => e.stopPropagation()}
        style={{ boxShadow: '-20px 0 60px rgba(0,0,0,0.5)' }}
      >
        {/* Header */}
        <div className={clsx(
          'sticky top-0 z-10 bg-gradient-to-b border-b px-5 py-4',
          data ? (verdictColor[data.overall_verdict] || 'from-slate-800/50 to-transparent border-white/10') : 'from-slate-800/50 to-transparent border-white/10'
        )}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Globe size={16} className="text-cyan-400 shrink-0" />
                <h2 className="font-mono text-sm font-bold text-white truncate">{domain}</h2>
              </div>
              {data && <RiskBadge risk={data.overall_verdict} size="md" />}
            </div>
            <div className="flex items-center gap-2">
              <button onClick={fetchEnrichment} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors" title="Refresh">
                <RefreshCw size={14} />
              </button>
              <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors">
                <X size={16} />
              </button>
            </div>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 p-5 space-y-5">
          {loading && (
            <div className="flex flex-col items-center justify-center py-20 gap-4">
              <div className="relative">
                <div className="w-12 h-12 rounded-full border-2 border-cyan-500/30 border-t-cyan-500 animate-spin" />
              </div>
              <div className="text-sm text-slate-400">Enriching domain intelligence…</div>
              <div className="flex gap-2 flex-wrap justify-center">
                {['WHOIS', 'DNS', 'VirusTotal', 'AlienVault', 'URLScan'].map(s => (
                  <span key={s} className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-white/5">{s}</span>
                ))}
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center gap-3 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
              <XCircle size={16} />
              {error}
            </div>
          )}

          {data && !loading && (
            <>
              {/* Screenshot */}
              <div className="rounded-xl overflow-hidden border border-white/10 bg-slate-900/50">
                <div className="flex items-center gap-2 px-3 py-2 border-b border-white/5">
                  <div className="flex gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
                    <div className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
                  </div>
                  <span className="flex-1 text-center text-xs text-slate-500 font-mono truncate">{domain}</span>
                  {data.screenshot?.scan_url && (
                    <a href={data.screenshot.scan_url} target="_blank" rel="noopener noreferrer" className="text-slate-500 hover:text-cyan-400 transition-colors">
                      <ExternalLink size={12} />
                    </a>
                  )}
                </div>
                <div className="relative" style={{ minHeight: '180px' }}>
                  {screenshotReady && data.screenshot?.screenshot_url ? (
                    <img
                      src={data.screenshot.screenshot_url}
                      alt={`Screenshot of ${domain}`}
                      className="w-full object-cover"
                      onError={e => { e.target.style.display = 'none' }}
                    />
                  ) : data.screenshot?.status === 'pending' ? (
                    <div className="flex flex-col items-center justify-center py-12 gap-3">
                      <Loader2 size={20} className="text-cyan-500 animate-spin" />
                      <div className="text-xs text-slate-400 text-center">
                        Capturing live screenshot…<br />
                        <span className="text-slate-500">This takes ~30 seconds for new domains</span>
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-12 gap-2">
                      <ImageIcon size={24} className="text-slate-600" />
                      <div className="text-xs text-slate-500">No screenshot available</div>
                    </div>
                  )}
                </div>
              </div>

              {/* WHOIS */}
              <section>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Calendar size={12} />
                  WHOIS Information
                  {data.whois?.source && !data.whois?.error && (
                    <span className="ml-auto text-[10px] font-normal px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 normal-case tracking-normal">
                      via {data.whois.source}
                    </span>
                  )}
                </h3>
                {data.whois?.error ? (
                  <div className="flex items-start gap-3 p-4 bg-slate-800/40 border border-white/5 rounded-xl text-xs text-slate-400">
                    <span className="text-2xl">🔍</span>
                    <div>
                      <div className="font-semibold text-slate-300 mb-1">WHOIS lookup unavailable</div>
                      <div className="text-slate-500">{data.whois.error}. Try the external WHOIS link below.</div>
                    </div>
                  </div>
                ) : (
                <div className="bg-slate-800/30 border border-white/5 rounded-xl divide-y divide-white/5">
                  {[
                    { label: 'Registrar', value: data.whois?.registrar },
                    { label: 'Organization', value: data.whois?.registrant_org },
                    { label: 'Country', value: data.whois?.registrant_country },
                    { label: 'Created', value: data.whois?.creation_date, badge: data.whois?.is_newly_registered ? '🚨 NEW' : null },
                    { label: 'Expires', value: data.whois?.expiry_date },
                    { label: 'Age', value: data.whois?.age_days >= 0 ? domainAge(data.whois.age_days) : null },
                    { label: 'DNSSEC', value: data.whois?.dnssec },
                  ].filter(r => r.value).map(({ label, value, badge }) => (
                    <div key={label} className="flex items-center justify-between px-4 py-2.5 gap-4">
                      <span className="text-xs text-slate-500 shrink-0">{label}</span>
                      <div className="flex items-center gap-2 min-w-0">
                        {badge && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                            {badge}
                          </span>
                        )}
                        <span className="text-xs text-white font-mono truncate text-right">{value}</span>
                      </div>
                    </div>
                  ))}
                  {data.whois?.name_servers?.length > 0 && (
                    <div className="px-4 py-2.5">
                      <div className="text-xs text-slate-500 mb-1.5">Name Servers</div>
                      <div className="flex flex-wrap gap-1">
                        {data.whois.name_servers.slice(0, 4).map((ns, i) => (
                          <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-700/50 text-slate-300">{ns}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                )}
              </section>

              {/* DNS Records */}
              <section>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Server size={12} />
                  DNS Records
                  {data.dns?.source && (
                    <span className="ml-auto text-[10px] font-normal px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 normal-case tracking-normal">
                      via {data.dns.source}
                    </span>
                  )}
                </h3>
                <div className="space-y-3">
                  <DnsBlock label="A Records (IPv4)" icon={<Globe size={10} />} records={data.dns?.a} />
                  <DnsBlock label="MX Records (Mail Servers)" icon={<Mail size={10} />} records={data.dns?.mx} />
                  <DnsBlock label="NS Records (Nameservers)" icon={<Server size={10} />} records={data.dns?.ns} />
                  <DnsBlock label="AAAA Records (IPv6)" icon={<Globe size={10} />} records={data.dns?.aaaa} />
                  <DnsBlock label="TXT Records" icon={<Terminal size={10} />} records={data.dns?.txt?.slice(0, 3)} />
                  {(!data.dns?.a?.length && !data.dns?.mx?.length && !data.dns?.ns?.length) && (
                    <div className="text-xs text-slate-500 flex items-center gap-2">
                      <XCircle size={12} className="text-red-500" />
                      No DNS records found — domain may not be active
                    </div>
                  )}
                </div>
              </section>

              {/* Multi-Engine Verdict */}
              <section>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Shield size={12} />
                  Multi-Engine Verdict
                </h3>
                <div className="bg-slate-800/30 border border-white/5 rounded-xl px-4">
                  <VerdictRow icon="⚡" name="VirusTotal" data={data.verdict?.virustotal} />
                  <VerdictRow icon="👽" name="AlienVault OTX" data={data.verdict?.alienvault} />
                  <VerdictRow icon="🌊" name="Pulsedive" data={data.verdict?.pulsedive} />
                  <VerdictRow icon="🦠" name="URLhaus" data={data.verdict?.urlhaus} />
                  <VerdictRow icon="🎯" name="ThreatFox" data={data.verdict?.threatfox} />
                  {Object.values(data.verdict || {}).every(v => !v || Object.keys(v).length === 0) && (
                    <div className="py-4 text-xs text-slate-500 text-center">No verdict data available</div>
                  )}
                </div>
              </section>

              {/* Quick Actions */}
              <div className="flex gap-2">
                <a
                  href={`https://who.is/whois/${domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-white/5 transition-colors"
                >
                  <ExternalLink size={12} />
                  WHOIS
                </a>
                <a
                  href={`https://www.virustotal.com/gui/domain/${domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-white/5 transition-colors"
                >
                  <Shield size={12} />
                  VirusTotal
                </a>
                <a
                  href={`https://urlscan.io/search/#page.domain%3A${domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-white/5 transition-colors"
                >
                  <Eye size={12} />
                  URLScan
                </a>
              </div>
            </>
          )}
        </div>
      </div>

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .animate-slideInRight {
          animation: slideInRight 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }
      `}</style>
    </div>
  )
}

// ── Domain Row ───────────────────────────────────────────────────────────────
function DomainRow({ item, onClick }) {
  return (
    <tr
      className="group cursor-pointer border-b border-white/5 hover:bg-white/3 transition-colors"
      onClick={() => onClick(item.domain)}
    >
      <td className="py-3 pl-4 pr-2">
        <div className="flex items-center gap-2">
          <div className={clsx(
            'w-1.5 h-1.5 rounded-full shrink-0',
            item.resolved ? 'bg-red-400' : 'bg-slate-600'
          )} />
          <span className="font-mono text-sm text-white group-hover:text-cyan-400 transition-colors">{item.domain}</span>
        </div>
      </td>
      <td className="py-3 px-2">
        <SourceChip source={item.source} />
      </td>
      <td className="py-3 px-2">
        {item.fuzzer && (
          <span className="text-xs text-slate-500 capitalize">{item.fuzzer}</span>
        )}
        {item.issued_date && (
          <span className="text-xs text-slate-500">{item.issued_date}</span>
        )}
      </td>
      <td className="py-3 px-2">
        {item.ip ? (
          <span className="font-mono text-xs text-slate-400">{item.ip}</span>
        ) : item.resolved === false ? (
          <span className="text-xs text-slate-600">—</span>
        ) : null}
      </td>
      <td className="py-3 px-2 max-w-[160px]">
        {item.mx ? (
          <span className="font-mono text-xs text-orange-400 truncate block" title={item.mx}>
            {item.mx.replace(/^\d+\s+/, '')}
          </span>
        ) : (
          <span className="text-xs text-slate-600">—</span>
        )}
      </td>
      <td className="py-3 px-2">
        {item.resolved !== undefined && (
          item.resolved
            ? <CheckCircle size={13} className="text-red-400" />
            : <XCircle size={13} className="text-slate-600" />
        )}
      </td>
      <td className="py-3 px-2">
        {item.has_ssl
          ? <Lock size={13} className="text-green-400" />
          : <span className="text-xs text-slate-600">—</span>
        }
      </td>
      <td className="py-3 pl-2 pr-4">
        <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <span className="text-xs text-cyan-400">Inspect</span>
          <ChevronRight size={12} className="text-cyan-400" />
        </div>
      </td>
    </tr>
  )
}

// ── Confirmed Phishing Row ───────────────────────────────────────────────────
function PhishRow({ item, onClick }) {
  return (
    <tr
      className="group cursor-pointer border-b border-white/5 hover:bg-red-500/3 transition-colors"
      onClick={() => onClick(item.domain)}
    >
      <td className="py-3 pl-4 pr-2">
        <div className="flex items-center gap-2">
          <AlertTriangle size={12} className="text-red-400 shrink-0" />
          <span className="font-mono text-sm text-red-300 group-hover:text-red-200 transition-colors truncate max-w-48">{item.domain}</span>
        </div>
      </td>
      <td className="py-3 px-2">
        <SourceChip source={item.source} />
      </td>
      <td className="py-3 px-2">
        {item.url && (
          <a
            href={item.url}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs text-slate-500 hover:text-cyan-400 transition-colors truncate max-w-xs block"
            onClick={e => e.stopPropagation()}
          >
            {item.url.length > 60 ? item.url.slice(0, 60) + '…' : item.url}
          </a>
        )}
      </td>
      <td className="py-3 pl-2 pr-4">
        {item.has_ssl && <Lock size={12} className="text-green-400" />}
      </td>
    </tr>
  )
}

// ── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ icon, label, value, sub, color = 'cyan' }) {
  const colors = {
    cyan: 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400',
    red: 'bg-red-500/10 border-red-500/20 text-red-400',
    orange: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
    green: 'bg-green-500/10 border-green-500/20 text-green-400',
  }
  return (
    <div className={clsx('rounded-2xl border p-4 flex items-center gap-4', colors[color])}>
      <div className={clsx('w-10 h-10 rounded-xl flex items-center justify-center text-xl', `bg-${color}-500/10`)}>
        {icon}
      </div>
      <div>
        <div className={clsx('text-2xl font-bold', `text-${color}-400`)}>{value}</div>
        <div className="text-xs font-medium text-white/80">{label}</div>
        {sub && <div className="text-[10px] text-slate-500 mt-0.5">{sub}</div>}
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function PhishingMonitor() {
  const [query, setQuery] = useState('')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('lookalikes')
  const [selectedDomain, setSelectedDomain] = useState(null)
  const inputRef = useRef(null)

  const handleScan = async (e) => {
    e?.preventDefault()
    const domain = query.trim()
    if (!domain) return

    setScanning(true)
    setError(null)
    setResults(null)

    try {
      const r = await fetch(`${API}/api/phishing/scan?domain=${encodeURIComponent(domain)}`, {
        headers: { Authorization: `Bearer ${getToken()}` }
      })
      if (!r.ok) {
        const err = await r.json().catch(() => ({}))
        throw new Error(err.detail || `HTTP ${r.status}`)
      }
      const json = await r.json()
      setResults(json)
      setActiveTab(json.confirmed_phishing?.length > 0 ? 'confirmed' : 'lookalikes')
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  // Keyboard shortcut
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        inputRef.current?.focus()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const tabs = results ? [
    { id: 'lookalikes', label: 'Lookalike Domains', count: results.lookalikes?.length, icon: '🔀' },
    { id: 'confirmed', label: 'Confirmed Phishing', count: results.confirmed_phishing?.length, icon: '☠️' },
  ] : []

  return (
    <div className="min-h-screen bg-[#060b18] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <Fish size={16} className="text-white" />
            </div>
            <h1 className="text-xl font-bold text-white">Phishing Monitor</h1>
          </div>
          <p className="text-sm text-slate-400">
            Search any legitimate domain to discover phishing lookalikes in real-time. Click any domain to inspect.
          </p>
        </div>
        {results && (
          <div className="text-xs text-slate-500 flex items-center gap-2">
            <Clock size={11} />
            Scanned {new Date(results.scan_time).toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* Search */}
      <form onSubmit={handleScan}>
        <div className="relative group">
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-cyan-500/20 to-blue-500/20 blur-lg opacity-0 group-focus-within:opacity-100 transition-all duration-300" />
          <div className="relative flex items-center gap-4 bg-slate-900/80 border border-white/10 rounded-2xl px-5 py-4 focus-within:border-cyan-500/50 transition-colors">
            <Globe size={20} className="text-cyan-500 shrink-0" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Enter a domain to monitor  (e.g. paypal.com, amazon.com)"
              className="flex-1 bg-transparent text-white placeholder-slate-500 focus:outline-none text-lg font-mono"
              disabled={scanning}
            />
            {scanning ? (
              <div className="flex items-center gap-3 text-sm text-cyan-400">
                <Loader2 size={18} className="animate-spin" />
                <span>Scanning…</span>
              </div>
            ) : (
              <button
                type="submit"
                disabled={!query.trim()}
                className={clsx(
                  'flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all',
                  query.trim()
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:shadow-lg hover:shadow-cyan-500/30 hover:scale-105'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                )}
              >
                <Search size={16} />
                Scan
              </button>
            )}
          </div>
        </div>
      </form>

      {/* Scanning animation */}
      {scanning && (
        <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-10 flex flex-col items-center gap-6">
          <div className="relative">
            <div className="w-20 h-20 rounded-full border-2 border-cyan-500/20 border-t-cyan-500 animate-spin" />
            <div className="absolute inset-3 rounded-full border-2 border-blue-500/20 border-b-blue-500 animate-spin" style={{ animationDirection: 'reverse', animationDuration: '0.8s' }} />
            <Fish size={20} className="absolute inset-0 m-auto text-cyan-400" />
          </div>
          <div className="text-center">
            <div className="font-bold text-white mb-1">Scanning {query} across 7 sources</div>
            <div className="text-sm text-slate-400">Querying dnstwist, crt.sh, PhishTank, OpenPhish, and more…</div>
          </div>
          <div className="flex flex-wrap gap-2 justify-center">
            {['🔀 dnstwist', '🔐 crt.sh', '🎣 PhishTank', '🐟 OpenPhish', '📊 PhishStats', '🗄️ Phishing.DB', '🔍 URLScan'].map(s => (
              <span key={s} className="text-xs px-3 py-1 rounded-full bg-slate-800 border border-white/5 text-slate-400 flex items-center gap-1">
                <Loader2 size={10} className="animate-spin text-cyan-400" />
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
          <XCircle size={16} />
          {error}
        </div>
      )}

      {/* Results */}
      {results && !scanning && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard icon="🔀" label="Lookalike Domains" value={results.summary.lookalike_count} sub={`${results.summary.resolved_lookalikes} DNS-resolved`} color="orange" />
            <StatCard icon="☠️" label="Confirmed Phishing" value={results.summary.confirmed_phishing} sub="Across 5 threat feeds" color="red" />
            <StatCard icon="🔐" label="SSL Cert Lookalikes" value={results.lookalikes?.filter(l => l.source === 'crt.sh').length || 0} sub="From crt.sh" color="cyan" />
            <StatCard icon="🔍" label="Sources Checked" value={results.sources_run?.length || 7} sub="All free, no limits" color="green" />
          </div>

          {/* Info banner for scanned domain */}
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-cyan-500/5 border border-cyan-500/20 text-sm text-cyan-300">
            <Info size={14} className="shrink-0" />
            <span>Showing phishing lookalikes for <strong className="font-mono">{results.domain}</strong>. Click any domain row to see WHOIS, DNS records, malicious verdict, and live screenshot.</span>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 p-1 bg-slate-900/60 rounded-xl border border-white/5 w-fit">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all',
                  activeTab === tab.id
                    ? 'bg-slate-800 text-white border border-white/10'
                    : 'text-slate-400 hover:text-white'
                )}
              >
                <span>{tab.icon}</span>
                {tab.label}
                {tab.count > 0 && (
                  <span className={clsx(
                    'text-xs px-1.5 py-0.5 rounded-full font-semibold',
                    tab.id === 'confirmed' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'
                  )}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Lookalike Domains Table */}
          {activeTab === 'lookalikes' && (
            <div className="rounded-2xl border border-white/10 overflow-hidden bg-slate-900/30">
              <div className="px-5 py-3 border-b border-white/5 flex items-center justify-between">
                <h3 className="font-semibold text-sm text-white flex items-center gap-2">
                  🔀 Lookalike Domains
                  <span className="text-xs font-normal text-slate-400">(dnstwist + crt.sh)</span>
                </h3>
                <span className="text-xs text-slate-500">{results.lookalikes?.length} domains found</span>
              </div>
              {results.lookalikes?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-white/5 bg-slate-900/50">
                        <th className="text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider py-2.5 pl-4 pr-2">Domain</th>
                        <th className="text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider py-2.5 px-2">Source</th>
                        <th className="text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider py-2.5 px-2">Type</th>
                        <th className="text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider py-2.5 px-2">IP / A Record</th>
                        <th className="text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider py-2.5 px-2">MX Mail</th>
                        <th className="text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider py-2.5 px-2">Live</th>
                        <th className="text-left text-[10px] font-semibold text-slate-500 uppercase tracking-wider py-2.5 px-2">SSL</th>
                        <th className="py-2.5 pl-2 pr-4" />
                      </tr>
                    </thead>
                    <tbody>
                      {results.lookalikes.map(item => (
                        <DomainRow key={item.id} item={item} onClick={setSelectedDomain} />
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-500">
                  <CheckCircle size={32} className="text-green-500/50" />
                  <div className="text-sm">No lookalike domains found</div>
                </div>
              )}
            </div>
          )}

          {/* Confirmed Phishing Table */}
          {activeTab === 'confirmed' && (
            <div className="rounded-2xl border border-red-500/20 overflow-hidden bg-red-500/3">
              <div className="px-5 py-3 border-b border-red-500/10 flex items-center justify-between bg-red-500/5">
                <h3 className="font-semibold text-sm text-red-300 flex items-center gap-2">
                  <AlertTriangle size={14} />
                  Confirmed Phishing URLs
                </h3>
                <span className="text-xs text-red-400/70">{results.confirmed_phishing?.length} active threats</span>
              </div>
              {results.confirmed_phishing?.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-red-500/10 bg-red-500/5">
                        <th className="text-left text-[10px] font-semibold text-red-400/60 uppercase tracking-wider py-2.5 pl-4 pr-2">Domain</th>
                        <th className="text-left text-[10px] font-semibold text-red-400/60 uppercase tracking-wider py-2.5 px-2">Source</th>
                        <th className="text-left text-[10px] font-semibold text-red-400/60 uppercase tracking-wider py-2.5 px-2">URL</th>
                        <th className="py-2.5 pl-2 pr-4" />
                      </tr>
                    </thead>
                    <tbody>
                      {results.confirmed_phishing.map(item => (
                        <PhishRow key={item.id} item={item} onClick={setSelectedDomain} />
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-500">
                  <CheckCircle size={32} className="text-green-500/50" />
                  <div className="text-sm">No confirmed phishing URLs found</div>
                  <div className="text-xs text-slate-600">This is a good sign for this domain.</div>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Empty state */}
      {!results && !scanning && !error && (
        <div className="flex flex-col items-center justify-center py-24 gap-6">
          <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-600/10 border border-cyan-500/20 flex items-center justify-center">
            <Fish size={32} className="text-cyan-400" />
          </div>
          <div className="text-center">
            <h2 className="text-xl font-bold text-white mb-2">Domain Phishing Intelligence</h2>
            <p className="text-slate-400 max-w-md text-sm leading-relaxed">
              Enter any legitimate domain above to discover all lookalike and phishing domains targeting your brand. 
              Click any result to see live WHOIS, DNS, and malicious verdict.
            </p>
          </div>
          <div className="flex flex-wrap gap-3 justify-center">
            {['paypal.com', 'amazon.com', 'google.com', 'microsoft.com'].map(d => (
              <button
                key={d}
                onClick={() => { setQuery(d); setTimeout(handleScan, 100) }}
                className="px-4 py-2 text-sm rounded-xl bg-slate-800/60 border border-white/5 text-slate-400 hover:text-white hover:border-cyan-500/30 transition-all font-mono"
              >
                {d}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Domain Detail Drawer */}
      {selectedDomain && (
        <DomainDrawer domain={selectedDomain} onClose={() => setSelectedDomain(null)} />
      )}
    </div>
  )
}
