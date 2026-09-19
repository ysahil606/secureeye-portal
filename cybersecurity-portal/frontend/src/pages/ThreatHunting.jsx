import React, { useState, useEffect, useRef } from 'react';
import {
  Crosshair, ShieldAlert, Sparkles, RefreshCw, Filter, Search, CheckCircle2,
  XCircle, Clock, Copy, Download, ChevronRight, Layers, FileCode, Terminal,
  AlertTriangle, BookOpen, UserCheck, ArrowUpRight, Cpu, Target, Activity,
  Zap, Shield, Eye, BarChart2, TrendingUp, ExternalLink, Hash, Database
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import clsx from 'clsx';
import api from '../services/api';
import toast from 'react-hot-toast';

// ── Design Tokens ─────────────────────────────────────────────────────────────
const SEV_CONFIG = {
  critical: { color: '#ef4444', glow: 'rgba(239,68,68,0.4)', text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', iconBg: 'bg-red-500/15', badge: 'bg-red-500/15 text-red-400 border-red-500/25' },
  high:     { color: '#f97316', glow: 'rgba(249,115,22,0.4)', text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', iconBg: 'bg-orange-500/15', badge: 'bg-orange-500/15 text-orange-400 border-orange-500/25' },
  medium:   { color: '#eab308', glow: 'rgba(234,179,8,0.4)', text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', iconBg: 'bg-yellow-500/15', badge: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/25' },
  low:      { color: '#22c55e', glow: 'rgba(34,197,94,0.4)', text: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20', iconBg: 'bg-green-500/15', badge: 'bg-green-500/15 text-green-400 border-green-500/25' },
};

const STATUS_CONFIG = {
  open:           { color: '#06b6d4', text: 'text-cyan-400',    bg: 'bg-cyan-500/10',    border: 'border-cyan-500/20',    badge: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/25',    label: 'Open' },
  in_progress:    { color: '#a855f7', text: 'text-purple-400',  bg: 'bg-purple-500/10',  border: 'border-purple-500/20',  badge: 'bg-purple-500/15 text-purple-400 border-purple-500/25', label: 'In Progress' },
  confirmed:      { color: '#22c55e', text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25', label: 'Confirmed' },
  false_positive: { color: '#ef4444', text: 'text-rose-400',    bg: 'bg-rose-500/10',    border: 'border-rose-500/20',    badge: 'bg-rose-500/15 text-rose-400 border-rose-500/25',    label: 'False Positive' },
  archived:       { color: '#64748b', text: 'text-slate-400',   bg: 'bg-slate-500/10',   border: 'border-slate-500/20',   badge: 'bg-slate-500/15 text-slate-400 border-slate-500/25', label: 'Archived' },
};

const TACTIC_COLORS = {
  'Initial Access':       '#ef4444',
  'Execution':            '#f97316',
  'Persistence':          '#eab308',
  'Privilege Escalation': '#84cc16',
  'Defense Evasion':      '#22c55e',
  'Credential Access':    '#14b8a6',
  'Discovery':            '#06b6d4',
  'Lateral Movement':     '#3b82f6',
  'Collection':           '#6366f1',
  'Command And Control':  '#8b5cf6',
  'Exfiltration':         '#a855f7',
  'Impact':               '#ec4899',
  'Reconnaissance':       '#f43f5e',
  'Resource Development': '#fb923c',
};

// ── Animated Counter ──────────────────────────────────────────────────────────
function AnimatedNumber({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const steps = 40;
    const increment = value / steps;
    const interval = duration / steps;
    const timer = setInterval(() => {
      start += increment;
      if (start >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(Math.floor(start));
    }, interval);
    return () => clearInterval(timer);
  }, [value]);
  return display;
}

// ── KPI Metric Card ───────────────────────────────────────────────────────────
function MetricCard({ icon: Icon, label, value, sub, color = 'cyan', delay = 0 }) {
  const C = {
    red:    { border: 'border-red-500/20',    bg: 'bg-red-500/8',    text: 'text-red-400',    iconBg: 'bg-red-500/15',    glow: '0 0 30px rgba(239,68,68,0.12)' },
    orange: { border: 'border-orange-500/20', bg: 'bg-orange-500/8', text: 'text-orange-400', iconBg: 'bg-orange-500/15', glow: '0 0 30px rgba(249,115,22,0.12)' },
    cyan:   { border: 'border-cyan-500/20',   bg: 'bg-cyan-500/8',   text: 'text-cyan-400',   iconBg: 'bg-cyan-500/15',   glow: '0 0 30px rgba(6,182,212,0.12)' },
    purple: { border: 'border-purple-500/20', bg: 'bg-purple-500/8', text: 'text-purple-400', iconBg: 'bg-purple-500/15', glow: '0 0 30px rgba(139,92,246,0.12)' },
    green:  { border: 'border-green-500/20',  bg: 'bg-green-500/8',  text: 'text-green-400',  iconBg: 'bg-green-500/15',  glow: '0 0 30px rgba(34,197,94,0.12)' },
    yellow: { border: 'border-yellow-500/20', bg: 'bg-yellow-500/8', text: 'text-yellow-400', iconBg: 'bg-yellow-500/15', glow: '0 0 30px rgba(234,179,8,0.12)' },
    rose:   { border: 'border-rose-500/20',   bg: 'bg-rose-500/8',   text: 'text-rose-400',   iconBg: 'bg-rose-500/15',   glow: '0 0 30px rgba(244,63,94,0.12)' },
  }[color] || {};

  return (
    <div
      className={clsx('relative rounded-2xl border p-5 overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:brightness-110 cursor-default', C.border, C.bg)}
      style={{ boxShadow: C.glow, animationDelay: `${delay}ms` }}
    >
      <div className={clsx('absolute -top-6 -right-6 w-24 h-24 rounded-full blur-2xl opacity-30', C.iconBg)} />
      <div className="relative z-10">
        <div className="flex items-start justify-between mb-4">
          <div className={clsx('p-2.5 rounded-xl', C.iconBg)}>
            <Icon className={clsx('w-5 h-5', C.text)} />
          </div>
        </div>
        <div className={clsx('text-3xl font-black tracking-tighter tabular-nums', C.text)}>
          <AnimatedNumber value={value ?? 0} />
        </div>
        <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">{label}</div>
        {sub && <div className="text-[10px] text-slate-600 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}

// ── MITRE Tactic Coverage Bar ─────────────────────────────────────────────────
function TacticCoverageBar({ tactics }) {
  if (!tactics || Object.keys(tactics).length === 0) return null;
  const total = Object.values(tactics).reduce((s, v) => s + v, 0) || 1;
  const sorted = Object.entries(tactics).sort((a, b) => b[1] - a[1]);

  return (
    <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-indigo-500/15 border border-indigo-500/25 flex items-center justify-center">
            <Target className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <span className="text-xs font-black text-slate-400 uppercase tracking-widest">MITRE ATT&CK Tactic Coverage</span>
        </div>
        <span className="text-[10px] font-bold text-indigo-400 bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded-full">
          {sorted.length} Tactics Active
        </span>
      </div>
      <div className="space-y-3">
        {sorted.map(([tactic, count]) => {
          const pct = Math.round((count / total) * 100);
          const color = TACTIC_COLORS[tactic] || '#64748b';
          return (
            <div key={tactic}>
              <div className="flex justify-between items-center mb-1">
                <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">{tactic}</span>
                <span className="text-[10px] font-black tabular-nums" style={{ color }}>
                  {count} <span className="text-slate-600">({pct}%)</span>
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-slate-800/80 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-1000"
                  style={{ width: `${pct}%`, background: color, boxShadow: `0 0 8px ${color}60` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Confidence Gauge ──────────────────────────────────────────────────────────
function ConfidenceGauge({ score }) {
  const pct = Math.round((score || 0.8) * 100);
  const color = pct >= 85 ? '#22c55e' : pct >= 70 ? '#06b6d4' : pct >= 50 ? '#eab308' : '#ef4444';
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Confidence</span>
      <div className="w-20 bg-slate-800/80 rounded-full h-1.5 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, background: color, boxShadow: `0 0 6px ${color}60` }}
        />
      </div>
      <span className="text-[11px] font-black tabular-nums" style={{ color }}>{pct}%</span>
    </div>
  );
}

// ── Hypothesis Card ───────────────────────────────────────────────────────────
function HypothesisCard({ hypo, onSelect, onStatusChange }) {
  const sev = SEV_CONFIG[hypo.severity?.toLowerCase()] || SEV_CONFIG.medium;
  const status = STATUS_CONFIG[hypo.status] || STATUS_CONFIG.open;
  const tacticColor = TACTIC_COLORS[hypo.mitre_tactic] || '#64748b';

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={clsx(
        'group relative rounded-2xl border overflow-hidden transition-all duration-300 hover:-translate-y-0.5 hover:brightness-110 cursor-pointer',
        'bg-slate-900/40 backdrop-blur-xl',
        sev.border
      )}
      style={{ boxShadow: `0 0 25px ${sev.glow}12` }}
      onClick={() => onSelect(hypo)}
    >
      {/* Top glow accent */}
      <div className="absolute top-0 left-0 right-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${sev.color}40, transparent)` }} />
      <div className="absolute -top-8 -right-8 w-24 h-24 rounded-full blur-3xl opacity-15" style={{ background: sev.color }} />

      <div className="relative z-10 p-5">
        {/* Header: Badges Row */}
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2">
            <span className={clsx('text-[9px] font-black uppercase px-2 py-0.5 rounded-full border', sev.badge)}>
              {hypo.severity}
            </span>
            <span
              className="text-[10px] font-bold px-2 py-0.5 rounded-full border border-slate-700/50 bg-slate-800/60 text-slate-300 flex items-center gap-1"
            >
              <Hash className="w-2.5 h-2.5" style={{ color: tacticColor }} />
              {hypo.mitre_technique_id}
            </span>
          </div>
          <span className={clsx('text-[9px] font-black uppercase px-2 py-0.5 rounded-full border', status.badge)}>
            {status.label}
          </span>
        </div>

        {/* Title */}
        <h3 className="text-sm font-black text-slate-200 group-hover:text-white transition-colors leading-snug mb-2">
          {hypo.title}
        </h3>

        {/* Hypothesis Statement */}
        <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed mb-3">
          {hypo.hypothesis}
        </p>

        {/* Tactic + MITRE Name */}
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <span
            className="text-[10px] font-bold px-2 py-0.5 rounded border"
            style={{
              color: tacticColor,
              background: `${tacticColor}15`,
              borderColor: `${tacticColor}30`
            }}
          >
            {hypo.mitre_tactic}
          </span>
          <span className="text-[10px] text-slate-500 font-semibold">{hypo.mitre_name}</span>
          {hypo.target_sector && hypo.target_sector !== 'All Sectors' && (
            <span className="text-[10px] text-slate-500 font-medium bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700/30">
              {hypo.target_sector}
            </span>
          )}
        </div>

        {/* Trigger Reason */}
        {hypo.trigger_reason && (
          <div className="text-[10px] text-amber-300/80 bg-amber-500/8 border border-amber-500/15 p-2.5 rounded-xl flex items-start gap-1.5 mb-3">
            <AlertTriangle className="w-3 h-3 text-amber-400 flex-shrink-0 mt-0.5" />
            <span className="line-clamp-2">{hypo.trigger_reason}</span>
          </div>
        )}

        {/* Footer */}
        <div className="pt-3 border-t border-slate-800/60 flex items-center justify-between">
          <ConfidenceGauge score={hypo.confidence_score} />

          <div className="flex items-center gap-2">
            <select
              value={hypo.status}
              onChange={(e) => { e.stopPropagation(); onStatusChange(hypo.id, e.target.value); }}
              onClick={(e) => e.stopPropagation()}
              className="bg-slate-800/60 border border-slate-700/50 rounded-lg px-2 py-1 text-[10px] text-slate-300 focus:outline-none focus:border-cyan-500/50 cursor-pointer"
            >
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="confirmed">Confirmed</option>
              <option value="false_positive">False Positive</option>
              <option value="archived">Archive</option>
            </select>

            <button
              onClick={(e) => { e.stopPropagation(); onSelect(hypo); }}
              className="flex items-center gap-1 px-3 py-1.5 bg-cyan-600/15 border border-cyan-500/25 text-cyan-400 rounded-xl text-[10px] font-bold uppercase tracking-wider hover:bg-cyan-600/25 transition-all"
            >
              Investigate <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────
function DetailDrawer({ hypo, onClose, onStatusChange, onSaveNotes }) {
  const [activeTab, setActiveTab] = useState('kql');
  const [copiedKey, setCopiedKey] = useState(null);
  const [analystNotes, setAnalystNotes] = useState(hypo?.analyst_notes || '');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setAnalystNotes(hypo?.analyst_notes || '');
  }, [hypo]);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text || '');
    setCopiedKey(key);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadSigma = () => {
    const element = document.createElement('a');
    const file = new Blob([hypo.sigma_rule || ''], { type: 'text/yaml' });
    element.href = URL.createObjectURL(file);
    element.download = `sigma_${hypo.mitre_technique_id || 'rule'}_${hypo.id}.yml`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleSave = async () => {
    setSaving(true);
    await onSaveNotes(hypo.id, hypo.status, analystNotes);
    setSaving(false);
  };

  if (!hypo) return null;
  const sev = SEV_CONFIG[hypo.severity?.toLowerCase()] || SEV_CONFIG.medium;
  const status = STATUS_CONFIG[hypo.status] || STATUS_CONFIG.open;
  const tacticColor = TACTIC_COLORS[hypo.mitre_tactic] || '#64748b';

  const tabs = [
    { id: 'kql', label: 'KQL', sublabel: 'Microsoft Sentinel', icon: Terminal, color: 'cyan' },
    { id: 'spl', label: 'SPL', sublabel: 'Splunk', icon: FileCode, color: 'orange' },
    { id: 'sigma', label: 'Sigma', sublabel: 'YAML Rule', icon: ShieldAlert, color: 'blue' },
    { id: 'steps', label: 'Playbook', sublabel: 'Hunt Steps', icon: UserCheck, color: 'green' },
  ];

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      {/* Backdrop */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
      />

      {/* Panel */}
      <motion.div
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 28, stiffness: 300 }}
        className="relative w-full max-w-3xl bg-slate-950 border-l border-slate-800/60 h-full flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top accent line */}
        <div className="absolute top-0 left-0 right-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${sev.color}, transparent)` }} />
        <div className="absolute top-0 right-0 w-60 h-60 rounded-full blur-[100px] opacity-10 pointer-events-none" style={{ background: sev.color }} />

        {/* Header */}
        <div className="relative z-10 p-6 border-b border-slate-800/60 bg-slate-900/60 backdrop-blur-xl flex-shrink-0">
          <div className="flex items-start justify-between">
            <div className="space-y-2 pr-4 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className={clsx('text-[9px] font-black uppercase px-2 py-0.5 rounded-full border', sev.badge)}>
                  {hypo.severity}
                </span>
                <span className={clsx('text-[9px] font-black uppercase px-2 py-0.5 rounded-full border', status.badge)}>
                  {status.label}
                </span>
                <span
                  className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                  style={{ color: tacticColor, background: `${tacticColor}15`, borderColor: `${tacticColor}30` }}
                >
                  {hypo.mitre_technique_id} • {hypo.mitre_tactic}
                </span>
              </div>
              <h2 className="text-lg font-black text-white leading-tight">{hypo.title}</h2>
              <div className="flex items-center gap-3 text-[10px] text-slate-500">
                <span>MITRE: {hypo.mitre_name}</span>
                {hypo.target_sector && <span>• Sector: {hypo.target_sector}</span>}
                <ConfidenceGauge score={hypo.confidence_score} />
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white bg-slate-800/60 hover:bg-slate-700/60 rounded-xl transition-all border border-slate-700/40 flex-shrink-0"
            >
              <XCircle className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5" style={{ scrollbarWidth: 'none' }}>
          {/* Hypothesis Statement */}
          <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 p-4">
            <div className="text-[10px] text-cyan-400 font-black uppercase tracking-widest mb-2 flex items-center gap-1.5">
              <BookOpen className="w-3.5 h-3.5" /> Hypothesis Statement
            </div>
            <p className="text-[13px] text-slate-200 leading-relaxed font-mono bg-slate-950/60 p-4 rounded-xl border border-slate-800/40">
              {hypo.hypothesis}
            </p>
          </div>

          {/* External Link */}
          <a
            href={`https://attack.mitre.org/techniques/${hypo.mitre_technique_id?.replace('.', '/')}/`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 text-[11px] font-bold text-indigo-400 hover:text-white bg-indigo-500/10 border border-indigo-500/20 px-3 py-2 rounded-xl transition-all hover:bg-indigo-500/20"
          >
            <ExternalLink className="w-3 h-3" />
            View {hypo.mitre_technique_id} on MITRE ATT&CK Navigator →
          </a>

          {/* Code Query Tabs */}
          <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 overflow-hidden">
            {/* Tab Buttons */}
            <div className="flex border-b border-slate-800/60 bg-slate-900/60">
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={clsx(
                    'flex-1 flex flex-col items-center gap-0.5 py-3 px-2 text-[10px] font-bold transition-all border-b-2',
                    activeTab === tab.id
                      ? `border-${tab.color}-400 text-${tab.color}-300 bg-${tab.color}-500/10`
                      : 'border-transparent text-slate-500 hover:text-slate-300 hover:bg-slate-800/30'
                  )}
                  style={activeTab === tab.id ? {
                    borderBottomColor: tab.color === 'cyan' ? '#06b6d4' : tab.color === 'orange' ? '#f97316' : tab.color === 'blue' ? '#3b82f6' : '#22c55e',
                    color: tab.color === 'cyan' ? '#22d3ee' : tab.color === 'orange' ? '#fb923c' : tab.color === 'blue' ? '#60a5fa' : '#4ade80',
                    background: tab.color === 'cyan' ? 'rgba(6,182,212,0.08)' : tab.color === 'orange' ? 'rgba(249,115,22,0.08)' : tab.color === 'blue' ? 'rgba(59,130,246,0.08)' : 'rgba(34,197,94,0.08)',
                  } : {}}
                >
                  <tab.icon className="w-3.5 h-3.5" />
                  <span className="uppercase tracking-wider">{tab.label}</span>
                </button>
              ))}
            </div>

            {/* Code Display */}
            <div className="p-4">
              {activeTab === 'kql' && (
                <>
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Microsoft Sentinel / Defender KQL</span>
                    <button
                      onClick={() => copyToClipboard(hypo.kql_query, 'kql')}
                      className="flex items-center gap-1 px-2.5 py-1 bg-slate-800/60 hover:bg-slate-700 text-cyan-400 rounded-lg border border-slate-700/50 text-[10px] font-bold transition-all"
                    >
                      <Copy className="w-3 h-3" />
                      {copiedKey === 'kql' ? 'Copied!' : 'Copy KQL'}
                    </button>
                  </div>
                  <pre className="font-mono text-[12px] text-emerald-400 leading-relaxed bg-slate-950/80 p-4 rounded-xl border border-slate-800/40 overflow-x-auto whitespace-pre-wrap">
                    {hypo.kql_query || '// No KQL query available for this hypothesis'}
                  </pre>
                </>
              )}

              {activeTab === 'spl' && (
                <>
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Splunk Search Processing Language</span>
                    <button
                      onClick={() => copyToClipboard(hypo.spl_query, 'spl')}
                      className="flex items-center gap-1 px-2.5 py-1 bg-slate-800/60 hover:bg-slate-700 text-orange-400 rounded-lg border border-slate-700/50 text-[10px] font-bold transition-all"
                    >
                      <Copy className="w-3 h-3" />
                      {copiedKey === 'spl' ? 'Copied!' : 'Copy SPL'}
                    </button>
                  </div>
                  <pre className="font-mono text-[12px] text-amber-300 leading-relaxed bg-slate-950/80 p-4 rounded-xl border border-slate-800/40 overflow-x-auto whitespace-pre-wrap">
                    {hypo.spl_query || '// No SPL query available for this hypothesis'}
                  </pre>
                </>
              )}

              {activeTab === 'sigma' && (
                <>
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Generic Sigma Detection Rule</span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => copyToClipboard(hypo.sigma_rule, 'sigma')}
                        className="flex items-center gap-1 px-2.5 py-1 bg-slate-800/60 hover:bg-slate-700 text-blue-400 rounded-lg border border-slate-700/50 text-[10px] font-bold transition-all"
                      >
                        <Copy className="w-3 h-3" />
                        {copiedKey === 'sigma' ? 'Copied!' : 'Copy'}
                      </button>
                      <button
                        onClick={downloadSigma}
                        className="flex items-center gap-1 px-2.5 py-1 bg-cyan-600/15 hover:bg-cyan-600/25 text-cyan-400 rounded-lg border border-cyan-500/25 text-[10px] font-bold transition-all"
                      >
                        <Download className="w-3 h-3" /> .yml
                      </button>
                    </div>
                  </div>
                  <pre className="font-mono text-[12px] text-blue-300 leading-relaxed bg-slate-950/80 p-4 rounded-xl border border-slate-800/40 overflow-x-auto whitespace-pre-wrap">
                    {hypo.sigma_rule || '# No Sigma rule available for this hypothesis'}
                  </pre>
                </>
              )}

              {activeTab === 'steps' && (
                <div className="space-y-2.5">
                  <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">SOC Analyst Investigation Checklist</div>
                  {hypo.investigation_steps && hypo.investigation_steps.length > 0 ? (
                    hypo.investigation_steps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-3 bg-slate-950/60 p-3 rounded-xl border border-slate-800/40 hover:border-slate-700/50 transition-all">
                        <div
                          className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-black flex-shrink-0 border"
                          style={{ color: '#22c55e', background: 'rgba(34,197,94,0.1)', borderColor: 'rgba(34,197,94,0.2)' }}
                        >
                          {idx + 1}
                        </div>
                        <span className="text-[12px] text-slate-300 leading-relaxed">{step}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-[11px] text-slate-600 italic p-4">No specific investigation steps recorded.</div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Data Sources */}
          {hypo.data_sources && hypo.data_sources.length > 0 && (
            <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 p-4">
              <div className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-3 flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5" /> Required Telemetry Sources
              </div>
              <div className="flex flex-wrap gap-2">
                {hypo.data_sources.map((src, i) => (
                  <span key={i} className="text-[10px] font-mono text-purple-400 bg-purple-500/10 border border-purple-500/20 px-2.5 py-1 rounded-lg">
                    {src}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Trigger IOCs */}
          {hypo.trigger_iocs && hypo.trigger_iocs.length > 0 && (
            <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 p-4">
              <div className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-3 flex items-center gap-1.5">
                <Eye className="w-3.5 h-3.5" /> Associated IOC / CVE Triggers
              </div>
              <div className="flex flex-wrap gap-2">
                {hypo.trigger_iocs.map((ioc, i) => (
                  <span key={i} className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2.5 py-1 rounded-lg">
                    {ioc}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Analyst Notes */}
          <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 p-4 space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-[10px] text-slate-500 font-black uppercase tracking-widest flex items-center gap-1.5">
                <UserCheck className="w-3.5 h-3.5" /> SOC Analyst Hunting Notes
              </span>
              <button
                onClick={handleSave}
                disabled={saving}
                className="flex items-center gap-1 px-3 py-1.5 bg-cyan-600/15 border border-cyan-500/25 text-cyan-400 rounded-lg text-[10px] font-bold uppercase tracking-wider hover:bg-cyan-600/25 transition-all disabled:opacity-50"
              >
                {saving ? <RefreshCw className="w-3 h-3 animate-spin" /> : <CheckCircle2 className="w-3 h-3" />}
                {saving ? 'Saving...' : 'Save Notes'}
              </button>
            </div>
            <textarea
              rows={4}
              placeholder="Enter notes, false-positive justification, or incident ticket references..."
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800/40 rounded-xl p-3 text-[12px] text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/40 resize-none"
            />
          </div>
        </div>
      </motion.div>
    </div>
  );
}

// ── MAIN THREAT HUNTING PAGE ──────────────────────────────────────────────────
export default function ThreatHunting() {
  const [stats, setStats] = useState({
    total_hypotheses: 0,
    open_count: 0,
    in_progress_count: 0,
    confirmed_count: 0,
    false_positive_count: 0,
    true_positive_rate_percent: 0.0,
    cached_mitre_techniques: 0,
    top_tactics: {},
    severity_distribution: {},
    sector_distribution: {}
  });
  const [hypotheses, setHypotheses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [syncingMitre, setSyncingMitre] = useState(false);

  // Filters
  const [statusFilter, setStatusFilter] = useState('');
  const [sectorFilter, setSectorFilter] = useState('All Sectors');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Detail drawer
  const [selectedHypo, setSelectedHypo] = useState(null);

  // Generation modal
  const [showGenModal, setShowGenModal] = useState(false);
  const [targetSectorGen, setTargetSectorGen] = useState('All Sectors');
  const [genCount, setGenCount] = useState(5);

  const fetchStats = async () => {
    try {
      const res = await api.get('/threat-hunting/stats');
      setStats(res.data);
    } catch (e) {
      console.error('Failed to fetch threat hunting stats', e);
    }
  };

  const fetchHypotheses = async () => {
    setLoading(true);
    try {
      const params = {};
      if (sectorFilter && sectorFilter !== 'All Sectors') params.sector = sectorFilter;
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      if (searchTerm) params.search = searchTerm;

      const res = await api.get('/threat-hunting/hypotheses', { params });
      setHypotheses(res.data.hypotheses || []);
    } catch (e) {
      console.error('Failed to fetch hypotheses', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    fetchHypotheses();
  }, [statusFilter, sectorFilter, severityFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchHypotheses();
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setShowGenModal(false);
    try {
      await api.post('/threat-hunting/generate', {
        sector: targetSectorGen,
        count: parseInt(genCount)
      });
      toast.success('AI hypotheses generated successfully');
      await fetchStats();
      await fetchHypotheses();
    } catch (e) {
      console.error('Error generating hypotheses', e);
      const errDetail = e.response?.data?.detail || 'Failed to generate hypotheses';
      toast.error(`Generation Error: ${errDetail}`);
    } finally {
      setGenerating(false);
    }
  };

  const handleMitreSync = async () => {
    setSyncingMitre(true);
    try {
      const res = await api.post('/threat-hunting/mitre/sync');
      toast.success(`MITRE Sync Complete! Added: ${res.data.added}, Updated: ${res.data.updated}`);
      fetchStats();
    } catch (e) {
      console.error('Error syncing MITRE', e);
      toast.error('MITRE sync failed');
    } finally {
      setSyncingMitre(false);
    }
  };

  const handleUpdateStatus = async (id, newStatus) => {
    try {
      const res = await api.patch(`/threat-hunting/hypotheses/${id}/status`, { status: newStatus });
      const updated = res.data;
      setHypotheses(prev => prev.map(h => h.id === id ? updated : h));
      if (selectedHypo && selectedHypo.id === id) setSelectedHypo(updated);
      fetchStats();
      toast.success(`Status updated to ${newStatus.replace('_', ' ')}`);
    } catch (e) {
      console.error('Failed to update status', e);
      toast.error('Failed to update status');
    }
  };

  const handleSaveNotes = async (id, status, notes) => {
    try {
      const res = await api.patch(`/threat-hunting/hypotheses/${id}/status`, {
        status: status,
        analyst_notes: notes
      });
      const updated = res.data;
      setSelectedHypo(updated);
      setHypotheses(prev => prev.map(h => h.id === updated.id ? updated : h));
      toast.success('Notes saved');
    } catch (e) {
      console.error('Failed to save notes', e);
      toast.error('Failed to save notes');
    }
  };

  const statusTabs = [
    { key: '', label: 'All', count: stats.total_hypotheses },
    { key: 'open', label: 'Open', count: stats.open_count },
    { key: 'in_progress', label: 'In Progress', count: stats.in_progress_count },
    { key: 'confirmed', label: 'Confirmed', count: stats.confirmed_count },
    { key: 'false_positive', label: 'False Positive', count: stats.false_positive_count },
  ];

  return (
    <div className="space-y-6 pb-20 relative">

      {/* ── Ambient Background ─────────────────────────────────────────────── */}
      <div className="fixed top-0 left-1/4 w-[600px] h-[600px] bg-cyan-600/5 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-[600px] h-[600px] bg-purple-600/5 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-indigo-600/3 rounded-full blur-[160px] pointer-events-none -z-10" />

      {/* ── Header Bar ─────────────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-5 flex flex-col lg:flex-row lg:items-center gap-5">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <div className="relative flex items-center justify-center">
              <span className="absolute w-3 h-3 rounded-full bg-cyan-500 animate-ping opacity-50" />
              <div className="relative w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center">
                <Crosshair className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-200 to-slate-400 tracking-tight">
                  Threat Hunting Engine
                </h1>
                <span className="text-[9px] font-black text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded-full uppercase tracking-widest">
                  AI Automated
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
                <span className="flex items-center gap-1"><Layers className="w-3 h-3" /> MITRE ATT&CK Mapped</span>
                <span className="w-1 h-1 rounded-full bg-slate-700" />
                <span className="flex items-center gap-1"><Database className="w-3 h-3" /> {stats.cached_mitre_techniques} techniques cached</span>
                <span className="w-1 h-1 rounded-full bg-slate-700" />
                <span className="flex items-center gap-1"><Activity className="w-3 h-3" /> {stats.total_hypotheses} hypotheses indexed</span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleMitreSync}
            disabled={syncingMitre}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800/60 border border-slate-700/40 text-slate-300 text-[10px] font-bold uppercase tracking-wider hover:bg-slate-700/50 hover:text-white transition-all disabled:opacity-50"
          >
            <RefreshCw className={clsx('w-3.5 h-3.5 text-cyan-400', syncingMitre && 'animate-spin')} />
            {syncingMitre ? 'Syncing...' : 'Sync MITRE'}
          </button>

          <button
            onClick={() => setShowGenModal(true)}
            disabled={generating}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-[10px] font-black uppercase tracking-wider shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            <Sparkles className={clsx('w-3.5 h-3.5', generating && 'animate-spin')} />
            {generating ? 'Generating...' : 'Generate AI Hypotheses'}
          </button>
        </div>
      </div>

      {/* ── KPI Cards Row ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard icon={Target}         label="Total Hypotheses"    value={stats.total_hypotheses}            color="cyan"   sub="AI Generated" delay={0} />
        <MetricCard icon={Crosshair}      label="Active Hunts"        value={stats.open_count}                  color="purple" sub="Ready for SOC" delay={50} />
        <MetricCard icon={Activity}       label="In Progress"         value={stats.in_progress_count}           color="yellow" sub="Under investigation" delay={100} />
        <MetricCard icon={CheckCircle2}   label="Confirmed Threats"   value={stats.confirmed_count}             color="green"  sub="True positives" delay={150} />
        <MetricCard icon={Shield}         label="True Positive Rate"  value={Math.round(stats.true_positive_rate_percent)} color="green"  sub="Hit ratio" delay={200} />
        <MetricCard icon={Cpu}            label="MITRE Library"       value={stats.cached_mitre_techniques}     color="purple" sub="STIX 2.1 cached" delay={250} />
      </div>

      {/* ── MITRE Tactic Coverage ──────────────────────────────────────────── */}
      {stats.top_tactics && Object.keys(stats.top_tactics).length > 0 && (
        <TacticCoverageBar tactics={stats.top_tactics} />
      )}

      {/* ── Filter Bar ─────────────────────────────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        {/* Status Tabs */}
        <div className="flex flex-wrap items-center gap-1.5">
          {statusTabs.map((tab) => {
            const isActive = statusFilter === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setStatusFilter(tab.key)}
                className={clsx(
                  'px-3 py-1.5 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all border',
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                    : 'bg-slate-800/30 text-slate-500 hover:text-slate-300 border-transparent hover:border-slate-700/40'
                )}
              >
                {tab.label}
                {tab.count > 0 && (
                  <span className={clsx('ml-1.5 tabular-nums', isActive ? 'text-cyan-400' : 'text-slate-600')}>
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-3">
          {/* Sector Select */}
          <select
            value={sectorFilter}
            onChange={(e) => setSectorFilter(e.target.value)}
            className="bg-slate-800/60 border border-slate-700/50 rounded-xl px-3 py-2 text-[10px] text-slate-300 focus:outline-none focus:border-cyan-500/50 cursor-pointer font-bold uppercase tracking-wider"
          >
            <option value="All Sectors">All Sectors</option>
            <option value="Financial">Financial</option>
            <option value="Healthcare">Healthcare</option>
            <option value="Government">Government</option>
            <option value="Critical Infrastructure">Critical Infra</option>
            <option value="Tech">Tech & SaaS</option>
          </select>

          {/* Severity */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-800/60 border border-slate-700/50 rounded-xl px-3 py-2 text-[10px] text-slate-300 focus:outline-none focus:border-cyan-500/50 cursor-pointer font-bold uppercase tracking-wider"
          >
            <option value="">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Search */}
          <form onSubmit={handleSearchSubmit} className="relative flex items-center">
            <Search className="absolute left-3 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search TTPs, IOCs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-800/60 border border-slate-700/50 rounded-xl pl-9 pr-4 py-2 text-[11px] text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 w-48 transition-colors"
            />
          </form>
        </div>
      </div>

      {/* ── Hypotheses Grid ────────────────────────────────────────────────── */}
      {loading ? (
        <div className="flex flex-col items-center justify-center h-[40vh] gap-4">
          <div className="relative w-16 h-16">
            <div className="absolute inset-0 rounded-full border-[3px] border-slate-800" />
            <div className="absolute inset-0 rounded-full border-[3px] border-t-cyan-500 animate-spin" />
            <div className="absolute inset-0 rounded-full border-[3px] border-r-purple-500 animate-spin" style={{ animationDuration: '1.5s', animationDirection: 'reverse' }} />
            <Crosshair className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
          </div>
          <div className="text-[11px] font-black text-cyan-500/60 uppercase tracking-[0.25em] animate-pulse">
            Scanning MITRE ATT&CK Telemetry
          </div>
        </div>
      ) : hypotheses.length === 0 ? (
        <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 backdrop-blur-xl py-16 flex flex-col items-center justify-center">
          <div className="w-16 h-16 rounded-2xl bg-slate-800/60 border border-slate-700/40 flex items-center justify-center mb-4">
            <ShieldAlert className="w-8 h-8 text-slate-600" />
          </div>
          <h3 className="text-base font-black text-white mb-1">No Hypotheses Found</h3>
          <p className="text-[11px] text-slate-500 max-w-md text-center mb-5 leading-relaxed">
            No threat hunting hypotheses match your active filters. Click the button below to trigger AI-powered hypothesis generation.
          </p>
          <button
            onClick={() => setShowGenModal(true)}
            className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600/15 border border-cyan-500/25 text-cyan-400 rounded-xl text-[10px] font-bold uppercase tracking-wider hover:bg-cyan-600/25 transition-all"
          >
            <Sparkles className="w-3.5 h-3.5" /> Generate AI Hypotheses
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {hypotheses.map((hypo) => (
            <HypothesisCard
              key={hypo.id}
              hypo={hypo}
              onSelect={setSelectedHypo}
              onStatusChange={handleUpdateStatus}
            />
          ))}
        </div>
      )}

      {/* ── Detail Drawer ──────────────────────────────────────────────────── */}
      <AnimatePresence>
        {selectedHypo && (
          <DetailDrawer
            hypo={selectedHypo}
            onClose={() => setSelectedHypo(null)}
            onStatusChange={handleUpdateStatus}
            onSaveNotes={handleSaveNotes}
          />
        )}
      </AnimatePresence>

      {/* ── Generation Modal ───────────────────────────────────────────────── */}
      <AnimatePresence>
        {showGenModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={() => setShowGenModal(false)}>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              className="relative bg-slate-950 border border-slate-800/60 rounded-2xl p-6 max-w-md w-full shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Top accent */}
              <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyan-500 to-transparent" />
              <div className="absolute -top-8 right-8 w-32 h-32 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

              <div className="relative z-10">
                <div className="flex justify-between items-center border-b border-slate-800/60 pb-4 mb-5">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center">
                      <Sparkles className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <h3 className="text-sm font-black text-white">AI Hunt Engine</h3>
                      <p className="text-[10px] text-slate-500 uppercase tracking-wider">Configure generation parameters</p>
                    </div>
                  </div>
                  <button onClick={() => setShowGenModal(false)} className="p-2 text-slate-400 hover:text-white bg-slate-800/60 rounded-xl border border-slate-700/40 transition-all">
                    <XCircle className="w-4 h-4" />
                  </button>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-[10px] text-slate-500 font-black uppercase tracking-widest mb-2">Target Sector Environment</label>
                    <select
                      value={targetSectorGen}
                      onChange={(e) => setTargetSectorGen(e.target.value)}
                      className="w-full bg-slate-900/60 border border-slate-800/60 rounded-xl p-3 text-[12px] text-slate-200 focus:outline-none focus:border-cyan-500/40"
                    >
                      <option value="All Sectors">All Sectors (Cross-Industry)</option>
                      <option value="Financial">Financial / Banking</option>
                      <option value="Healthcare">Healthcare & BioTech</option>
                      <option value="Government">Government & Defense</option>
                      <option value="Critical Infrastructure">Critical Infrastructure & Energy</option>
                      <option value="Tech">Tech & Cloud SaaS</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-[10px] text-slate-500 font-black uppercase tracking-widest mb-2">Hypothesis Count</label>
                    <select
                      value={genCount}
                      onChange={(e) => setGenCount(e.target.value)}
                      className="w-full bg-slate-900/60 border border-slate-800/60 rounded-xl p-3 text-[12px] text-slate-200 focus:outline-none focus:border-cyan-500/40"
                    >
                      <option value="3">3 Hypotheses — Quick Scan</option>
                      <option value="5">5 Hypotheses — Recommended</option>
                      <option value="8">8 Hypotheses — Deep Hunt</option>
                    </select>
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-5 border-t border-slate-800/60 mt-5">
                  <button
                    onClick={() => setShowGenModal(false)}
                    className="px-4 py-2.5 bg-slate-800/60 hover:bg-slate-700/60 text-slate-300 rounded-xl text-[10px] font-bold uppercase tracking-wider border border-slate-700/40 transition-all"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleGenerate}
                    className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-[10px] font-black uppercase tracking-wider shadow-lg shadow-cyan-500/20 transition-all"
                  >
                    <span className="flex items-center gap-2">
                      <Zap className="w-3.5 h-3.5" /> Launch Hunt Engine
                    </span>
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
