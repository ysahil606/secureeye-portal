import React, { useState, useEffect } from 'react';
import {
  Crosshair, ShieldAlert, Sparkles, RefreshCw, Filter, Search, CheckCircle2,
  XCircle, Clock, Copy, Download, ChevronRight, Layers, FileCode, Terminal,
  AlertTriangle, BookOpen, UserCheck, ArrowUpRight, Cpu
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../services/api';

export default function ThreatHunting() {
  const [stats, setStats] = useState({
    total_hypotheses: 0,
    open_count: 0,
    in_progress_count: 0,
    confirmed_count: 0,
    false_positive_count: 0,
    true_positive_rate_percent: 0.0,
    cached_mitre_techniques: 0
  });

  const [hypotheses, setHypotheses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [syncingMitre, setSyncingMitre] = useState(false);

  // Filters - default statusFilter to empty '' so ALL hypotheses show up by default
  const [statusFilter, setStatusFilter] = useState('');
  const [sectorFilter, setSectorFilter] = useState('All Sectors');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Selected hypothesis drawer
  const [selectedHypo, setSelectedHypo] = useState(null);
  const [activeTab, setActiveTab] = useState('kql'); // 'kql', 'spl', 'sigma', 'steps'
  const [copiedKey, setCopiedKey] = useState(null);
  const [analystNotes, setAnalystNotes] = useState('');
  const [updatingNotes, setUpdatingNotes] = useState(false);

  // Sector selection modal for generation
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
      const res = await api.post('/threat-hunting/generate', {
        sector: targetSectorGen,
        count: parseInt(genCount)
      });
      await fetchStats();
      await fetchHypotheses();
    } catch (e) {
      console.error('Error generating hypotheses', e);
      const errDetail = e.response?.data?.detail || 'Failed to generate hypotheses';
      alert(`Generation Error: ${errDetail}`);
    } finally {
      setGenerating(false);
    }
  };

  const handleMitreSync = async () => {
    setSyncingMitre(true);
    try {
      const res = await api.post('/threat-hunting/mitre/sync');
      const data = res.data;
      alert(`MITRE Sync Complete! Added: ${data.added}, Updated: ${data.updated}`);
      fetchStats();
    } catch (e) {
      console.error('Error syncing MITRE', e);
    } finally {
      setSyncingMitre(false);
    }
  };

  const handleUpdateStatus = async (id, newStatus) => {
    try {
      const res = await api.patch(`/threat-hunting/hypotheses/${id}/status`, { status: newStatus });
      const updated = res.data;
      setHypotheses(prev => prev.map(h => h.id === id ? updated : h));
      if (selectedHypo && selectedHypo.id === id) {
        setSelectedHypo(updated);
      }
      fetchStats();
    } catch (e) {
      console.error('Failed to update status', e);
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedHypo) return;
    setUpdatingNotes(true);
    try {
      const res = await api.patch(`/threat-hunting/hypotheses/${selectedHypo.id}/status`, {
        status: selectedHypo.status,
        analyst_notes: analystNotes
      });
      const updated = res.data;
      setSelectedHypo(updated);
      setHypotheses(prev => prev.map(h => h.id === updated.id ? updated : h));
    } catch (e) {
      console.error('Failed to save analyst notes', e);
    } finally {
      setUpdatingNotes(false);
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadSigma = (hypo) => {
    const element = document.createElement('a');
    const file = new Blob([hypo.sigma_rule || ''], { type: 'text/yaml' });
    element.href = URL.createObjectURL(file);
    element.download = `sigma_${hypo.mitre_technique_id || 'rule'}_${hypo.id}.yml`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const getSeverityBadge = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'medium':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getStatusBadge = (st) => {
    switch (st) {
      case 'open':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
      case 'in_progress':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'confirmed':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
      case 'false_positive':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-6 text-slate-200">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-dark-800/60 p-6 rounded-2xl border border-white/5 backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 rounded-xl text-cyan-400">
              <Crosshair className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
                Threat Hunting Engine
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-semibold">
                  AI Automated
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Autonomous MITRE ATT&CK hypothesis generation mapped to live threat telemetry & Sigma detection rules.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleMitreSync}
            disabled={syncingMitre}
            className="flex items-center gap-2 px-4 py-2.5 bg-dark-700/80 hover:bg-dark-600 border border-white/10 rounded-xl text-sm font-semibold transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 text-cyan-400 ${syncingMitre ? 'animate-spin' : ''}`} />
            {syncingMitre ? 'Syncing ATT&CK...' : 'Sync MITRE'}
          </button>

          <button
            onClick={() => setShowGenModal(true)}
            disabled={generating}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white rounded-xl text-sm font-bold shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
          >
            <Sparkles className={`w-4 h-4 ${generating ? 'animate-spin' : ''}`} />
            {generating ? 'Generating AI Hunts...' : 'Generate AI Hypotheses'}
          </button>
        </div>
      </div>

      {/* Metrics Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 bg-dark-800/40 border border-white/5 rounded-2xl backdrop-blur-md">
          <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">Total Hypotheses</div>
          <div className="text-2xl font-extrabold text-white">{stats.total_hypotheses}</div>
          <div className="text-[11px] text-cyan-400 mt-1 flex items-center gap-1">
            <Layers className="w-3 h-3" /> Mapped to MITRE ATT&CK
          </div>
        </div>

        <div className="p-4 bg-dark-800/40 border border-white/5 rounded-2xl backdrop-blur-md">
          <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">Active Hunts (Open)</div>
          <div className="text-2xl font-extrabold text-cyan-400">{stats.open_count}</div>
          <div className="text-[11px] text-slate-400 mt-1">Ready for SOC execution</div>
        </div>

        <div className="p-4 bg-dark-800/40 border border-white/5 rounded-2xl backdrop-blur-md">
          <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">True Positive Rate</div>
          <div className="text-2xl font-extrabold text-emerald-400">{stats.true_positive_rate_percent}%</div>
          <div className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> {stats.confirmed_count} Confirmed Threats
          </div>
        </div>

        <div className="p-4 bg-dark-800/40 border border-white/5 rounded-2xl backdrop-blur-md">
          <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">MITRE ATT&CK Library</div>
          <div className="text-2xl font-extrabold text-purple-400">{stats.cached_mitre_techniques}</div>
          <div className="text-[11px] text-purple-300 mt-1 flex items-center gap-1">
            <Cpu className="w-3 h-3" /> STIX 2.1 Cached Techniques
          </div>
        </div>
      </div>

      {/* Filter Bar & Search */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 bg-dark-800/30 p-4 rounded-2xl border border-white/5">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filter Buttons */}
          {['', 'open', 'in_progress', 'confirmed', 'false_positive'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold capitalize transition-all ${
                statusFilter === st
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'bg-dark-700/50 text-slate-400 hover:text-white border border-transparent'
              }`}
            >
              {st === '' ? 'All Status' : st.replace('_', ' ')}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3">
          {/* Sector Select */}
          <select
            value={sectorFilter}
            onChange={(e) => setSectorFilter(e.target.value)}
            className="bg-dark-900/80 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="All Sectors">All Sectors</option>
            <option value="Financial">Financial Sector</option>
            <option value="Healthcare">Healthcare</option>
            <option value="Government">Government / Defense</option>
            <option value="Critical Infrastructure">Critical Infrastructure</option>
            <option value="Tech">Tech & SaaS</option>
          </select>

          {/* Search form */}
          <form onSubmit={handleSearchSubmit} className="relative flex-1 md:w-64">
            <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search TTPs, title..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-dark-900/80 border border-white/10 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </form>
        </div>
      </div>

      {/* Main Hypotheses Grid */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center space-y-4">
          <div className="w-10 h-10 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
          <div className="text-sm text-slate-400 font-medium">Scanning MITRE ATT&CK telemetry & generating hypotheses...</div>
        </div>
      ) : hypotheses.length === 0 ? (
        <div className="py-16 text-center bg-dark-800/20 border border-white/5 rounded-2xl p-8">
          <ShieldAlert className="w-12 h-12 text-slate-500 mx-auto mb-3" />
          <h3 className="text-base font-bold text-white mb-1">No Threat Hunting Hypotheses Found</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto mb-4">
            No hypotheses match your active filters. Click "Generate AI Hypotheses" to trigger live automated hunt creation.
          </p>
          <button
            onClick={() => setShowGenModal(true)}
            className="px-4 py-2 bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-xl text-xs font-semibold hover:bg-cyan-500/30"
          >
            Generate Now
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {hypotheses.map((hypo) => (
            <motion.div
              key={hypo.id}
              layout
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-dark-800/40 hover:bg-dark-800/70 border border-white/5 hover:border-cyan-500/30 transition-all rounded-2xl p-5 flex flex-col justify-between group backdrop-blur-md shadow-lg"
            >
              <div>
                {/* Header badges */}
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-extrabold uppercase border ${getSeverityBadge(hypo.severity)}`}>
                      {hypo.severity}
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-dark-900/80 text-cyan-300 border border-cyan-500/20">
                      {hypo.mitre_technique_id} • {hypo.mitre_name}
                    </span>
                  </div>

                  <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${getStatusBadge(hypo.status)}`}>
                    {hypo.status?.replace('_', ' ')}
                  </span>
                </div>

                {/* Title & Hypothesis */}
                <h3 className="text-base font-bold text-white mb-2 group-hover:text-cyan-300 transition-colors">
                  {hypo.title}
                </h3>
                <p className="text-xs text-slate-300 line-clamp-3 mb-4 leading-relaxed bg-dark-900/30 p-3 rounded-xl border border-white/5">
                  "{hypo.hypothesis}"
                </p>

                {/* Trigger Reason & Tactic */}
                <div className="space-y-2 mb-4">
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span className="text-slate-500 font-semibold">Tactic:</span>
                    <span className="text-purple-300 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                      {hypo.mitre_tactic}
                    </span>
                    <span className="text-slate-500 font-semibold ml-2">Sector:</span>
                    <span className="text-slate-300">{hypo.target_sector}</span>
                  </div>

                  {hypo.trigger_reason && (
                    <div className="text-[11px] text-amber-300/90 bg-amber-500/10 border border-amber-500/20 p-2 rounded-lg flex items-start gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />
                      <span>{hypo.trigger_reason}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Footer Actions */}
              <div className="pt-3 border-t border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-2 text-[11px] text-slate-400">
                  <span>Confidence:</span>
                  <div className="w-16 bg-dark-900 rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-cyan-400 h-full rounded-full"
                      style={{ width: `${(hypo.confidence_score || 0.8) * 100}%` }}
                    />
                  </div>
                  <span className="text-white font-bold">{Math.round((hypo.confidence_score || 0.8) * 100)}%</span>
                </div>

                <div className="flex items-center gap-2">
                  <select
                    value={hypo.status}
                    onChange={(e) => handleUpdateStatus(hypo.id, e.target.value)}
                    className="bg-dark-900 border border-white/10 rounded-lg px-2 py-1 text-[11px] text-slate-300 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="open">Open</option>
                    <option value="in_progress">In Progress</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="false_positive">False Positive</option>
                    <option value="archived">Archive</option>
                  </select>

                  <button
                    onClick={() => {
                      setSelectedHypo(hypo);
                      setAnalystNotes(hypo.analyst_notes || '');
                    }}
                    className="flex items-center gap-1 px-3 py-1.5 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 rounded-xl text-xs font-semibold transition-all"
                  >
                    Investigate & Queries <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Slide-over Detail Drawer */}
      <AnimatePresence>
        {selectedHypo && (
          <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm">
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 250 }}
              className="w-full max-w-3xl bg-dark-900 border-l border-white/10 h-full flex flex-col shadow-2xl overflow-hidden"
            >
              {/* Drawer Header */}
              <div className="p-6 border-b border-white/10 flex items-start justify-between bg-dark-800/80">
                <div className="space-y-1 pr-4">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getSeverityBadge(selectedHypo.severity)}`}>
                      {selectedHypo.severity}
                    </span>
                    <span className="text-xs px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 font-bold">
                      {selectedHypo.mitre_technique_id} • {selectedHypo.mitre_tactic}
                    </span>
                  </div>
                  <h2 className="text-xl font-bold text-white">{selectedHypo.title}</h2>
                </div>

                <button
                  onClick={() => setSelectedHypo(null)}
                  className="p-2 text-slate-400 hover:text-white bg-dark-700/50 rounded-xl"
                >
                  <XCircle className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Body Scrollable */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-hide">
                {/* Hypothesis Box */}
                <div className="bg-dark-800/50 p-4 rounded-2xl border border-white/5">
                  <div className="text-xs text-cyan-400 font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <BookOpen className="w-4 h-4" /> Hypothesis Statement
                  </div>
                  <p className="text-sm text-slate-200 leading-relaxed font-mono bg-dark-900/60 p-3 rounded-xl border border-white/5">
                    {selectedHypo.hypothesis}
                  </p>
                </div>

                {/* Code Query Tabs (KQL, SPL, SIGMA, STEPS) */}
                <div className="space-y-3">
                  <div className="flex border-b border-white/10 space-x-4">
                    {[
                      { id: 'kql', label: 'KQL Query (Sentinel)', icon: Terminal },
                      { id: 'spl', label: 'SPL Query (Splunk)', icon: FileCode },
                      { id: 'sigma', label: 'Sigma Rule (YAML)', icon: ShieldAlert },
                      { id: 'steps', label: 'Hunt Playbook Steps', icon: UserCheck }
                    ].map(tab => (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 py-2.5 px-3 text-xs font-bold border-b-2 transition-all ${
                          activeTab === tab.id
                            ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10'
                            : 'border-transparent text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        <tab.icon className="w-3.5 h-3.5" />
                        {tab.label}
                      </button>
                    ))}
                  </div>

                  {/* Code Display Area */}
                  <div className="relative bg-dark-950 p-4 rounded-2xl border border-white/10 font-mono text-xs text-emerald-400 leading-relaxed overflow-x-auto">
                    {activeTab === 'kql' && (
                      <>
                        <div className="flex justify-between items-center mb-2 pb-2 border-b border-white/5 text-slate-400 font-sans text-xs">
                          <span>Microsoft Sentinel / Defender KQL</span>
                          <button
                            onClick={() => copyToClipboard(selectedHypo.kql_query, 'kql')}
                            className="flex items-center gap-1 px-2.5 py-1 bg-dark-800 hover:bg-dark-700 text-cyan-300 rounded border border-white/10"
                          >
                            <Copy className="w-3 h-3" />
                            {copiedKey === 'kql' ? 'Copied!' : 'Copy KQL'}
                          </button>
                        </div>
                        <pre className="whitespace-pre-wrap">{selectedHypo.kql_query || '// No KQL query specified'}</pre>
                      </>
                    )}

                    {activeTab === 'spl' && (
                      <>
                        <div className="flex justify-between items-center mb-2 pb-2 border-b border-white/5 text-slate-400 font-sans text-xs">
                          <span>Splunk Search Processing Language (SPL)</span>
                          <button
                            onClick={() => copyToClipboard(selectedHypo.spl_query, 'spl')}
                            className="flex items-center gap-1 px-2.5 py-1 bg-dark-800 hover:bg-dark-700 text-cyan-300 rounded border border-white/10"
                          >
                            <Copy className="w-3 h-3" />
                            {copiedKey === 'spl' ? 'Copied!' : 'Copy SPL'}
                          </button>
                        </div>
                        <pre className="whitespace-pre-wrap text-amber-300">{selectedHypo.spl_query || '// No SPL query specified'}</pre>
                      </>
                    )}

                    {activeTab === 'sigma' && (
                      <>
                        <div className="flex justify-between items-center mb-2 pb-2 border-b border-white/5 text-slate-400 font-sans text-xs">
                          <span>Generic Sigma Detection Rule</span>
                          <div className="flex gap-2">
                            <button
                              onClick={() => copyToClipboard(selectedHypo.sigma_rule, 'sigma')}
                              className="flex items-center gap-1 px-2.5 py-1 bg-dark-800 hover:bg-dark-700 text-cyan-300 rounded border border-white/10"
                            >
                              <Copy className="w-3 h-3" />
                              {copiedKey === 'sigma' ? 'Copied!' : 'Copy'}
                            </button>
                            <button
                              onClick={() => downloadSigma(selectedHypo)}
                              className="flex items-center gap-1 px-2.5 py-1 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 rounded border border-cyan-500/30"
                            >
                              <Download className="w-3 h-3" /> Export .yml
                            </button>
                          </div>
                        </div>
                        <pre className="whitespace-pre-wrap text-blue-300">{selectedHypo.sigma_rule || '# No Sigma rule specified'}</pre>
                      </>
                    )}

                    {activeTab === 'steps' && (
                      <div className="font-sans text-slate-200 space-y-3">
                        <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">SOC Analyst Investigation Checklist</div>
                        {selectedHypo.investigation_steps && selectedHypo.investigation_steps.length > 0 ? (
                          selectedHypo.investigation_steps.map((step, idx) => (
                            <div key={idx} className="flex items-start gap-3 bg-dark-900 p-3 rounded-xl border border-white/5">
                              <div className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs font-bold flex-shrink-0">
                                {idx + 1}
                              </div>
                              <span className="text-xs text-slate-300">{step}</span>
                            </div>
                          ))
                        ) : (
                          <div className="text-xs text-slate-500">No specific steps recorded.</div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* Trigger Indicators */}
                {selectedHypo.trigger_iocs && selectedHypo.trigger_iocs.length > 0 && (
                  <div className="bg-dark-800/40 p-4 rounded-2xl border border-white/5">
                    <div className="text-xs text-slate-400 font-bold uppercase tracking-wider mb-2">Associated IOC / CVE Triggers</div>
                    <div className="flex flex-wrap gap-2">
                      {selectedHypo.trigger_iocs.map((ioc, i) => (
                        <span key={i} className="px-2.5 py-1 bg-dark-950 text-cyan-400 border border-cyan-500/20 rounded-lg text-xs font-mono">
                          {ioc}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Analyst Notes */}
                <div className="bg-dark-800/40 p-4 rounded-2xl border border-white/5 space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-xs text-slate-400 font-bold uppercase tracking-wider">SOC Analyst Hunting Notes</span>
                    <button
                      onClick={handleSaveNotes}
                      disabled={updatingNotes}
                      className="px-3 py-1 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 rounded-lg text-xs font-semibold border border-cyan-500/30"
                    >
                      {updatingNotes ? 'Saving...' : 'Save Notes'}
                    </button>
                  </div>
                  <textarea
                    rows={3}
                    placeholder="Enter notes, false-positive justification, or incident ticket references..."
                    value={analystNotes}
                    onChange={(e) => setAnalystNotes(e.target.value)}
                    className="w-full bg-dark-950 border border-white/10 rounded-xl p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Generation Sector Selection Modal */}
      {showGenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-dark-900 border border-white/10 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex justify-between items-center border-b border-white/10 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-cyan-400" /> AI Threat Hunting Generator
              </h3>
              <button onClick={() => setShowGenModal(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Target Sector Environment</label>
                <select
                  value={targetSectorGen}
                  onChange={(e) => setTargetSectorGen(e.target.value)}
                  className="w-full bg-dark-950 border border-white/10 rounded-xl p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
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
                <label className="block text-slate-400 font-semibold mb-1">Hypothesis Count</label>
                <select
                  value={genCount}
                  onChange={(e) => setGenCount(e.target.value)}
                  className="w-full bg-dark-950 border border-white/10 rounded-xl p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="3">3 Hypotheses (Quick)</option>
                  <option value="5">5 Hypotheses (Recommended)</option>
                  <option value="8">8 Hypotheses (Deep Hunt)</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-white/10">
              <button
                onClick={() => setShowGenModal(false)}
                className="px-4 py-2 bg-dark-800 hover:bg-dark-700 text-slate-300 rounded-xl text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                className="px-5 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-white rounded-xl text-xs font-bold shadow-lg shadow-cyan-500/20"
              >
                Start AI Hunt Engine
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
