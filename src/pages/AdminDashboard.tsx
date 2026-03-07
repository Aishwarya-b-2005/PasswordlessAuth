import React, { useEffect, useState, useCallback } from 'react';
import {
  ShieldCheck, ShieldAlert, Hash, RefreshCw,
  Zap, RotateCcw, LogOut, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle2, Loader2, Database
} from 'lucide-react';
import { Api } from '../services/api';

interface AdminDashboardProps {
  token: string;
  onLogout: () => void;
}

interface ChainEntry {
  id: number;
  user: string;
  result: string;
  timestamp: number;
  riskScore: number;
  action: string;
  stored_prev: string;
  stored_current: string;
  expected_prev: string;
  expected_current: string;
  ok: boolean;
  tampered: boolean;
  prev_mismatch: boolean;
  hash_mismatch: boolean;
}

type PanelState = 'idle' | 'loading' | 'done';

const AdminDashboard: React.FC<AdminDashboardProps> = ({ token, onLogout }) => {

  // ── State ──────────────────────────────────────────────────────────────────
  const [logs, setLogs]                   = useState<ChainEntry[]>([]);
  const [logsState, setLogsState]         = useState<PanelState>('idle');

  const [chainResults, setChainResults]   = useState<ChainEntry[]>([]);
  const [chainOverall, setChainOverall]   = useState<boolean | null>(null);
  const [chainState, setChainState]       = useState<PanelState>('idle');

  const [tamperState, setTamperState]     = useState<'idle' | 'loading' | 'done'>('idle');
  const [tamperedId, setTamperedId]       = useState<number | null>(null);

  const [restoreState, setRestoreState]   = useState<'idle' | 'loading' | 'done'>('idle');

  const [expandedRow, setExpandedRow]     = useState<number | null>(null);
  const [activeTab, setActiveTab]         = useState<'logs' | 'verify'>('logs');

  // ── Load logs ──────────────────────────────────────────────────────────────
  const fetchLogs = useCallback(async () => {
    setLogsState('loading');
    try {
      const data = await Api.adminGetLogs(token);
      setLogs(data);
    } finally {
      setLogsState('done');
    }
  }, [token]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  // ── Verify chain ───────────────────────────────────────────────────────────
  const handleVerify = async () => {
    setChainState('loading');
    setChainResults([]);
    setChainOverall(null);
    const data = await Api.adminVerifyChain(token);
    setChainResults(data.entries);
    setChainOverall(data.overall);
    setChainState('done');
    setActiveTab('verify');
  };

  // ── Tamper ─────────────────────────────────────────────────────────────────
  const handleTamper = async () => {
    setTamperState('loading');
    const data = await Api.adminTamperLog(token);
    setTamperedId(data.tampered_id);
    setTamperState('done');
    fetchLogs();   // refresh log table
  };

  // ── Restore ────────────────────────────────────────────────────────────────
  const handleRestore = async () => {
    setRestoreState('loading');
    await Api.adminRestoreLogs(token);
    setRestoreState('done');
    setTamperState('idle');
    setTamperedId(null);
    setChainResults([]);
    setChainOverall(null);
    setChainState('idle');
    fetchLogs();
  };

  // ── Helpers ────────────────────────────────────────────────────────────────
  const fmt = (ts: number) => new Date(ts * 1000).toLocaleString();
  const trunc = (h: string) => h ? h.slice(0, 10) + '…' : '—';
  const riskColor = (r: number) =>
    r > 0.7 ? 'text-rose-600' : r > 0.3 ? 'text-amber-600' : 'text-emerald-600';

  const tampered = tamperState === 'done';

  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div className="min-h-screen bg-slate-50">

      {/* Top bar */}
      <nav className="bg-slate-900 text-white px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-500 rounded-lg">
            <Database size={20} />
          </div>
          <div>
            <p className="font-bold text-sm">SecureBank — Admin Console</p>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest">
              Hash-Chain Audit Inspector
            </p>
          </div>
        </div>
        <button
          onClick={onLogout}
          className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm transition-colors"
        >
          <LogOut size={14} /> Logout
        </button>
      </nav>

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">

        {/* ── Action bar ────────────────────────────────────────────────── */}
        <div className="flex flex-wrap gap-3">

          <button
            onClick={fetchLogs}
            className="flex items-center gap-2 px-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm font-semibold hover:bg-slate-50 transition-colors shadow-sm"
          >
            <RefreshCw size={15} className={logsState === 'loading' ? 'animate-spin' : ''} />
            Refresh Logs
          </button>

          <button
            onClick={handleVerify}
            disabled={chainState === 'loading'}
            className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-sm font-semibold transition-colors shadow-sm disabled:opacity-60"
          >
            {chainState === 'loading'
              ? <Loader2 size={15} className="animate-spin" />
              : <ShieldCheck size={15} />}
            Verify Chain
          </button>

          <button
            onClick={handleTamper}
            disabled={tampered || tamperState === 'loading'}
            className="flex items-center gap-2 px-4 py-2.5 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-sm font-semibold transition-colors shadow-sm disabled:opacity-50"
          >
            {tamperState === 'loading'
              ? <Loader2 size={15} className="animate-spin" />
              : <Zap size={15} />}
            {tampered ? `Tampered Row #${tamperedId}` : 'Simulate Tamper'}
          </button>

          {tampered && (
            <button
              onClick={handleRestore}
              disabled={restoreState === 'loading'}
              className="flex items-center gap-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-sm font-semibold transition-colors shadow-sm disabled:opacity-50"
            >
              {restoreState === 'loading'
                ? <Loader2 size={15} className="animate-spin" />
                : <RotateCcw size={15} />}
              Restore Chain
            </button>
          )}
        </div>

        {/* ── Tamper notice ─────────────────────────────────────────────── */}
        {tampered && (
          <div className="flex items-start gap-3 p-4 bg-rose-50 border border-rose-200 rounded-xl text-rose-800">
            <AlertTriangle size={18} className="shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-bold">Database Tampered — Row #{tamperedId} corrupted</p>
              <p className="text-rose-600 mt-0.5">
                Click <strong>Verify Chain</strong> to see the broken entries highlighted below.
                Then click <strong>Restore Chain</strong> to reset.
              </p>
            </div>
          </div>
        )}

        {/* ── Tabs ──────────────────────────────────────────────────────── */}
        <div className="flex gap-1 bg-slate-200 p-1 rounded-xl w-fit">
          {(['logs', 'verify'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2 rounded-lg text-sm font-semibold transition-colors ${
                activeTab === tab
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              {tab === 'logs' ? '📋 Audit Logs' : '🔍 Chain Verification'}
              {tab === 'verify' && chainState === 'done' && (
                <span className={`ml-2 text-[10px] font-bold px-1.5 py-0.5 rounded-full ${
                  chainOverall ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'
                }`}>
                  {chainOverall ? '✓ OK' : '✗ FAIL'}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* ════════════════════════════════════════════════════════════════
            TAB: AUDIT LOGS
        ════════════════════════════════════════════════════════════════ */}
        {activeTab === 'logs' && (
          <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
              <h2 className="font-bold text-slate-800">
                All Audit Logs
                <span className="ml-2 text-slate-400 text-sm font-normal">({logs.length} entries)</span>
              </h2>
              <ShieldCheck size={18} className="text-slate-400" />
            </div>

            {logsState === 'loading' ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="animate-spin text-blue-500" size={32} />
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="text-[10px] font-bold text-slate-400 uppercase tracking-widest border-b border-slate-100 bg-slate-50">
                      <th className="px-4 py-3">ID</th>
                      <th className="px-4 py-3">User</th>
                      <th className="px-4 py-3">Action</th>
                      <th className="px-4 py-3">Result</th>
                      <th className="px-4 py-3">Risk</th>
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3">Chain Hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-50">
                    {logs.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="text-center py-12 text-slate-400 italic">
                          No log entries yet.
                        </td>
                      </tr>
                    ) : (
                      logs.slice().reverse().map(log => (
                        <tr key={log.id} className="hover:bg-slate-50/60 transition-colors">
                          <td className="px-4 py-3 font-mono text-xs text-slate-400">#{log.id}</td>
                          <td className="px-4 py-3 font-medium text-slate-700">{log.user}</td>
                          <td className="px-4 py-3">
                            <span className="font-mono text-xs bg-slate-100 text-slate-700 px-2 py-0.5 rounded">
                              {log.action}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`text-xs font-bold ${
                              log.result.includes('SUCCESS') || log.result.includes('ALLOW')
                                ? 'text-emerald-600'
                                : log.result.includes('TAMPERED')
                                  ? 'text-rose-700 bg-rose-50 px-2 py-0.5 rounded'
                                  : 'text-rose-600'
                            }`}>
                              {log.result}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`text-xs font-mono font-bold ${riskColor(log.riskScore)}`}>
                              {log.riskScore.toFixed(2)}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-[10px] font-mono text-slate-500">
                            {fmt(log.timestamp)}
                          </td>
                          <td className="px-4 py-3">
                            <span className="font-mono text-[10px] text-blue-500 bg-blue-50 px-2 py-1 rounded flex items-center gap-1 w-fit">
                              <Hash size={9} />
                              {trunc(log.stored_current)}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ════════════════════════════════════════════════════════════════
            TAB: CHAIN VERIFICATION
        ════════════════════════════════════════════════════════════════ */}
        {activeTab === 'verify' && (
          <div className="space-y-4">

            {/* Overall banner */}
            {chainState === 'idle' && (
              <div className="text-center py-16 text-slate-400">
                <ShieldCheck size={48} className="mx-auto mb-4 opacity-30" />
                <p className="font-medium">Click <strong>Verify Chain</strong> to run the integrity check.</p>
              </div>
            )}

            {chainState === 'loading' && (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="animate-spin text-blue-500 mr-3" size={28} />
                <p className="text-slate-500 font-medium">Recomputing hashes…</p>
              </div>
            )}

            {chainState === 'done' && (
              <>
                {/* Summary card */}
                <div className={`flex items-center gap-4 p-5 rounded-2xl border-2 ${
                  chainOverall
                    ? 'bg-emerald-50 border-emerald-200'
                    : 'bg-rose-50 border-rose-200'
                }`}>
                  {chainOverall
                    ? <CheckCircle2 size={36} className="text-emerald-500 shrink-0" />
                    : <ShieldAlert size={36} className="text-rose-500 shrink-0 animate-pulse" />
                  }
                  <div>
                    <p className={`text-lg font-bold ${chainOverall ? 'text-emerald-800' : 'text-rose-800'}`}>
                      {chainOverall
                        ? 'Chain Intact — No Tampering Detected'
                        : 'Chain Broken — Tampering Detected!'}
                    </p>
                    <p className={`text-sm mt-0.5 ${chainOverall ? 'text-emerald-600' : 'text-rose-600'}`}>
                      {chainOverall
                        ? `All ${chainResults.length} entries verified successfully.`
                        : `${chainResults.filter(e => e.tampered).length} of ${chainResults.length} entries have invalid hashes.`}
                    </p>
                  </div>
                </div>

                {/* Per-entry table */}
                <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
                  <div className="px-6 py-4 border-b border-slate-100">
                    <h3 className="font-bold text-slate-800">Per-Entry Hash Verification</h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Click any row to expand and see the full hash comparison.
                    </p>
                  </div>

                  <div className="divide-y divide-slate-50">
                    {chainResults.map((entry) => (
                      <div key={entry.id}>
                        {/* Row summary */}
                        <button
                          onClick={() => setExpandedRow(expandedRow === entry.id ? null : entry.id)}
                          className={`w-full flex items-center gap-4 px-6 py-3 text-left transition-colors ${
                            entry.tampered
                              ? 'bg-rose-50 hover:bg-rose-100'
                              : 'hover:bg-slate-50'
                          }`}
                        >
                          {/* Status icon */}
                          <div className="shrink-0 w-6">
                            {entry.tampered
                              ? <AlertTriangle size={16} className="text-rose-500" />
                              : <CheckCircle2 size={16} className="text-emerald-500" />}
                          </div>

                          {/* ID */}
                          <span className="font-mono text-xs text-slate-400 w-8">#{entry.id}</span>

                          {/* User + action */}
                          <span className="text-sm font-medium text-slate-700 w-24 truncate">{entry.user}</span>
                          <span className="font-mono text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded w-20 text-center">
                            {entry.action}
                          </span>

                          {/* Result */}
                          <span className={`text-xs font-bold flex-1 ${
                            entry.result.includes('SUCCESS') || entry.result.includes('ALLOW')
                              ? 'text-emerald-600' : 'text-rose-600'
                          }`}>
                            {entry.result}
                          </span>

                          {/* Hash preview */}
                          <span className={`font-mono text-[10px] px-2 py-1 rounded ${
                            entry.tampered
                              ? 'bg-rose-100 text-rose-600'
                              : 'bg-blue-50 text-blue-500'
                          }`}>
                            <Hash size={8} className="inline mr-1" />
                            {trunc(entry.stored_current)}
                          </span>

                          {/* Expand chevron */}
                          <span className="text-slate-300 shrink-0">
                            {expandedRow === entry.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                          </span>
                        </button>

                        {/* Expanded hash detail */}
                        {expandedRow === entry.id && (
                          <div className="px-6 pb-4 bg-slate-950 text-[11px] font-mono space-y-3">
                            <div className="pt-3 grid grid-cols-1 gap-2">

                              {/* prev_hash comparison */}
                              <div className={`p-3 rounded-lg border ${
                                entry.prev_mismatch ? 'border-rose-500 bg-rose-950' : 'border-slate-700 bg-slate-900'
                              }`}>
                                <p className="text-slate-400 mb-1">prev_hash (pointer to previous entry)</p>
                                <p className="text-slate-300">
                                  Stored:&nbsp;
                                  <span className={entry.prev_mismatch ? 'text-rose-400' : 'text-emerald-400'}>
                                    {entry.stored_prev}
                                  </span>
                                </p>
                                <p className="text-slate-300">
                                  Expected:&nbsp;
                                  <span className="text-blue-400">{entry.expected_prev}</span>
                                </p>
                                {entry.prev_mismatch && (
                                  <p className="text-rose-400 mt-1 font-bold">
                                    ⚠ prev_hash mismatch — a previous entry was modified
                                  </p>
                                )}
                              </div>

                              {/* current_hash comparison */}
                              <div className={`p-3 rounded-lg border ${
                                entry.hash_mismatch ? 'border-rose-500 bg-rose-950' : 'border-slate-700 bg-slate-900'
                              }`}>
                                <p className="text-slate-400 mb-1">current_hash (SHA-256 of this entry's data)</p>
                                <p className="text-slate-300">
                                  Stored:&nbsp;
                                  <span className={entry.hash_mismatch ? 'text-rose-400' : 'text-emerald-400'}>
                                    {entry.stored_current}
                                  </span>
                                </p>
                                <p className="text-slate-300">
                                  Expected:&nbsp;
                                  <span className="text-blue-400">{entry.expected_current}</span>
                                </p>
                                {entry.hash_mismatch && (
                                  <p className="text-rose-400 mt-1 font-bold">
                                    ⚠ hash mismatch — this entry's data was directly modified
                                  </p>
                                )}
                              </div>

                              {/* Chain-broken flag */}
                              {entry.tampered && !entry.prev_mismatch && !entry.hash_mismatch && (
                                <div className="p-3 rounded-lg border border-amber-600 bg-amber-950">
                                  <p className="text-amber-400 font-bold">
                                    ⚠ Chain broken by a previous entry — this entry itself is unmodified
                                    but cannot be verified because it depends on a corrupted predecessor.
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminDashboard;