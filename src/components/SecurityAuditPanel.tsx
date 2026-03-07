/**
 * SecurityAuditPanel.tsx
 *
 * A live "RAM operations" log panel that makes invisible cryptographic
 * steps visible — useful for demos / faculty presentations.
 *
 * Usage:
 *   1. Wrap your app in <AuditProvider>
 *   2. Call useAudit().log(...) from anywhere
 *   3. <SecurityAuditPanel /> renders the floating panel
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
} from 'react';
import {
  ChevronDown,
  ChevronUp,
  Shield,
  Trash2,
  X,
  FlaskConical,
} from 'lucide-react';

// ─── Types ───────────────────────────────────────────────────────────────────

export type LogLevel = 'info' | 'crypto' | 'ram' | 'network' | 'success' | 'warning' | 'error';

export interface AuditEntry {
  id: number;
  ts: string;          // HH:MM:SS.mmm
  level: LogLevel;
  message: string;
  detail?: string;     // optional truncated value (key bytes, fingerprint, etc.)
}

interface AuditContextValue {
  log: (level: LogLevel, message: string, detail?: string) => void;
  clear: () => void;
  entries: AuditEntry[];
}

// ─── Context ──────────────────────────────────────────────────────────────────

const AuditContext = createContext<AuditContextValue>({
  log: () => {},
  clear: () => {},
  entries: [],
});

export function useAudit() {
  return useContext(AuditContext);
}

// ─── Provider ─────────────────────────────────────────────────────────────────

let _idCounter = 0;

function nowTs(): string {
  const d = new Date();
  return (
    String(d.getHours()).padStart(2, '0') + ':' +
    String(d.getMinutes()).padStart(2, '0') + ':' +
    String(d.getSeconds()).padStart(2, '0') + '.' +
    String(d.getMilliseconds()).padStart(3, '0')
  );
}

export const AuditProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  const log = useCallback((level: LogLevel, message: string, detail?: string) => {
    const entry: AuditEntry = { id: ++_idCounter, ts: nowTs(), level, message, detail };
    setEntries(prev => [...prev, entry]);
  }, []);

  const clear = useCallback(() => setEntries([]), []);

  return (
    <AuditContext.Provider value={{ log, clear, entries }}>
      {children}
    </AuditContext.Provider>
  );
};

// ─── Level Config ─────────────────────────────────────────────────────────────

const LEVEL_CONFIG: Record<LogLevel, { icon: string; color: string; bg: string }> = {
  info:    { icon: 'ℹ️',  color: 'text-slate-400',   bg: '' },
  crypto:  { icon: '🔐', color: 'text-purple-400',  bg: '' },
  ram:     { icon: '🧠', color: 'text-blue-400',    bg: '' },
  network: { icon: '🌐', color: 'text-cyan-400',    bg: '' },
  success: { icon: '✅', color: 'text-emerald-400', bg: '' },
  warning: { icon: '⚠️',  color: 'text-amber-400',  bg: '' },
  error:   { icon: '❌', color: 'text-rose-400',    bg: '' },
};

// ─── Panel Component ──────────────────────────────────────────────────────────

export const SecurityAuditPanel: React.FC = () => {
  const { entries, clear } = useAudit();
  const [open, setOpen]       = useState(true);
  const [pinned, setPinned]   = useState(true);
  const bottomRef             = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom on new entries
  React.useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [entries, open]);

  if (!pinned) {
    return (
      <button
        onClick={() => setPinned(true)}
        className="fixed bottom-4 right-4 z-50 flex items-center gap-2 px-4 py-2 bg-slate-900 text-white text-xs font-bold rounded-full shadow-2xl border border-slate-700 hover:bg-slate-800 transition-colors"
      >
        <FlaskConical size={14} className="text-purple-400" />
        Security Audit
        {entries.length > 0 && (
          <span className="bg-purple-600 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">
            {entries.length}
          </span>
        )}
      </button>
    );
  }

  return (
    <div className="fixed bottom-0 right-0 z-50 w-full md:w-[480px] flex flex-col shadow-2xl border border-slate-700 rounded-t-2xl overflow-hidden">

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900 cursor-pointer select-none"
           onClick={() => setOpen(o => !o)}>
        <div className="flex items-center gap-2">
          <FlaskConical size={16} className="text-purple-400" />
          <span className="text-white text-xs font-bold uppercase tracking-widest">
            Security Audit — RAM Operations Log
          </span>
          {entries.length > 0 && (
            <span className="bg-purple-600 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">
              {entries.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={e => { e.stopPropagation(); clear(); }}
            className="text-slate-500 hover:text-slate-300 transition-colors"
            title="Clear log"
          >
            <Trash2 size={13} />
          </button>
          <button
            onClick={e => { e.stopPropagation(); setPinned(false); }}
            className="text-slate-500 hover:text-slate-300 transition-colors"
            title="Minimise"
          >
            <X size={13} />
          </button>
          {open ? <ChevronDown size={14} className="text-slate-400" /> : <ChevronUp size={14} className="text-slate-400" />}
        </div>
      </div>

      {/* Legend row */}
      {open && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 px-4 py-2 bg-slate-950 border-b border-slate-800 text-[10px]">
          {(Object.entries(LEVEL_CONFIG) as [LogLevel, typeof LEVEL_CONFIG[LogLevel]][]).map(([k, v]) => (
            <span key={k} className={`${v.color} font-mono`}>{v.icon} {k}</span>
          ))}
        </div>
      )}

      {/* Log entries */}
      {open && (
        <div className="bg-slate-950 h-64 overflow-y-auto font-mono text-[11px] p-3 space-y-1">
          {entries.length === 0 && (
            <p className="text-slate-600 italic text-center mt-8">
              No events yet — start registration or login to see live RAM operations.
            </p>
          )}
          {entries.map(entry => {
            const cfg = LEVEL_CONFIG[entry.level];
            return (
              <div key={entry.id} className="flex gap-2 leading-relaxed">
                <span className="text-slate-600 shrink-0">{entry.ts}</span>
                <span className="shrink-0">{cfg.icon}</span>
                <span className={`${cfg.color} flex-1`}>
                  {entry.message}
                  {entry.detail && (
                    <span className="ml-2 text-slate-500 break-all">
                      [{entry.detail}]
                    </span>
                  )}
                </span>
              </div>
            );
          })}
          <div ref={bottomRef} />
        </div>
      )}

      {/* Footer */}
      {open && (
        <div className="px-4 py-2 bg-slate-900 border-t border-slate-800 flex items-center gap-2">
          <Shield size={11} className="text-emerald-500" />
          <p className="text-[10px] text-slate-500">
            All cryptographic operations occur exclusively in browser RAM. Nothing sensitive is written to disk.
          </p>
        </div>
      )}
    </div>
  );
};