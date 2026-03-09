import React, { useState, useEffect, useRef } from 'react';
import {
  ArrowRightLeft, FileText, UserCircle, Trash2,
  History, ShieldCheck, Lock, AlertTriangle,
  RefreshCw, X, ChevronRight, Hash, Cpu,
  Send, Edit3, AlertOctagon, CheckCircle2,
  ArrowLeft, Loader2, CreditCard, User, Mail,
  Phone, MapPin, Calendar, TrendingUp, Shield
} from 'lucide-react';
import { OperationType, RiskLevel } from '../types';
import { Api } from '../services/api';
import { collectRiskContext, recordOperation } from '../utils/riskEngine';
import { decryptAndSign } from '../utils/deviceKey';
import { useAudit } from '../components/SecurityAuditPanel';

interface DashboardProps {
  user: string;
  onNavigate: (page: string, params?: any) => void;
  onStepUp?: (operationId: string) => void;
  pendingOperation?: string | null;
  onStepUpComplete?: () => void;
}

const riskStyles: Record<RiskLevel, string> = {
  [RiskLevel.LOW]:    'bg-emerald-50 border-emerald-200 text-emerald-600',
  [RiskLevel.MEDIUM]: 'bg-amber-50 border-amber-200 text-amber-600',
  [RiskLevel.HIGH]:   'bg-rose-50 border-rose-200 text-rose-600',
};

const OPERATIONS = [
  { id: OperationType.READ,     title: 'Sensitive Records', desc: 'View confidential profile and activity data.', icon: <FileText className="text-blue-600" />,      risk: RiskLevel.LOW    },
  { id: OperationType.WRITE,    title: 'Account Details',   desc: 'Update personal settings and contact info.',  icon: <UserCircle className="text-amber-600" />,    risk: RiskLevel.MEDIUM },
  { id: OperationType.TRANSFER, title: 'Transfer Money',    desc: 'Send funds to other accounts securely.',      icon: <ArrowRightLeft className="text-blue-600" />, risk: RiskLevel.MEDIUM },
  { id: OperationType.DELETE,   title: 'Close Account',     desc: 'Permanently delete account and all data.',    icon: <Trash2 className="text-rose-600" />,         risk: RiskLevel.HIGH   },
];

type OpStatus =
  | 'idle'
  | 'collecting' | 'challenging' | 'signing' | 'executing'
  | 'allowed'
  | 'step_up' | 'stepup_signing'
  | 'denied' | 'error';

interface NonceDetails { nonce: string; contextHash: string; expiresAt: number; riskLevel: string; riskScore: number; }
interface ContextDetails { deviceFingerprint: string; sessionAgeMs: number; timezone: string; connectionType: string; mouseMovementDetected: boolean; keyboardInteractionDetected: boolean; timeOnPageMs: number; }
interface OpState { status: OpStatus; operationId: OperationType | null; riskScore: number; riskReasons: string[]; message: string; nonceDetails: NonceDetails | null; contextDetails: ContextDetails | null; }

// TOTP code input state — lives outside OpState so it persists while modal is open
// Declared at module scope so it's accessible in both handler and JSX
const INITIAL: OpState = { status: 'idle', operationId: null, riskScore: 0, riskReasons: [], message: '', nonceDetails: null, contextDetails: null };

const STEPS = [
  { id: 'collecting',  label: '📡 Collecting Context Signals'   },
  { id: 'challenging', label: '🔗 Binding Context to Nonce'      },
  { id: 'signing',     label: '✍️  Signing Nonce with Device Key' },
  { id: 'executing',   label: '🔍 Server Risk Evaluation'        },
];

const truncate = (s: string, n = 18) => s.length > n ? s.slice(0, n) + '…' : s;
const msToSec  = (ms: number) => (ms / 1000).toFixed(1) + 's';

// ─── Post-Auth Operation Views ─────────────────────────────────────────────────

const ReadView: React.FC<{ user: string; onBack: () => void }> = ({ user, onBack }) => (
  <div className="space-y-6">
    <button onClick={onBack} className="flex items-center gap-2 text-slate-500 hover:text-slate-800 text-sm font-medium">
      <ArrowLeft size={16} /> Back to Dashboard
    </button>
    <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
      <div className="bg-slate-900 p-6 text-white flex items-center gap-3">
        <div className="p-2 bg-blue-600/30 rounded-lg"><FileText size={20} className="text-blue-400" /></div>
        <div>
          <h2 className="font-bold text-lg">Sensitive Records</h2>
          <p className="text-slate-400 text-xs">Access granted · Context-verified session</p>
        </div>
        <span className="ml-auto text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-1 rounded-full font-bold">🔓 UNLOCKED</span>
      </div>
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { icon: <User size={16} />, label: 'Full Name', value: user + ' · Verified' },
            { icon: <CreditCard size={16} />, label: 'Account Number', value: 'SB-••••-••••-8821' },
            { icon: <TrendingUp size={16} />, label: 'Credit Score', value: '782 — Excellent' },
            { icon: <Shield size={16} />, label: 'KYC Status', value: 'Fully Verified · Tier 3' },
            { icon: <Calendar size={16} />, label: 'Account Since', value: 'March 2021' },
            { icon: <MapPin size={16} />, label: 'Region', value: 'India · IN' },
          ].map(item => (
            <div key={item.label} className="flex items-start gap-3 p-4 bg-slate-50 rounded-xl border border-slate-100">
              <div className="p-2 bg-white rounded-lg shadow-sm text-blue-600 shrink-0">{item.icon}</div>
              <div>
                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-0.5">{item.label}</p>
                <p className="text-sm font-semibold text-slate-800">{item.value}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="p-4 bg-slate-900 rounded-xl font-mono text-xs text-slate-300 space-y-1.5">
          <p className="text-slate-500 border-b border-slate-800 pb-2 mb-2 uppercase text-[9px] tracking-wider">Raw Record · SEC-88921-X</p>
          <p><span className="text-blue-400">INTERNAL_FLAG:</span> ACADEMIC_DEMO_USER</p>
          <p><span className="text-blue-400">RISK_PROFILE:</span> STANDARD</p>
          <p><span className="text-blue-400">SESSION_TOKEN:</span> ctx-nonce-verified-✓</p>
          <p><span className="text-blue-400">LAST_ACCESS:</span> {new Date().toISOString()}</p>
        </div>
        <div className="flex items-center gap-2 p-3 bg-emerald-50 border border-emerald-100 rounded-lg text-xs text-emerald-700">
          <CheckCircle2 size={14} className="shrink-0" />
          This record was accessed using a context-bound nonce. Access has been logged to the immutable audit chain.
        </div>
      </div>
    </div>
  </div>
);

const WriteView: React.FC<{ user: string; onBack: () => void }> = ({ user, onBack }) => {
  const [saved, setSaved] = useState(false);
  const [email, setEmail] = useState(user + '@securebank.demo');
  const [phone, setPhone] = useState('+91 98765 43210');
  const [address, setAddress] = useState('Chennai, Tamil Nadu, IN');
  return (
    <div className="space-y-6">
      <button onClick={onBack} className="flex items-center gap-2 text-slate-500 hover:text-slate-800 text-sm font-medium">
        <ArrowLeft size={16} /> Back to Dashboard
      </button>
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
        <div className="bg-amber-500 p-6 text-white flex items-center gap-3">
          <div className="p-2 bg-white/20 rounded-lg"><Edit3 size={20} /></div>
          <div>
            <h2 className="font-bold text-lg">Update Account Details</h2>
            <p className="text-white/70 text-xs">Authorized · Changes are audit-logged</p>
          </div>
          <span className="ml-auto text-[10px] bg-white/20 text-white border border-white/30 px-2 py-1 rounded-full font-bold">✍️ AUTHORIZED</span>
        </div>
        <div className="p-6 space-y-4">
          {saved && (
            <div className="flex items-center gap-2 p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-sm text-emerald-700 font-medium">
              <CheckCircle2 size={16} /> Changes saved and audit-logged successfully.
            </div>
          )}
          {[
            { icon: <Mail size={16} />, label: 'Email Address', value: email, setter: setEmail, type: 'email' },
            { icon: <Phone size={16} />, label: 'Phone Number', value: phone, setter: setPhone, type: 'tel' },
            { icon: <MapPin size={16} />, label: 'Address', value: address, setter: setAddress, type: 'text' },
          ].map(field => (
            <div key={field.label}>
              <label className="flex items-center gap-1.5 text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">
                <span className="text-slate-400">{field.icon}</span>{field.label}
              </label>
              <input type={field.type} value={field.value}
                onChange={e => { field.setter(e.target.value); setSaved(false); }}
                className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-amber-400" />
            </div>
          ))}
          <button onClick={() => setSaved(true)}
            className="w-full py-3 bg-amber-500 hover:bg-amber-600 text-white font-bold rounded-lg transition-colors flex items-center justify-center gap-2">
            <CheckCircle2 size={16} /> Save Changes
          </button>
          <p className="text-[10px] text-slate-400 text-center">All changes are signed with your device key and recorded in the tamper-evident audit log.</p>
        </div>
      </div>
    </div>
  );
};

interface TransferViewProps {
  user: string;
  onBack: () => void;
  runTransferAuth: (amount: number, recipient: string) => void;
  op: OpState;
  closeModal: () => void;
  totpCode: string;
  setTotpCode: (v: string) => void;
  handleTOTPStepUp: () => void;
  handleRetry: () => void;
  headerBg: string;
}

const TransferView: React.FC<TransferViewProps> = ({
  user, onBack, runTransferAuth, op, closeModal,
  totpCode, setTotpCode, handleTOTPStepUp, handleRetry, headerBg,
}) => {
  const [recipient, setRecipient] = useState('');
  const [amount,    setAmount]    = useState('');
  const [note,      setNote]      = useState('');
  const [phase, setPhase] = useState<'form' | 'confirm' | 'done'>('form');

  // When auth succeeds, move to done phase
  useEffect(() => {
    if (op.status === 'allowed' && op.operationId === OperationType.TRANSFER) {
      setTimeout(() => { closeModal(); setPhase('done'); }, 1200);
    }
  }, [op.status]);

  const amountNum = parseFloat(amount || '0');

  // Inline risk hint so user knows what to expect before confirming
  const getRiskHint = () => {
    if (amountNum > 10000) return { label: 'LIKELY DENY', color: 'text-rose-600 bg-rose-50 border-rose-200' };
    if (amountNum > 5000)  return { label: 'STEP_UP EXPECTED', color: 'text-amber-600 bg-amber-50 border-amber-200' };
    if (amountNum > 1000)  return { label: 'STEP_UP POSSIBLE', color: 'text-amber-500 bg-amber-50 border-amber-100' };
    if (amountNum > 0)     return { label: 'LIKELY ALLOW', color: 'text-emerald-600 bg-emerald-50 border-emerald-200' };
    return null;
  };
  const hint = getRiskHint();

  return (
    <div className="space-y-6">
      <button onClick={onBack} className="flex items-center gap-2 text-slate-500 hover:text-slate-800 text-sm font-medium">
        <ArrowLeft size={16} /> Back to Dashboard
      </button>

      {/* ── Security modal — fires after Confirm & Send ── */}
      {op.status !== 'idle' && op.operationId === OperationType.TRANSFER && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg my-4 overflow-hidden">

            <div className={`p-5 text-white ${headerBg}`}>
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-bold text-lg">Security Check</h3>
                  <p className="text-white/70 text-xs mt-0.5 uppercase tracking-wider">
                    TRANSFER · ${amountNum.toFixed(2)} → {recipient} · Context-Aware Nonce + Risk Engine
                  </p>
                </div>
                {['denied','error','step_up','allowed'].includes(op.status) && (
                  <button onClick={closeModal} className="p-1 hover:opacity-70"><X size={20} /></button>
                )}
              </div>
            </div>

            <div className="p-5 space-y-4 max-h-[80vh] overflow-y-auto">

              {/* Step progress */}
              <div className="space-y-1.5">
                {STEPS.map((s) => {
                  const order  = STEPS.map(x => x.id);
                  const curIdx = order.indexOf(op.status);
                  const sIdx   = order.indexOf(s.id);
                  const isDone   = ['allowed','denied','step_up','stepup_signing','error'].includes(op.status) || sIdx < curIdx;
                  const isActive = s.id === op.status;
                  return (
                    <div key={s.id} className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${isActive ? 'bg-blue-50 text-blue-800 font-semibold' : isDone ? 'text-slate-400' : 'text-slate-300'}`}>
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 ${isDone ? 'border-emerald-400 bg-emerald-400' : isActive ? 'border-blue-500 bg-blue-500 animate-pulse' : 'border-slate-200'}`}>
                        {isDone && <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7"/></svg>}
                      </div>
                      {s.label}
                    </div>
                  );
                })}
              </div>

              {/* Context signals */}
              {op.contextDetails && ['challenging','signing','executing','allowed','denied','step_up','stepup_signing'].includes(op.status) && (
                <div className="rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-800 px-4 py-2.5 flex items-center gap-2">
                    <Cpu size={14} className="text-blue-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Context Signals</span>
                  </div>
                  <div className="bg-slate-50 p-3 grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-[10px]">
                    <span className="text-slate-400">DEVICE_FP</span><span className="text-slate-700 font-bold truncate">{op.contextDetails.deviceFingerprint.slice(0,22)}…</span>
                    <span className="text-slate-400">AMOUNT</span><span className="text-blue-700 font-bold">${amountNum.toFixed(2)}</span>
                    <span className="text-slate-400">RECIPIENT</span><span className="text-slate-700 font-bold">{recipient}</span>
                    <span className="text-slate-400">SESSION_AGE</span><span className="text-slate-700 font-bold">{(op.contextDetails.sessionAgeMs/1000).toFixed(1)}s</span>
                    <span className="text-slate-400">MOUSE_MOVED</span>
                    <span className={`font-bold ${op.contextDetails.mouseMovementDetected ? 'text-emerald-600' : 'text-rose-500'}`}>{op.contextDetails.mouseMovementDetected ? '✓ YES' : '✗ NO'}</span>
                  </div>
                </div>
              )}

              {/* Nonce binding */}
              {op.nonceDetails && ['signing','executing','allowed','denied','step_up','stepup_signing'].includes(op.status) && (
                <div className="rounded-xl border border-blue-200 overflow-hidden">
                  <div className="bg-blue-700 px-4 py-2.5 flex items-center gap-2">
                    <Hash size={14} className="text-blue-200" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Context-Bound Nonce</span>
                  </div>
                  <div className="bg-blue-50 p-3 grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-[11px]">
                    <span className="text-blue-500 font-semibold">NONCE</span>
                    <span className="text-slate-800 font-bold truncate">{op.nonceDetails.nonce.slice(0,22)}…</span>
                    <span className="text-blue-500 font-semibold">CONTEXT_HASH</span>
                    <span className="text-slate-800 font-bold truncate">{op.nonceDetails.contextHash?.slice(0,22)}…</span>
                    <span className="text-blue-500 font-semibold">PRE_RISK_SCORE</span>
                    <span className={`font-bold ${op.nonceDetails.riskScore >= 70 ? 'text-rose-600' : op.nonceDetails.riskScore >= 40 ? 'text-amber-600' : 'text-emerald-600'}`}>
                      {op.nonceDetails.riskScore}/100
                    </span>
                    <span className="text-blue-500 font-semibold">EXPIRES_IN</span>
                    <span className="text-slate-800 font-bold">
                      {(() => {
                        const exp = op.nonceDetails.expiresAt;
                        if (!exp) return '—';
                        const rem = Math.round((exp > 1e10 ? exp/1000 : exp) - Date.now()/1000);
                        return rem > 0 ? <span className="text-emerald-600">{rem}s</span> : <span className="text-rose-500">expired</span>;
                      })()}
                    </span>
                  </div>
                  <div className="bg-blue-100 px-3 py-2 text-[9px] text-blue-600">
                    ⚠ Nonce is bound to amount=${amountNum.toFixed(2)} and recipient={recipient}. Replaying with different values fails server-side.
                  </div>
                </div>
              )}

              {/* Final risk score */}
              {op.riskScore > 0 && ['allowed','denied','step_up','stepup_signing'].includes(op.status) && (
                <div className="rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-800 px-4 py-2.5 flex items-center gap-2">
                    <ShieldCheck size={14} className="text-emerald-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Final Risk Decision</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-500 uppercase">Risk Score</span>
                      <span className={`font-bold text-sm ${op.riskScore >= 70 ? 'text-rose-600' : op.riskScore >= 40 ? 'text-amber-600' : 'text-emerald-600'}`}>{op.riskScore}/100</span>
                    </div>
                    <div className="w-full bg-slate-200 rounded-full h-2.5">
                      <div className={`h-2.5 rounded-full transition-all ${op.riskScore >= 70 ? 'bg-rose-500' : op.riskScore >= 40 ? 'bg-amber-500' : 'bg-emerald-500'}`} style={{ width: `${op.riskScore}%` }} />
                    </div>
                    <div className="flex justify-between text-[9px] text-slate-400 font-mono">
                      <span>0 — ALLOW</span><span>40 — STEP_UP</span><span>70 — DENY</span>
                    </div>
                    {op.riskReasons.length > 0 && (
                      <ul className="space-y-1 pt-1 border-t border-slate-100">
                        {op.riskReasons.map((r, i) => (
                          <li key={i} className="text-xs text-slate-500 flex items-start gap-1.5">
                            <AlertTriangle size={11} className="text-amber-500 mt-0.5 shrink-0" />{r}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}

              {/* Status message */}
              <p className={`text-sm text-center font-medium ${op.status === 'allowed' ? 'text-emerald-600' : op.status === 'denied' ? 'text-rose-600' : 'text-slate-600'}`}>
                {['collecting','challenging','signing','executing','stepup_signing'].includes(op.status) && (
                  <Loader2 className="inline animate-spin mr-2" size={14} />
                )}
                {op.message}
              </p>

              {/* TOTP step-up */}
              {op.status === 'step_up' && (
                <div className="space-y-3">
                  <p className="text-xs text-amber-700 bg-amber-50 border border-amber-100 rounded-lg p-3 text-center">
                    Transfer of ${amountNum.toFixed(2)} requires step-up. Enter your Google Authenticator code.
                  </p>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpCode}
                    onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="000000"
                    className="w-full text-center text-3xl font-mono font-bold tracking-[0.5em] py-4 bg-slate-50 border-2 border-amber-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-amber-400"
                  />
                  <p className="text-[10px] text-slate-400 text-center">Code refreshes every 30 seconds</p>
                  <button
                    onClick={handleTOTPStepUp}
                    disabled={totpCode.length !== 6}
                    className="w-full py-3 bg-amber-500 hover:bg-amber-600 disabled:opacity-40 text-white font-bold rounded-lg transition-colors"
                  >
                    Verify Code
                  </button>
                </div>
              )}

              {/* Denied / Error */}
              {['denied','error'].includes(op.status) && (
                <div className="flex gap-3">
                  <button onClick={closeModal} className="flex-1 py-3 border border-slate-200 text-slate-600 font-medium rounded-lg hover:bg-slate-50">Cancel</button>
                  <button onClick={handleRetry} className="flex-1 flex items-center justify-center gap-2 py-3 bg-slate-800 hover:bg-slate-900 text-white font-bold rounded-lg">
                    <RefreshCw size={15} /> Try Again
                  </button>
                </div>
              )}

            </div>
          </div>
        </div>
      )}

      {/* ── Transfer form ── */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
        <div className="bg-blue-600 p-6 text-white flex items-center gap-3">
          <div className="p-2 bg-white/20 rounded-lg"><ArrowRightLeft size={20} /></div>
          <div>
            <h2 className="font-bold text-lg">Transfer Money</h2>
            <p className="text-white/70 text-xs">Amount-aware risk scoring · Context-bound nonce</p>
          </div>
        </div>
        <div className="p-6">
          {phase === 'form' && (
            <div className="space-y-4">
              <div className="p-4 bg-slate-50 rounded-xl border border-slate-100 flex items-center justify-between">
                <div>
                  <p className="text-xs text-slate-400 uppercase font-bold tracking-wider">From</p>
                  <p className="font-bold text-slate-800">{user}</p>
                  <p className="text-xs text-slate-400 font-mono">SB-••••-••••-8821</p>
                </div>
                <div className="p-3 bg-blue-100 rounded-full"><Send size={18} className="text-blue-600" /></div>
                <div className="text-right">
                  <p className="text-xs text-slate-400 uppercase font-bold tracking-wider">Balance</p>
                  <p className="font-bold text-slate-800">$12,450.80</p>
                </div>
              </div>
              <div>
                <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Recipient Username</label>
                <input type="text" value={recipient} onChange={e => setRecipient(e.target.value)} placeholder="e.g. jdoe88"
                  className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
              </div>
              <div>
                <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Amount (USD)</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 font-bold">$</span>
                  <input type="number" value={amount} onChange={e => setAmount(e.target.value)} placeholder="0.00"
                    className="w-full pl-8 p-3 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
                </div>
                {hint && (
                  <p className={`mt-1.5 text-[10px] font-bold px-2 py-1 rounded border w-fit ${hint.color}`}>
                    {hint.label}
                  </p>
                )}
              </div>
              <div>
                <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Note (optional)</label>
                <input type="text" value={note} onChange={e => setNote(e.target.value)} placeholder="e.g. Rent payment"
                  className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
              </div>
              <button onClick={() => setPhase('confirm')} disabled={!recipient || !amount}
                className="w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white font-bold rounded-lg transition-colors">
                Review Transfer
              </button>
            </div>
          )}
          {phase === 'confirm' && (
            <div className="space-y-4">
              <h3 className="font-bold text-slate-800 text-center">Confirm Transfer</h3>
              <div className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3 font-mono text-sm">
                <div className="flex justify-between"><span className="text-slate-400">To</span><span className="font-bold">{recipient}</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Amount</span><span className="font-bold text-blue-600">${amountNum.toFixed(2)}</span></div>
                {note && <div className="flex justify-between"><span className="text-slate-400">Note</span><span className="font-bold">{note}</span></div>}
                <div className="flex justify-between pt-2 border-t border-slate-200"><span className="text-slate-400">New Balance</span><span className="font-bold">${(12450.80 - amountNum).toFixed(2)}</span></div>
              </div>
              {hint && (
                <div className={`text-xs font-medium px-3 py-2 rounded-lg border ${hint.color}`}>
                  💡 Risk engine prediction: <strong>{hint.label}</strong> based on transfer amount
                </div>
              )}
              <div className="flex gap-3">
                <button onClick={() => setPhase('form')} className="flex-1 py-3 border border-slate-200 text-slate-600 font-bold rounded-lg hover:bg-slate-50">Edit</button>
                <button
                  onClick={() => runTransferAuth(amountNum, recipient)}
                  className="flex-1 py-3 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg transition-colors"
                >
                  Confirm & Send
                </button>
              </div>
            </div>
          )}
          {phase === 'done' && (
            <div className="text-center py-8 space-y-4">
              <div className="mx-auto w-16 h-16 rounded-full bg-emerald-100 flex items-center justify-center">
                <CheckCircle2 size={36} className="text-emerald-600" />
              </div>
              <h3 className="text-xl font-bold text-slate-800">Transfer Complete</h3>
              <p className="text-slate-500 text-sm">${amountNum.toFixed(2)} sent to <strong>{recipient}</strong></p>
              <p className="text-[10px] text-slate-400 font-mono">TXN-{Date.now()} · Logged to audit chain</p>
              <button onClick={onBack} className="w-full py-3 border border-slate-200 text-slate-600 font-bold rounded-lg hover:bg-slate-50">Back to Dashboard</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const DeleteView: React.FC<{ user: string; onBack: () => void }> = ({ user, onBack }) => {
  const [countdown, setCountdown] = useState(5);
  const [phase, setPhase] = useState<'warning' | 'countdown' | 'done'>('warning');
  const timerRef = useRef<any>(null);
  const startCountdown = () => {
    setPhase('countdown');
    timerRef.current = setInterval(() => {
      setCountdown(c => {
        if (c <= 1) { clearInterval(timerRef.current); setPhase('done'); return 0; }
        return c - 1;
      });
    }, 1000);
  };
  useEffect(() => () => clearInterval(timerRef.current), []);
  return (
    <div className="space-y-6">
      <button onClick={onBack} className="flex items-center gap-2 text-slate-500 hover:text-slate-800 text-sm font-medium">
        <ArrowLeft size={16} /> Back to Dashboard
      </button>
      <div className="bg-white rounded-2xl border border-rose-200 overflow-hidden">
        <div className="bg-rose-600 p-6 text-white flex items-center gap-3">
          <div className="p-2 bg-white/20 rounded-lg"><AlertOctagon size={20} /></div>
          <div>
            <h2 className="font-bold text-lg">Close Account</h2>
            <p className="text-white/70 text-xs">High-risk operation · Irreversible</p>
          </div>
          <span className="ml-auto text-[10px] bg-white/20 text-white border border-white/30 px-2 py-1 rounded-full font-bold">⚠️ AUTHORIZED</span>
        </div>
        <div className="p-6">
          {phase === 'warning' && (
            <div className="space-y-5">
              <div className="p-5 bg-rose-50 border border-rose-200 rounded-xl space-y-2">
                <h3 className="font-bold text-rose-900 flex items-center gap-2"><AlertOctagon size={16} /> This action is permanent</h3>
                <ul className="text-sm text-rose-700 space-y-1.5">
                  {['All account data will be permanently deleted','Your balance of $12,450.80 will be forfeited','Your device key bundle will be wiped from localStorage','This action will be recorded and cannot be undone'].map(item => (
                    <li key={item} className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-rose-400 shrink-0" />{item}</li>
                  ))}
                </ul>
              </div>
              <div className="flex gap-3">
                <button onClick={onBack} className="flex-1 py-3 border border-slate-200 text-slate-600 font-bold rounded-lg hover:bg-slate-50">Cancel</button>
                <button onClick={startCountdown} className="flex-1 py-3 bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-lg transition-colors">Proceed to Delete</button>
              </div>
            </div>
          )}
          {phase === 'countdown' && (
            <div className="text-center py-10 space-y-4">
              <div className="mx-auto w-24 h-24 rounded-full border-4 border-rose-200 flex items-center justify-center">
                <span className="text-4xl font-black text-rose-600">{countdown}</span>
              </div>
              <p className="text-slate-600 font-medium">Deleting in {countdown} second{countdown !== 1 ? 's' : ''}…</p>
              <p className="text-xs text-slate-400">Close this tab to abort</p>
            </div>
          )}
          {phase === 'done' && (
            <div className="text-center py-10 space-y-4">
              <div className="mx-auto w-16 h-16 rounded-full bg-slate-100 flex items-center justify-center">
                <Trash2 size={32} className="text-slate-400" />
              </div>
              <h3 className="text-xl font-bold text-slate-800">Account Closed</h3>
              <p className="text-slate-500 text-sm">Demo account for <strong>{user}</strong> has been wiped.</p>
              <p className="text-[10px] text-slate-400 font-mono">DEL-{Date.now()} · Audit chain entry written</p>
              <p className="text-xs text-slate-400 italic">(Demo mode — refresh to start fresh)</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ─── Main Dashboard ───────────────────────────────────────────────────────────

const Dashboard: React.FC<DashboardProps> = ({ user, onNavigate, onStepUp, pendingOperation, onStepUpComplete }) => {
  const { log } = useAudit();
  const [op, setOp]               = useState<OpState>(INITIAL);
  const [activeView, setActiveView] = useState<OperationType | null>(null);
  const [totpCode, setTotpCode]   = useState('');

  // Close modal and go back to dashboard grid (does NOT reset activeView)
  const closeModal = () => { setOp(INITIAL); setTotpCode(''); };

  useEffect(() => {
    if (pendingOperation) {
      onStepUpComplete?.();
      runOperation(pendingOperation as OperationType);
    }
  }, []);

  // ── Core auth flow — can be called fresh or as a retry ──
  const runOperation = async (operationId: OperationType) => {
    setOp({ ...INITIAL, status: 'collecting', operationId, message: 'Gathering device & behavioural signals…' });
    log('info', `── Operation started: ${operationId} ──`);
    try {
      // ── Step 1: Collect context signals ──────────────────────────────────
      log('info', `Collecting device & behavioural signals for ${operationId}…`);
      const riskCtx = await collectRiskContext(operationId);
      const contextDetails: ContextDetails = {
        deviceFingerprint: riskCtx.deviceFingerprint, sessionAgeMs: riskCtx.sessionAgeMs,
        timezone: riskCtx.timezone, connectionType: riskCtx.connectionType,
        mouseMovementDetected: riskCtx.mouseMovementDetected,
        keyboardInteractionDetected: riskCtx.keyboardInteractionDetected,
        timeOnPageMs: riskCtx.timeOnPageMs,
      };
      log('crypto', 'Device fingerprint (SHA-256) collected', riskCtx.deviceFingerprint.slice(0, 32) + '…');
      log('info',   `Session age: ${(riskCtx.sessionAgeMs/1000).toFixed(1)}s · Mouse: ${riskCtx.mouseMovementDetected ? 'YES' : 'NO'} · Keyboard: ${riskCtx.keyboardInteractionDetected ? 'YES' : 'NO'}`);
      log('info',   `Connection: ${riskCtx.connectionType} · Timezone: ${riskCtx.timezone}`);

      // ── Step 2: Request context-bound nonce ───────────────────────────────
      setOp(s => ({ ...s, status: 'challenging', contextDetails, message: 'Sending context to server — requesting bound nonce…' }));
      log('network', `POST /operation-challenge — binding context to nonce for ${operationId}…`);
      const challengeResp = await Api.getOperationChallenge(user, operationId, riskCtx);

      if (challengeResp.status === 'DENIED') {
        log('error', `Challenge denied by server: ${challengeResp.reason ?? 'risk policy'}`);
        setOp(s => ({ ...s, status: 'denied', riskScore: challengeResp.risk ?? 0, riskReasons: challengeResp.factors ?? [], message: challengeResp.reason ?? 'Denied by risk policy.' }));
        return;
      }

      log('network', 'Nonce received from server', challengeResp.nonce?.slice(0, 20) + '…');
      log('crypto',  'Context hash (SHA-256 of username+operation+context)', challengeResp.contextHash?.slice(0, 32) + '…');
      log('info',    `Nonce expires in 60s — bound to this exact context, single-use`);

      const nonceDetails: NonceDetails = {
        nonce: challengeResp.nonce, contextHash: challengeResp.contextHash ?? '—',
        expiresAt: challengeResp.expiresAt, riskLevel: challengeResp.riskLevel ?? '—',
        riskScore: challengeResp.riskScore ?? 0,
      };

      // ── Step 3: Decrypt private key + sign nonce ──────────────────────────
      setOp(s => ({ ...s, status: 'signing', nonceDetails, message: 'Decrypting device key & signing the bound nonce…' }));
      log('info',   'Loading encrypted key bundle from localStorage…');
      log('crypto', 'Re-collecting device fingerprint to re-derive MasterKey…');
      log('crypto', 'PBKDF2-SHA256 (310,000 iterations) → AES-256 MasterKey derived in RAM');
      log('crypto', 'AES-256-GCM decryption → private key bytes in RAM');
      const signature = await decryptAndSign(user, challengeResp.nonce);
      log('crypto', 'RSA-PSS signature computed over context-bound nonce');
      log('ram',    '🗑️  Private key bytes zeroed — no longer in memory');

      // ── Step 4: Execute operation (server risk gate) ──────────────────────
      setOp(s => ({ ...s, status: 'executing', message: 'Sending signed nonce — server running final risk gate…' }));
      log('network', 'POST /execute-operation — sending nonce + signature + context…');
      log('info',    'Server will: verify nonce → check expiry → verify context hash → verify RSA signature → run risk engine');
      const execResp = await Api.executeOperation(user, operationId, challengeResp.nonce, riskCtx, signature);

      recordOperation();

      // ── Step 5: Handle server decision ────────────────────────────────────
      if (execResp.status === 'ALLOW') {
        log('success', `✅ Server decision: ALLOW (risk=${execResp.risk}/100) — operation authorized`);
        setOp(s => ({ ...s, status: 'allowed', riskScore: execResp.risk ?? 0, message: 'Operation authorised — context verified ✓' }));
        setTimeout(() => { closeModal(); setActiveView(operationId); }, 1500);
      } else if (execResp.status === 'STEP_UP') {
        log('warning', `⚠️ Server decision: STEP_UP (risk=${execResp.risk}/100) — second factor required`);
        if (execResp.reasons?.length) log('warning', `Risk factors: ${execResp.reasons.join(' · ')}`);
        setOp(s => ({ ...s, status: 'step_up', riskScore: execResp.risk ?? 0, riskReasons: execResp.factors ?? [], message: execResp.reason ?? 'Step-up authentication required.' }));
      } else {
        log('error', `❌ Server decision: DENY (risk=${execResp.risk}/100) — ${execResp.reason ?? 'risk too high'}`);
        if (execResp.reasons?.length) log('error', `Risk factors: ${execResp.reasons.join(' · ')}`);
        setOp(s => ({ ...s, status: 'denied', riskScore: execResp.risk ?? 0, riskReasons: execResp.factors ?? [], message: execResp.reason ?? 'Operation denied.' }));
      }
    } catch (err: any) {
      log('error', 'Operation flow error: ' + (err.message ?? 'Unexpected error'));
      setOp(s => ({ ...s, status: 'error', message: err.message ?? 'Unexpected error.' }));
    }
  };

  // ── TOTP Step-Up: user enters 6-digit code from Google Authenticator ──
  const handleTOTPStepUp = async () => {
    if (!op.operationId) return;
    const operationId = op.operationId;
    const code = totpCode.trim();

    if (code.length !== 6 || !/^\d{6}$/.test(code)) {
      setOp(s => ({ ...s, message: 'Enter the 6-digit code from your authenticator app.' }));
      return;
    }

    setOp(s => ({ ...s, status: 'stepup_signing', message: 'Verifying authenticator code…' }));
    log('info',    `── Step-Up: TOTP verification for ${operationId} ──`);
    log('network', 'POST /stepup-totp — sending 6-digit TOTP code to server…');
    log('info',    'Server will: fetch totp_secret from DB → pyotp.TOTP(secret).verify(code)');
    try {
      const result = await Api.verifyStepUpTOTP(user, operationId, code);

      if (result.status === 'UPGRADED_ALLOW') {
        log('success', '✅ TOTP verified — second factor confirmed (phone possession proven)');
        log('info',    'Two factors satisfied: device-bound key (laptop) + TOTP (phone)');
        setTotpCode('');
        setOp(s => ({ ...s, status: 'allowed', message: '✅ Authenticator code verified — operation authorized.' }));
        setTimeout(() => { closeModal(); setActiveView(operationId); }, 1500);
      } else {
        log('error', `❌ TOTP verification failed: ${result.reason ?? 'invalid code'}`);
        setTotpCode('');
        setOp(s => ({
          ...s,
          status: 'step_up',
          message: result.reason === 'Invalid or expired code'
            ? '❌ Wrong code — wait for the next 30s window and try again.'
            : 'Step-up failed. Try again.',
        }));
      }
    } catch (err: any) {
      log('error', 'Step-up error: ' + (err.message ?? 'Unexpected error'));
      setOp(s => ({ ...s, status: 'error', message: err.message ?? 'Step-up failed.' }));
    }
  };

  // ── Transfer-specific auth: runs after user fills in amount + recipient ──
  // Passes amount and recipient inside context so risk engine can score them.
  const runTransferAuth = async (amount: number, recipient: string) => {
    const operationId = OperationType.TRANSFER;
    setOp({ ...INITIAL, status: 'collecting', operationId, message: 'Gathering device & behavioural signals…' });
    log('info', `── Transfer auth started: $${amount} → ${recipient} ──`);
    try {
      // Step 1: collect context — amount + recipient included
      log('info', 'Collecting device & behavioural signals…');
      const riskCtx = await collectRiskContext(operationId);
      const contextWithAmount = { ...riskCtx, amount, recipient };
      const contextDetails: ContextDetails = {
        deviceFingerprint: riskCtx.deviceFingerprint, sessionAgeMs: riskCtx.sessionAgeMs,
        timezone: riskCtx.timezone, connectionType: riskCtx.connectionType,
        mouseMovementDetected: riskCtx.mouseMovementDetected,
        keyboardInteractionDetected: riskCtx.keyboardInteractionDetected,
        timeOnPageMs: riskCtx.timeOnPageMs,
      };
      log('crypto', 'Device fingerprint (SHA-256) collected', riskCtx.deviceFingerprint.slice(0, 32) + '…');
      log('info',   `Amount: $${amount} · Recipient: ${recipient} · Session age: ${(riskCtx.sessionAgeMs/1000).toFixed(1)}s`);

      // Step 2: request nonce — context includes amount so hash covers it
      setOp(s => ({ ...s, status: 'challenging', contextDetails, message: 'Binding transfer context to nonce…' }));
      log('network', `POST /operation-challenge — amount=$${amount} is now part of context hash`);
      const challengeResp = await Api.getOperationChallenge(user, operationId, contextWithAmount);

      if (challengeResp.status === 'DENIED') {
        log('error', `Challenge denied: ${challengeResp.reason ?? 'risk policy'}`);
        setOp(s => ({ ...s, status: 'denied', riskScore: challengeResp.risk ?? 0, riskReasons: challengeResp.factors ?? [], message: challengeResp.reason ?? 'Denied by risk policy.' }));
        return;
      }

      log('network', 'Nonce received', challengeResp.nonce?.slice(0, 20) + '…');
      log('crypto',  `Context hash covers: user + TRANSFER + amount=$${amount} + recipient=${recipient}`, challengeResp.contextHash?.slice(0, 32) + '…');
      log('info',    'Nonce is single-use, expires in 60s, bound to this exact amount');

      const nonceDetails: NonceDetails = {
        nonce: challengeResp.nonce, contextHash: challengeResp.contextHash ?? '—',
        expiresAt: challengeResp.expiresAt, riskLevel: challengeResp.riskLevel ?? '—',
        riskScore: challengeResp.riskScore ?? 0,
      };

      // Step 3: decrypt private key + sign nonce
      setOp(s => ({ ...s, status: 'signing', nonceDetails, message: 'Decrypting device key & signing the bound nonce…' }));
      log('crypto', 'Re-deriving MasterKey from device fingerprint via PBKDF2-SHA256 (310,000 iterations)…');
      log('crypto', 'AES-256-GCM decryption → private key bytes in RAM');
      const signature = await decryptAndSign(user, challengeResp.nonce);
      log('crypto', 'RSA-PSS signature computed over context-bound nonce');
      log('ram',    '🗑️  Private key bytes zeroed — no longer in memory');

      // Step 4: execute — server checks nonce + context hash + signature + risk
      setOp(s => ({ ...s, status: 'executing', message: 'Sending signed nonce — server running risk gate…' }));
      log('network', 'POST /execute-operation — amount is part of context hash, server re-verifies it');
      const execResp = await Api.executeOperation(user, operationId, challengeResp.nonce, contextWithAmount, signature);

      recordOperation();

      if (execResp.status === 'ALLOW') {
        log('success', `✅ ALLOW — risk=${execResp.risk}/100 — transfer of $${amount} authorized`);
        setOp(s => ({ ...s, status: 'allowed', riskScore: execResp.risk ?? 0, message: `Transfer of $${amount} authorised ✓` }));
        // TransferView's useEffect watches for this and moves to 'done' phase
      } else if (execResp.status === 'STEP_UP') {
        log('warning', `⚠️ STEP_UP — risk=${execResp.risk}/100 — amount $${amount} triggered elevated check`);
        if (execResp.reasons?.length) log('warning', `Risk factors: ${execResp.reasons.join(' · ')}`);
        setOp(s => ({ ...s, status: 'step_up', riskScore: execResp.risk ?? 0, riskReasons: execResp.reasons ?? [], message: 'Step-up required — open Google Authenticator.' }));
      } else {
        log('error', `❌ DENY — risk=${execResp.risk}/100 — transfer blocked`);
        if (execResp.reasons?.length) log('error', `Risk factors: ${execResp.reasons.join(' · ')}`);
        setOp(s => ({ ...s, status: 'denied', riskScore: execResp.risk ?? 0, riskReasons: execResp.reasons ?? [], message: execResp.reason ?? 'Transfer denied by risk policy.' }));
      }
    } catch (err: any) {
      log('error', 'Transfer auth error: ' + (err.message ?? 'Unexpected error'));
      setOp(s => ({ ...s, status: 'error', message: err.message ?? 'Unexpected error.' }));
    }
  };

  // ── Retry: re-runs the full auth flow for the same operation ──
  const handleRetry = () => {
    if (op.operationId) runOperation(op.operationId);
  };

  const headerBg =
    op.status === 'allowed'                         ? 'bg-emerald-600' :
    op.status === 'denied' || op.status === 'error' ? 'bg-rose-600'    :
    op.status === 'step_up'                         ? 'bg-amber-500'   : 'bg-slate-900';

  // Render post-auth operation views
  if (activeView === OperationType.READ)     return <ReadView     user={user} onBack={() => setActiveView(null)} />;
  if (activeView === OperationType.WRITE)    return <WriteView    user={user} onBack={() => setActiveView(null)} />;
  if (activeView === OperationType.TRANSFER) return (
    <TransferView
      user={user}
      onBack={() => { setActiveView(null); setOp(INITIAL); setTotpCode(''); }}
      runTransferAuth={runTransferAuth}
      op={op}
      closeModal={closeModal}
      totpCode={totpCode}
      setTotpCode={setTotpCode}
      handleTOTPStepUp={handleTOTPStepUp}
      handleRetry={handleRetry}
      headerBg={headerBg}
    />
  );
  if (activeView === OperationType.DELETE)   return <DeleteView   user={user} onBack={() => setActiveView(null)} />;

  return (
    <div className="space-y-8">

      {/* Header */}
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Welcome, {user}</h1>
          <p className="text-slate-500">Academic Demo Session · {new Date().toLocaleDateString()}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => onNavigate('logs')} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50"><History size={16} /> Audit Logs</button>
          <button onClick={() => onNavigate('integrity')} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50"><ShieldCheck size={16} /> Verify Integrity</button>
        </div>
      </header>

      {/* ── Security Check Modal ── */}
      {op.status !== 'idle' && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg my-4 overflow-hidden">

            {/* Modal header */}
            <div className={`p-5 text-white ${headerBg}`}>
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-bold text-lg">Security Check</h3>
                  <p className="text-white/70 text-xs mt-0.5 uppercase tracking-wider">
                    {op.operationId} — Context-Aware Nonce + Risk Engine
                  </p>
                </div>
                {/* X closes the modal but stays on dashboard — no page reset */}
                {['denied','error','step_up','allowed'].includes(op.status) && (
                  <button onClick={closeModal} className="p-1 hover:opacity-70"><X size={20} /></button>
                )}
              </div>
            </div>

            <div className="p-5 space-y-4 max-h-[80vh] overflow-y-auto">

              {/* Step progress */}
              <div className="space-y-1.5">
                {STEPS.map((s) => {
                  const order  = STEPS.map(x => x.id);
                  const curIdx = order.indexOf(op.status);
                  const sIdx   = order.indexOf(s.id);
                  const isDone   = ['allowed','denied','step_up','stepup_signing','error'].includes(op.status) || sIdx < curIdx;
                  const isActive = s.id === op.status;
                  return (
                    <div key={s.id} className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${isActive ? 'bg-blue-50 text-blue-800 font-semibold' : isDone ? 'text-slate-400' : 'text-slate-300'}`}>
                      <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 transition-all ${isDone ? 'border-emerald-400 bg-emerald-400' : isActive ? 'border-blue-500 bg-blue-500 animate-pulse' : 'border-slate-200'}`}>
                        {isDone && <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7"/></svg>}
                      </div>
                      {s.label}
                    </div>
                  );
                })}
              </div>

              {/* Context Signals */}
              {op.contextDetails && ['challenging','signing','executing','allowed','denied','step_up','stepup_signing'].includes(op.status) && (
                <div className="rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-800 px-4 py-2.5 flex items-center gap-2">
                    <Cpu size={14} className="text-blue-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Context Signals Collected</span>
                  </div>
                  <div className="bg-slate-50 p-3 grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-[10px]">
                    <span className="text-slate-400">DEVICE_FP</span><span className="text-slate-700 font-bold truncate">{truncate(op.contextDetails.deviceFingerprint, 22)}</span>
                    <span className="text-slate-400">SESSION_AGE</span><span className="text-slate-700 font-bold">{msToSec(op.contextDetails.sessionAgeMs)}</span>
                    <span className="text-slate-400">TIME_ON_PAGE</span><span className="text-slate-700 font-bold">{msToSec(op.contextDetails.timeOnPageMs)}</span>
                    <span className="text-slate-400">TIMEZONE</span><span className="text-slate-700 font-bold truncate">{op.contextDetails.timezone}</span>
                    <span className="text-slate-400">CONNECTION</span><span className="text-slate-700 font-bold">{op.contextDetails.connectionType}</span>
                    <span className="text-slate-400">MOUSE_MOVED</span>
                    <span className={`font-bold ${op.contextDetails.mouseMovementDetected ? 'text-emerald-600' : 'text-rose-500'}`}>{op.contextDetails.mouseMovementDetected ? '✓ YES' : '✗ NO'}</span>
                    <span className="text-slate-400">KEYBOARD_USED</span>
                    <span className={`font-bold ${op.contextDetails.keyboardInteractionDetected ? 'text-emerald-600' : 'text-rose-500'}`}>{op.contextDetails.keyboardInteractionDetected ? '✓ YES' : '✗ NO'}</span>
                  </div>
                </div>
              )}

              {/* Nonce Binding */}
              {op.nonceDetails && ['signing','executing','allowed','denied','step_up','stepup_signing'].includes(op.status) && (
                <div className="rounded-xl border border-blue-200 overflow-hidden">
                  <div className="bg-blue-700 px-4 py-2.5 flex items-center gap-2">
                    <Hash size={14} className="text-blue-200" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Context-Bound Nonce</span>
                  </div>
                  <div className="bg-blue-50 p-3 grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-[11px]">
                    <span className="text-blue-500 font-semibold">NONCE</span>
                    <span className="text-slate-800 font-bold truncate">{truncate(op.nonceDetails.nonce, 22)}</span>
                    <span className="text-blue-500 font-semibold">CONTEXT_HASH</span>
                    <span className="text-slate-800 font-bold truncate">
                      {op.nonceDetails.contextHash && op.nonceDetails.contextHash !== '—'
                        ? truncate(op.nonceDetails.contextHash, 22)
                        : <span className="text-amber-500 italic">not returned</span>}
                    </span>
                    <span className="text-blue-500 font-semibold">PRE_RISK_SCORE</span>
                    <span className={`font-bold ${op.nonceDetails.riskScore >= 70 ? 'text-rose-600' : op.nonceDetails.riskScore >= 40 ? 'text-amber-600' : 'text-emerald-600'}`}>
                      {op.nonceDetails.riskScore}/100 ({op.nonceDetails.riskLevel})
                    </span>
                    <span className="text-blue-500 font-semibold">EXPIRES_IN</span>
                    <span className="text-slate-800 font-bold">
                      {(() => {
                        const exp = op.nonceDetails.expiresAt;
                        if (!exp) return <span className="text-amber-500 italic">not returned</span>;
                        const nowSec = Date.now() / 1000;
                        const expSec = exp > 1e10 ? exp / 1000 : exp;
                        const remaining = Math.round(expSec - nowSec);
                        return remaining > 0
                          ? <span className="text-emerald-600">{remaining}s</span>
                          : <span className="text-rose-500">expired</span>;
                      })()}
                    </span>
                  </div>
                  <div className="bg-blue-100 px-3 py-2 text-[9px] text-blue-600 leading-relaxed">
                    ⚠ This nonce is cryptographically bound to the context hash above. Replaying it with different operation/user/amount will fail server-side verification.
                  </div>
                </div>
              )}

              {/* Final Risk Score */}
              {op.riskScore > 0 && ['allowed','denied','step_up','stepup_signing'].includes(op.status) && (
                <div className="rounded-xl border border-slate-200 overflow-hidden">
                  <div className="bg-slate-800 px-4 py-2.5 flex items-center gap-2">
                    <ShieldCheck size={14} className="text-emerald-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Final Risk Decision</span>
                  </div>
                  <div className="p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-500 uppercase">Risk Score</span>
                      <span className={`font-bold text-sm ${op.riskScore >= 70 ? 'text-rose-600' : op.riskScore >= 40 ? 'text-amber-600' : 'text-emerald-600'}`}>{op.riskScore}/100</span>
                    </div>
                    <div className="w-full bg-slate-200 rounded-full h-2.5">
                      <div className={`h-2.5 rounded-full transition-all ${op.riskScore >= 70 ? 'bg-rose-500' : op.riskScore >= 40 ? 'bg-amber-500' : 'bg-emerald-500'}`} style={{ width: `${op.riskScore}%` }} />
                    </div>
                    <div className="flex justify-between text-[9px] text-slate-400 font-mono">
                      <span>0 — ALLOW</span><span>40 — STEP_UP</span><span>70 — DENY</span>
                    </div>
                    {op.riskReasons.length > 0 && (
                      <ul className="space-y-1 pt-1 border-t border-slate-100">
                        {op.riskReasons.map((r, i) => (
                          <li key={i} className="text-xs text-slate-500 flex items-start gap-1.5">
                            <AlertTriangle size={11} className="text-amber-500 mt-0.5 shrink-0" />{r}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}

              {/* Status message */}
              <p className={`text-sm text-center font-medium ${op.status === 'allowed' ? 'text-emerald-600' : op.status === 'denied' ? 'text-rose-600' : 'text-slate-600'}`}>
                {['collecting','challenging','signing','executing','stepup_signing'].includes(op.status) && (
                  <Loader2 className="inline animate-spin mr-2" size={14} />
                )}
                {op.message}
              </p>

              {/* ── Step-Up CTA: inline device-key re-auth ── */}
              {op.status === 'step_up' && (
                <div className="space-y-3">

                  {/* Explanation banner */}
                  <div className="p-3 bg-amber-50 border border-amber-100 rounded-xl text-xs text-amber-800 space-y-1">
                    <p className="font-bold">🔐 Step-Up Authentication Required</p>
                    <p>
                      This operation has a risk score in the medium band.
                      Open <strong>Google Authenticator</strong> on your phone and
                      enter the 6-digit code for <strong>SecureBank Demo</strong>.
                    </p>
                  </div>

                  {/* 6-digit input */}
                  <div className="flex flex-col items-center gap-3">
                    <input
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      maxLength={6}
                      value={totpCode}
                      onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="_ _ _ _ _ _"
                      className="w-48 text-center text-3xl font-mono font-bold tracking-[0.4em] py-3 px-4 border-2 border-amber-300 rounded-xl focus:outline-none focus:border-amber-500 bg-amber-50"
                      autoFocus
                    />
                    <p className="text-[10px] text-slate-400">
                      Code refreshes every 30 seconds
                    </p>
                  </div>

                  <button
                    onClick={handleTOTPStepUp}
                    disabled={totpCode.length !== 6}
                    className="w-full flex items-center justify-center gap-2 py-3 bg-amber-500 text-white font-bold rounded-lg hover:bg-amber-600 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <ShieldCheck size={16} /> Verify Code
                  </button>

                  {op.message.startsWith('❌') && (
                    <p className="text-xs text-rose-600 text-center">{op.message}</p>
                  )}
                </div>
              )}

              {/* ── Denied / Error: retry restarts the full flow for the same operation ── */}
              {['denied', 'error'].includes(op.status) && (
                <div className="flex gap-3">
                  <button onClick={closeModal}
                    className="flex-1 py-3 border border-slate-200 text-slate-600 font-medium rounded-lg hover:bg-slate-50">
                    Cancel
                  </button>
                  <button onClick={handleRetry}
                    className="flex-1 flex items-center justify-center gap-2 py-3 bg-slate-800 hover:bg-slate-900 text-white font-bold rounded-lg transition-colors">
                    <RefreshCw size={15} /> Try Again
                  </button>
                </div>
              )}

            </div>
          </div>
        </div>
      )}

      {/* ── Main Grid ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-1 bg-slate-900 rounded-2xl p-8 text-white relative overflow-hidden">
          <div className="relative z-10">
            <p className="text-slate-400 text-sm uppercase tracking-wider mb-2">Available Balance</p>
            <h2 className="text-4xl font-bold">$12,450.80</h2>
            <div className="mt-8 flex items-center gap-3">
              <div className="p-2 bg-emerald-500/20 rounded-lg"><Lock size={20} className="text-emerald-400" /></div>
              <p className="text-xs text-slate-300 leading-relaxed">Protected by <strong>Context-Aware Nonce Binding</strong> + <strong>Risk Engine</strong>.</p>
            </div>
          </div>
          <div className="absolute -right-10 -bottom-10 w-40 h-40 bg-blue-600/20 rounded-full blur-3xl" />
          <div className="absolute -left-10 -top-10 w-40 h-40 bg-blue-400/10 rounded-full blur-3xl" />
        </div>

        <div className="lg:col-span-2">
          <h3 className="font-bold text-slate-800 flex items-center gap-2 mb-4"><ShieldCheck className="text-blue-600" size={20} />Secure Operations</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {OPERATIONS.map(o => (
              <button key={o.id} onClick={() => o.id === OperationType.TRANSFER ? setActiveView(OperationType.TRANSFER) : runOperation(o.id)}
                className="group flex flex-col items-start p-6 bg-white border border-slate-200 rounded-xl hover:shadow-lg hover:border-blue-200 transition-all text-left">
                <div className="p-3 rounded-xl mb-4 bg-slate-50 group-hover:scale-110 transition-transform">{o.icon}</div>
                <h4 className="font-bold text-slate-800 mb-1">{o.title}</h4>
                <p className="text-xs text-slate-500 mb-4">{o.desc}</p>
                <div className="mt-auto flex items-center gap-2">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border ${riskStyles[o.risk]}`}>{o.risk} RISK</span>
                  <ChevronRight size={14} className="text-slate-300 group-hover:text-blue-400 ml-auto" />
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Info banner */}
      <div className="p-5 bg-blue-50 border border-blue-100 rounded-2xl flex gap-4">
        <div className="p-3 bg-blue-100 rounded-full h-fit"><ShieldCheck className="text-blue-600" size={22} /></div>
        <div className="space-y-1">
          <h4 className="font-bold text-blue-900 text-sm">Two-Layer Security Active</h4>
          <p className="text-xs text-blue-700/80 leading-relaxed"><strong>Layer 1 — Context-Aware Nonce:</strong> Every nonce is SHA-256 bound to the operation type, user, target, and amount. Replaying it with any different payload fails server-side.</p>
          <p className="text-xs text-blue-700/80 leading-relaxed"><strong>Layer 2 — Risk Engine:</strong> Device fingerprint, session age, velocity, behavioural signals, and transfer amount are scored before the nonce is issued and again before execution.</p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;