import React, { useState, useEffect } from 'react';
import { User, ShieldCheck, ShieldAlert, Loader2, Lock, KeyRound, ShieldHalf } from 'lucide-react';

import { Api } from '../services/api';
import { generateKeyPair, exportPublicKeyPEM } from '../utils/keygen';
import {
  encryptAndStorePrivateKey,
  decryptAndSign,
  hasStoredKey,
  deleteStoredKey,
  collectDeviceFingerprint,
} from '../utils/deviceKey';
import { useAudit } from '../components/SecurityAuditPanel';

interface LoginProps {
  onLoginSuccess: (username: string) => void;
  onAdminSuccess: (token: string) => void;
  stepUpOperation?: string | null;
}

const Login: React.FC<LoginProps> = ({ onLoginSuccess, onAdminSuccess, stepUpOperation }) => {
  const { log, clear } = useAudit();

  const [username, setUsername]               = useState('');
  const [activeTab, setActiveTab]             = useState<'login' | 'register' | 'admin'>('login');
  const [showFingerprint, setShowFingerprint] = useState(false);
  const [fingerprintHash, setFingerprintHash] = useState<string>('computing…');

  const [step, setStep] = useState<
    | 'idle' | 'generating' | 'encrypting'
    | 'requesting' | 'decrypting' | 'signing' | 'verifying'
    | 'success' | 'failed'
  >('idle');
  const [errorMessage, setErrorMessage] = useState('');

  // ── TOTP setup — shown after successful registration ──────────────────────
  const [totpQR,     setTotpQR]     = useState<string | null>(null);
  const [totpSecret, setTotpSecret] = useState<string | null>(null);

  // ── Admin login state ─────────────────────────────────────────────────────
  const [adminUser,    setAdminUser]    = useState('');
  const [adminPass,    setAdminPass]    = useState('');
  const [adminError,   setAdminError]   = useState('');
  const [adminLoading, setAdminLoading] = useState(false);

  useEffect(() => {
    collectDeviceFingerprint().then(setFingerprintHash);
  }, []);

  const isStepUp = !!stepUpOperation;

  // ─── Registration ──────────────────────────────────────────────────────────
  const handleRegister = async () => {
    if (!username.trim()) { setErrorMessage('Enter a username first.'); return; }
    setErrorMessage('');
    clear();
    const registrationStart = performance.now();

    try {
      log('info', `Starting registration for user "${username}"`);

      setStep('generating');
      log('crypto', 'Generating RSA-2048 key pair via Web Crypto API (in browser RAM)…');
      const keyPair   = await generateKeyPair();
      const publicPem = await exportPublicKeyPEM(keyPair.publicKey);
      log('ram',  'RSA-2048 key pair created — both keys exist only in RAM so far');
      log('info', 'Public key exported to PEM format for server registration');

      setStep('encrypting');
      await encryptAndStorePrivateKey(username, keyPair.privateKey, log);

      log('network', 'Sending public key PEM to server /register endpoint…');
      const result = await Api.registerUser(username, publicPem);

      if (result.status === 'REGISTERED') {
        log('success', `User "${username}" registered on server. Public key stored in DB.`);
        log('info', 'Summary: Private key = encrypted in localStorage. Public key = on server. MasterKey = nowhere.');

        // Store QR data — show TOTP setup screen before switching to login
        if (result.totp_qr)     setTotpQR(result.totp_qr);
        if (result.totp_secret) setTotpSecret(result.totp_secret);
        setStep('success');
        const registrationTimeSec = (performance.now() - registrationStart) / 1000;
        console.log(`[METRIC] Registration Time: ${registrationTimeSec.toFixed(2)} sec`);

      } else if (result.status === 'EXISTS') {
        deleteStoredKey(username);
        log('warning', 'Username already exists on server — local key bundle deleted');
        setStep('idle');
        setErrorMessage('Username already exists. Try logging in.');
      } else {
        log('error', 'Server registration failed: ' + JSON.stringify(result));
        setStep('failed');
        setErrorMessage('Backend registration failed.');
      }
    } catch (err: any) {
      log('error', 'Registration exception: ' + err.message);
      setStep('failed');
      setErrorMessage('Registration error. See console.');
    }
  };

  // ─── User Login ────────────────────────────────────────────────────────────
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    clear();
    const loginStart = performance.now();

    if (!username.trim()) { setErrorMessage('Enter your username.'); return; }

    if (!hasStoredKey(username)) {
      setErrorMessage('No key found for that username on this device. Register first, or use your original device.');
      log('warning', `No localStorage key bundle found for "${username}" on this device`);
      return;
    }

    try {
      log('info', `Starting authentication for user "${username}"${isStepUp ? ` (step-up for ${stepUpOperation})` : ''}`);

      setStep('requesting');
      log('network', 'Requesting challenge nonce from server /challenge endpoint…');
      const nonceResponse = await Api.getLoginNonce(username);

      if (!nonceResponse.nonce) {
        log('error', 'Server returned no nonce — user may not exist in DB');
        setStep('failed');
        setErrorMessage('User not found on server.');
        return;
      }
      log('network', 'Server nonce received', `nonce=${nonceResponse.nonce.slice(0, 16)}…`);

      setStep('decrypting');
      await new Promise(r => setTimeout(r, 200));

      setStep('signing');
      const signature = await decryptAndSign(username, nonceResponse.nonce, log);

      setStep('verifying');
      log('network', 'Sending RSA-PSS signature to server /login for verification…');
      const result = await Api.verifyLogin(username, signature);

      if (result.status === 'SUCCESS') {
        log('success', 'Server verified signature against stored public key — ACCESS GRANTED');
        log('ram', 'All ephemeral key material has been garbage collected by browser');
        setStep('success');
        setTimeout(() => onLoginSuccess(username), 1200);
      } else {
        log('error', 'Server rejected signature — wrong key or tampered nonce');
        setStep('failed');
        setErrorMessage('Invalid signature or expired nonce.');
      }
      const loginEnd = performance.now();
      console.log(`[METRIC] Total Login Latency: ${(loginEnd - loginStart).toFixed(2)} ms`);
    } catch (err: any) {
      log('error', 'Authentication exception: ' + err.message);
      setStep('failed');
      setErrorMessage(err.message ?? 'Authentication error.');
      const loginEnd = performance.now();
      console.log(`[METRIC] Total Login Latency: ${(loginEnd - loginStart).toFixed(2)} ms`);
    }
  };

  // ─── Admin Login ───────────────────────────────────────────────────────────
  const handleAdminLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdminError('');
    setAdminLoading(true);
    try {
      const result = await Api.adminLogin(adminUser, adminPass);
      if (result.status === 'SUCCESS' && result.token) {
        onAdminSuccess(result.token);
      } else {
        setAdminError('Invalid admin credentials.');
      }
    } catch {
      setAdminError('Could not reach server.');
    } finally {
      setAdminLoading(false);
    }
  };

  const stepLabel: Record<string, string> = {
    generating: '🔑 Generating RSA-2048 Key Pair…',
    encrypting: '🔒 Encrypting Key with Device Fingerprint…',
    requesting: '📡 Requesting Server Challenge Nonce…',
    decrypting: '🔓 Re-deriving Master Key from Device…',
    signing:    '✍️  Signing Nonce in Memory…',
    verifying:  '🔍 Verifying Signature with Server…',
    success:    activeTab === 'register' ? '✅ Registered — Key Secured on this Device' : '✅ Access Granted',
    failed:     '❌ Failed',
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 p-4 pb-72">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-xl overflow-hidden">

        {/* Header */}
        <div className="bg-slate-900 p-8 text-white text-center">
          <div className="inline-block p-3 bg-blue-600 rounded-xl mb-4">
            <ShieldCheck size={32} />
          </div>
          <h1 className="text-2xl font-bold">SecureBank Demo</h1>
          <p className="text-slate-400 text-sm mt-1">
            {isStepUp
              ? `⚠️ Step-Up Required — Re-authenticate to continue ${stepUpOperation}`
              : 'Device-Bound Key Authentication'}
          </p>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-slate-200">
          {(['login', 'register', 'admin'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => {
                setActiveTab(tab);
                setStep('idle');
                setErrorMessage('');
                setAdminError('');
              }}
              className={`flex-1 py-3 text-xs font-semibold capitalize transition-colors ${
                activeTab === tab
                  ? 'border-b-2 border-blue-600 text-blue-600'
                  : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              {tab === 'login' ? '🔐 Login' : tab === 'register' ? '📝 Register' : '🛡️ Admin'}
            </button>
          ))}
        </div>

        <div className="p-8">

          {/* ── Status overlay (user flows only) ── */}
          {step !== 'idle' && activeTab !== 'admin' && (

            // ── TOTP Setup Screen (shown after registration success) ──────────
            step === 'success' && activeTab === 'register' && totpQR ? (
              <div className="space-y-5 text-center">
                <div className="inline-block p-3 bg-emerald-100 text-emerald-600 rounded-full">
                  <ShieldCheck size={36} />
                </div>
                <div>
                  <p className="font-bold text-slate-800 text-lg">One last step — set up your authenticator</p>
                  <p className="text-slate-500 text-sm mt-1">
                    Scan this QR with <strong>Google Authenticator</strong> (or any TOTP app).
                    You'll need it every time a high-risk operation triggers step-up.
                  </p>
                </div>

                {/* QR Code */}
                <div className="flex justify-center p-4 bg-white border-2 border-slate-200 rounded-2xl">
                  <img
                    src={`data:image/svg+xml;base64,${totpQR}`}
                    alt="TOTP QR Code"
                    className="w-52 h-52"
                  />
                </div>

                {/* Backup text code */}
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                  <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                    Can't scan? Enter this key manually in your app:
                  </p>
                  <p className="font-mono text-sm font-bold text-slate-700 tracking-widest break-all">
                    {totpSecret}
                  </p>
                </div>

                <div className="p-3 bg-amber-50 border border-amber-100 rounded-xl text-xs text-amber-700 text-left flex items-start gap-2">
                  <span className="text-base shrink-0">⚠️</span>
                  <span>
                    <strong>Save this code somewhere safe.</strong> If you lose access to your
                    authenticator app, you won't be able to complete step-up.
                    This QR will not be shown again.
                  </span>
                </div>

                <button
                  onClick={() => {
                    setStep('idle');
                    setActiveTab('login');
                    setTotpQR(null);
                    setTotpSecret(null);
                  }}
                  className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-4 rounded-lg transition-colors"
                >
                  ✅ I've saved my code — Go to Login
                </button>
              </div>

            ) : (
              // ── Generic step progress overlay ──────────────────────────────
              <div className="text-center py-8 space-y-6">
                {step === 'success' ? (
                  <div className="inline-block p-4 bg-emerald-100 text-emerald-600 rounded-full">
                    <ShieldCheck size={48} />
                  </div>
                ) : step === 'failed' ? (
                  <div className="inline-block p-4 bg-rose-100 text-rose-600 rounded-full">
                    <ShieldAlert size={48} />
                  </div>
                ) : (
                  <Loader2 className="animate-spin text-blue-600 w-16 h-16 mx-auto" />
                )}
                <p className="font-semibold text-lg text-slate-800">{stepLabel[step]}</p>
                {errorMessage && <p className="text-sm text-rose-600">{errorMessage}</p>}
                {step === 'failed' && (
                  <button
                    onClick={() => { setStep('idle'); setErrorMessage(''); }}
                    className="px-6 py-2 border border-slate-300 rounded-full text-slate-600 hover:bg-slate-50"
                  >
                    Try Again
                  </button>
                )}
              </div>
            )
          )}

          {/* ── LOGIN FORM ── */}
          {step === 'idle' && activeTab === 'login' && (
            <form onSubmit={handleLogin} className="space-y-5">

              {isStepUp && (
                <div className="flex items-start gap-3 p-3 bg-amber-50 border border-amber-200 rounded-lg">
                  <ShieldHalf size={16} className="text-amber-600 shrink-0 mt-0.5" />
                  <p className="text-xs text-amber-700 font-medium">
                    Your <strong>{stepUpOperation}</strong> operation requires re-authentication.
                    Log in again to continue.
                  </p>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">Username</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                  <input
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="Your username"
                    className="w-full pl-10 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
              </div>

              <button
                type="button"
                onClick={() => setShowFingerprint(f => !f)}
                className="w-full flex items-start gap-3 p-3 bg-blue-50 border border-blue-100 rounded-lg text-left hover:bg-blue-100 transition-colors"
              >
                <Lock size={16} className="text-blue-500 mt-0.5 shrink-0" />
                <div className="text-xs text-blue-700">
                  <p className="font-semibold">Device-Bound — No PEM File Required</p>
                  <p className="mt-0.5 text-blue-600">
                    Your key is encrypted with a master key derived from this device's fingerprint. Tap to reveal.
                  </p>
                  {showFingerprint && (
                    <p className="mt-2 font-mono text-[10px] text-blue-400 break-all">
                      SHA-256: {fingerprintHash}
                    </p>
                  )}
                </div>
              </button>

              {errorMessage && <p className="text-sm text-rose-600">{errorMessage}</p>}

              <button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 rounded-lg transition-colors"
              >
                {isStepUp ? 'Re-Authenticate & Continue' : 'Authenticate Securely'}
              </button>
            </form>
          )}

          {/* ── REGISTER FORM ── */}
          {step === 'idle' && activeTab === 'register' && (
            <div className="space-y-5">
              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">Choose Username</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                  <input
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="Pick a username"
                    className="w-full pl-10 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 divide-y divide-slate-100 text-sm">
                {[
                  { icon: '🔑', title: 'RSA-2048 Key Pair Generated',         sub: 'Web Crypto API — in browser RAM only' },
                  { icon: '🔒', title: 'Private Key Encrypted (AES-256-GCM)', sub: 'MasterKey = PBKDF2(device fingerprint + random salt)' },
                  { icon: '💾', title: 'Encrypted Bundle → localStorage',     sub: 'No .pem download, no plaintext on disk' },
                  { icon: '🌐', title: 'Public Key → Server DB',              sub: 'Used to verify RSA-PSS signatures at login' },
                  { icon: '📱', title: 'TOTP Secret Generated',               sub: 'QR code shown once — scan with Google Authenticator' },
                ].map(item => (
                  <div key={item.title} className="flex items-start gap-3 p-3">
                    <span className="text-lg">{item.icon}</span>
                    <div>
                      <p className="font-medium text-slate-700">{item.title}</p>
                      <p className="text-slate-400 text-xs mt-0.5">{item.sub}</p>
                    </div>
                  </div>
                ))}
              </div>

              {errorMessage && <p className="text-sm text-rose-600">{errorMessage}</p>}

              <button
                onClick={handleRegister}
                className="w-full bg-slate-800 hover:bg-slate-900 text-white font-bold py-4 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <KeyRound size={18} />
                Generate &amp; Secure My Keys
              </button>
            </div>
          )}

          {/* ── ADMIN LOGIN FORM ── */}
          {activeTab === 'admin' && (
            <form onSubmit={handleAdminLogin} className="space-y-5">

              <div className="flex items-start gap-3 p-3 bg-amber-50 border border-amber-100 rounded-lg">
                <ShieldHalf size={16} className="text-amber-600 shrink-0 mt-0.5" />
                <p className="text-xs text-amber-700 font-medium">
                  Admin access only. Password-based — no device key required.
                  Grants access to hash-chain audit inspector and tamper simulator.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">Admin Username</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                  <input
                    type="text"
                    value={adminUser}
                    onChange={e => setAdminUser(e.target.value)}
                    placeholder="admin"
                    className="w-full pl-10 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-amber-500"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                  <input
                    type="password"
                    value={adminPass}
                    onChange={e => setAdminPass(e.target.value)}
                    placeholder="••••••••"
                    className="w-full pl-10 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-amber-500"
                    required
                  />
                </div>
              </div>

              {adminError && <p className="text-sm text-rose-600">{adminError}</p>}

              <button
                type="submit"
                disabled={adminLoading}
                className="w-full bg-amber-600 hover:bg-amber-700 text-white font-bold py-4 rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-60"
              >
                {adminLoading ? <Loader2 size={18} className="animate-spin" /> : <ShieldHalf size={18} />}
                Enter Admin Console
              </button>
            </form>
          )}

        </div>
      </div>
    </div>
  );
};

export default Login;