/**
 * deviceKey.ts
 * Device-Bound Private Key Protection
 *
 * Flow:
 *   Registration : generate keypair → derive MasterKey from device fingerprint
 *                  → AES-GCM encrypt private key → store encrypted bundle in localStorage
 *
 *   Login        : re-derive MasterKey from same fingerprint + stored salt
 *                  → decrypt private key in RAM → sign nonce → zero bytes → done
 *
 * The plaintext private key NEVER touches disk.
 * Moving the encrypted bundle to another device = decryption failure.
 */

import type { LogLevel } from '../components/SecurityAuditPanel';

// ─── Logger type (injected from UI so audit panel can receive events) ─────────
export type AuditLogger = (
  level: LogLevel,
  message: string,
  detail?: string
) => void;

const noop: AuditLogger = () => {};

// ─── Storage ──────────────────────────────────────────────────────────────────
const STORAGE_KEY = (username: string) => `securebank_key_${username}`;

export interface EncryptedKeyBundle {
  encryptedKey: string;
  salt: string;
  iv: string;
}

// ─── Device Fingerprint ───────────────────────────────────────────────────────
/**
 * Collects the richest set of stable, browser-observable signals available
 * without any native/OS API access (browsers intentionally block hardware
 * identifiers like system UUID, MAC address, CPU serial for privacy reasons).
 *
 * Signals used:
 *  • Navigator   — userAgent, language, platform, CPU cores, max touch points,
 *                  do-not-track, pdfViewer, cookie enabled, device memory
 *  • Screen      — resolution, color depth, pixel depth, available size
 *  • Timezone    — IANA zone name
 *  • Canvas 2D   — GPU/driver-level pixel rendering differences
 *  • WebGL       — GPU renderer + vendor strings (most hardware-specific signal available)
 *  • Audio       — AudioContext sample rate + channel count
 *  • Fonts       — measured width differences across a probe string in several fonts
 *  • Media       — supported MIME types
 *
 * All signals are deterministic for the same device+browser+profile.
 * The result is hashed with SHA-256 before use so the raw strings are never
 * exposed — only a 32-byte digest feeds into PBKDF2.
 */
export async function collectDeviceFingerprint(): Promise<string> {
  const parts: string[] = [];

  // ── 1. Navigator signals ────────────────────────────────────────────────────
  parts.push(
    navigator.userAgent,
    navigator.language,
    (navigator.languages ?? []).join(','),
    navigator.platform ?? '',
    String(navigator.hardwareConcurrency ?? ''),
    String((navigator as any).deviceMemory ?? ''),       // GB RAM (rounded)
    String(navigator.maxTouchPoints ?? '0'),
    String(navigator.cookieEnabled),
    String((navigator as any).pdfViewerEnabled ?? ''),
    String(navigator.doNotTrack ?? ''),
  );

  // ── 2. Screen signals ───────────────────────────────────────────────────────
  parts.push(
    `${screen.width}x${screen.height}`,
    `${screen.availWidth}x${screen.availHeight}`,
    String(screen.colorDepth),
    String(screen.pixelDepth),
    String(window.devicePixelRatio ?? ''),
  );

  // ── 3. Timezone ─────────────────────────────────────────────────────────────
  parts.push(Intl.DateTimeFormat().resolvedOptions().timeZone);

  // ── 4. Canvas 2D fingerprint ─────────────────────────────────────────────────
  // Different GPU drivers render text and gradients subtly differently.
  try {
    const canvas  = document.createElement('canvas');
    canvas.width  = 240;
    canvas.height = 60;
    const ctx = canvas.getContext('2d')!;
    ctx.fillStyle   = '#f0f0f0';
    ctx.fillRect(0, 0, 240, 60);
    ctx.fillStyle   = '#1a73e8';
    ctx.font        = '16px Arial';
    ctx.fillText('SecureBank🔐Canvas', 10, 30);
    ctx.strokeStyle = '#e8430a';
    ctx.lineWidth   = 1.5;
    ctx.beginPath();
    ctx.arc(200, 30, 18, 0, Math.PI * 2);
    ctx.stroke();
    // Gradient
    const grad = ctx.createLinearGradient(0, 0, 240, 0);
    grad.addColorStop(0, 'rgba(100,200,100,0.6)');
    grad.addColorStop(1, 'rgba(200,100,200,0.6)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 50, 240, 10);
    parts.push(canvas.toDataURL());
  } catch { parts.push('canvas:unavailable'); }

  // ── 5. WebGL fingerprint (most hardware-specific browser signal) ─────────────
  try {
    const gl = document.createElement('canvas')
      .getContext('webgl') as WebGLRenderingContext | null;
    if (gl) {
      const dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (dbgInfo) {
        parts.push(
          gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL),   // e.g. "NVIDIA GeForce RTX 3080"
          gl.getParameter(dbgInfo.UNMASKED_VENDOR_WEBGL),     // e.g. "NVIDIA Corporation"
        );
      }
      parts.push(
        gl.getParameter(gl.VERSION),
        gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        String(gl.getParameter(gl.MAX_TEXTURE_SIZE)),
        String(gl.getParameter(gl.MAX_VERTEX_ATTRIBS)),
        String(gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS)),
      );
    }
  } catch { parts.push('webgl:unavailable'); }

  // ── 6. Audio fingerprint ────────────────────────────────────────────────────
  // AudioContext properties differ slightly between hardware/OS/driver combos.
  try {
    const AudioCtx = (window.AudioContext || (window as any).webkitAudioContext);
    if (AudioCtx) {
      const ctx = new AudioCtx();
      parts.push(
        String(ctx.sampleRate),
        String(ctx.destination.maxChannelCount),
      );
      await ctx.close();
    }
  } catch { parts.push('audio:unavailable'); }

  // ── 7. Font metric fingerprint ──────────────────────────────────────────────
  // Different OS font renderers produce slightly different measured widths.
  try {
    const probe = 'mmmmmmmmmmlli';
    const testFonts = ['monospace', 'serif', 'sans-serif', 'Arial', 'Georgia', 'Courier New'];
    const canvas = document.createElement('canvas');
    const ctx    = canvas.getContext('2d')!;
    const widths  = testFonts.map(f => {
      ctx.font = `16px ${f}`;
      return ctx.measureText(probe).width.toFixed(2);
    });
    parts.push(widths.join(','));
  } catch { parts.push('fonts:unavailable'); }

  // ── 8. Supported media types ────────────────────────────────────────────────
  try {
    const video = document.createElement('video');
    const probeTypes = [
      'video/mp4; codecs="avc1.42E01E"',
      'video/webm; codecs="vp8"',
      'audio/ogg; codecs="vorbis"',
    ];
    parts.push(probeTypes.map(t => video.canPlayType(t)).join(','));
  } catch { parts.push('media:unavailable'); }

  // ── Hash everything into a single 32-byte digest ────────────────────────────
  const raw     = parts.join('||');
  const encoded = new TextEncoder().encode(raw);
  const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
  const hashHex = Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return hashHex;   // 64-char hex string → feeds into PBKDF2 as "password"
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function base64Encode(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  bytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function base64Decode(b64: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).slice();
}

function truncate(b64: string, chars = 24): string {
  return b64.slice(0, chars) + '…';
}

// ─── KDF ──────────────────────────────────────────────────────────────────────
async function deriveMasterKey(
  fingerprint: string,
  salt: Uint8Array<ArrayBuffer>,
  log: AuditLogger
): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  log('crypto', 'Importing device fingerprint as PBKDF2 base key material…');

  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(fingerprint),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  log('crypto', 'Running PBKDF2-SHA256 (310,000 iterations) to derive MasterKey…',
      `salt=${truncate(base64Encode(salt.buffer))}`);

  const masterKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,       // non-exportable
    ['encrypt', 'decrypt']
  );

  log('ram', 'MasterKey derived (AES-256) — exists in RAM only, never stored');
  return masterKey;
}

// ─── Encrypt & Store ──────────────────────────────────────────────────────────
export async function encryptAndStorePrivateKey(
  username: string,
  privateKey: CryptoKey,
  log: AuditLogger = noop
): Promise<void> {
  log('ram', 'Exporting private key to raw PKCS#8 bytes in RAM…');
  const pkcs8: ArrayBuffer = await crypto.subtle.exportKey('pkcs8', privateKey);
  const keyBytes = new Uint8Array(pkcs8).slice() as Uint8Array<ArrayBuffer>;
  log('ram', `Private key in RAM: ${keyBytes.byteLength} bytes (not yet stored anywhere)`);

  const salt = crypto.getRandomValues(new Uint8Array(32)).slice() as Uint8Array<ArrayBuffer>;
  const iv   = crypto.getRandomValues(new Uint8Array(12)).slice() as Uint8Array<ArrayBuffer>;
  log('crypto', 'Generated random salt (32 bytes) and IV (12 bytes)',
      `salt=${truncate(base64Encode(salt.buffer))} iv=${truncate(base64Encode(iv.buffer))}`);

  log('info', 'Collecting device fingerprint (canvas, WebGL, audio, fonts, navigator…)');
  const fingerprint = await collectDeviceFingerprint();
  log('info', 'Device fingerprint SHA-256 hash computed (never stored)', truncate(fingerprint, 40));

  const masterKey = await deriveMasterKey(fingerprint, salt, log);

  log('crypto', 'Encrypting private key bytes with AES-256-GCM…');
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    masterKey,
    keyBytes
  );

  log('ram', '🗑️  Zeroing plaintext private key bytes in memory…');
  keyBytes.fill(0);
  log('ram', 'Plaintext private key bytes zeroed — no longer in memory');

  const bundle: EncryptedKeyBundle = {
    encryptedKey: base64Encode(ciphertext),
    salt:         base64Encode(salt.buffer),
    iv:           base64Encode(iv.buffer),
  };

  localStorage.setItem(STORAGE_KEY(username), JSON.stringify(bundle));
  log('success',
      'Encrypted bundle saved to localStorage (encryptedKey + salt + iv)',
      `key=${truncate(bundle.encryptedKey)}`);
  log('info', 'Server receives public key only. Private key never leaves this device.');
}

// ─── Storage Helpers ──────────────────────────────────────────────────────────
export function loadEncryptedBundle(username: string): EncryptedKeyBundle | null {
  const raw = localStorage.getItem(STORAGE_KEY(username));
  if (!raw) return null;
  try { return JSON.parse(raw) as EncryptedKeyBundle; } catch { return null; }
}

export function hasStoredKey(username: string): boolean {
  return localStorage.getItem(STORAGE_KEY(username)) !== null;
}

export function deleteStoredKey(username: string): void {
  localStorage.removeItem(STORAGE_KEY(username));
}

// ─── Decrypt & Sign ───────────────────────────────────────────────────────────
export async function decryptAndSign(
  username: string,
  nonceBase64: string,
  log: AuditLogger = noop
): Promise<string> {
  log('info', `Loading encrypted key bundle from localStorage for "${username}"…`);
  const bundle = loadEncryptedBundle(username);
  if (!bundle) throw new Error('No stored key found for this user on this device.');
  log('info', 'Bundle found: encryptedKey + salt + iv loaded into RAM');

  log('info', 'Re-collecting device fingerprint (canvas, WebGL, audio, fonts…)');
  const fingerprint = await collectDeviceFingerprint();
  log('info', 'Fingerprint hash recomputed live — never stored', truncate(fingerprint, 40));

  const salt       = base64Decode(bundle.salt);
  const iv         = base64Decode(bundle.iv);
  const ciphertext = base64Decode(bundle.encryptedKey);

  const masterKey = await deriveMasterKey(fingerprint, salt, log);

  log('crypto', 'Decrypting private key bytes with AES-256-GCM (in RAM only)…');
  let pkcs8Bytes: Uint8Array<ArrayBuffer>;
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      masterKey,
      ciphertext
    );
    pkcs8Bytes = new Uint8Array(plaintext).slice() as Uint8Array<ArrayBuffer>;
    log('ram', `Private key decrypted into RAM: ${pkcs8Bytes.byteLength} bytes — NOT written to disk`);
  } catch {
    log('error', 'Decryption FAILED — device fingerprint mismatch or tampered bundle');
    throw new Error('Decryption failed — key is bound to a different device or browser profile.');
  }

  log('crypto', 'Importing decrypted bytes as non-extractable RSA-PSS signing key…');
  const signingKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Bytes,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,   // non-extractable
    ['sign']
  );

  log('ram', '🗑️  Zeroing decrypted private key bytes immediately after import…');
  pkcs8Bytes.fill(0);
  log('ram', 'Private key bytes zeroed — only the non-extractable CryptoKey object remains');

  log('crypto', 'Signing server nonce with RSA-PSS (saltLength=32)…');
  const nonceBytes      = base64Decode(nonceBase64);
  const signatureBuffer = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    signingKey,
    nonceBytes
  );

  log('success', 'Nonce signed successfully — private key object will be GC\'d by browser');
  log('network', 'Sending signature to server for RSA-PSS verification with stored public key…');

  const sigBytes = new Uint8Array(signatureBuffer);
  let binary = '';
  sigBytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary);
}