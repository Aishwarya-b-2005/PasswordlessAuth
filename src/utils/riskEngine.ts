/**
 * riskEngine.ts
 * Client-Side Risk Context Collector
 *
 * Gathers behavioral + contextual signals BEFORE each operation request.
 * These signals are sent to the server alongside the nonce request so the
 * server's Risk Policy Engine can score them and decide: ALLOW / STEP_UP / DENY.
 *
 * ⚠️  None of these signals are individually definitive.
 *      The server combines them with historical baselines to produce a score.
 */

/**
 * riskEngine.ts
 * Client-Side Risk Context Collector
 *
 * Gathers behavioral + contextual signals BEFORE each operation request.
 * These signals are sent to the server alongside the nonce request so the
 * server's Risk Policy Engine can score them and decide: ALLOW / STEP_UP / DENY.
 *
 * FIX: collectRiskContext() is now async and calls collectDeviceFingerprint()
 * from deviceKey.ts directly — so deviceFingerprint is always the same
 * SHA-256 hex digest that was used to encrypt/decrypt the private key.
 * Previously riskEngine built its own plain-string fingerprint which NEVER
 * matched the hash, making the server's device-mismatch check useless.
 */

import { collectDeviceFingerprint } from './deviceKey';

export interface RiskContext {
  // ── Device ──────────────────────────────────────────────────────────────
  deviceFingerprint: string;        // SHA-256 hex — identical to deviceKey.ts
  screenResolution: string;
  timezone: string;
  language: string;
  platform: string;
  hardwareConcurrency: number;
  colorDepth: number;

  // ── Session ──────────────────────────────────────────────────────────────
  sessionAgeMs: number;
  previousOperationsCount: number;
  lastOperationTimestamp: number | null;

  // ── Behavioural ──────────────────────────────────────────────────────────
  timeOnPageMs: number;
  mouseMovementDetected: boolean;
  keyboardInteractionDetected: boolean;

  // ── Network ──────────────────────────────────────────────────────────────
  connectionType: string;

  // ── Operation ────────────────────────────────────────────────────────────
  operationType: string;
  targetResource?: string;
  amount?: number;

  // ── Timestamp ────────────────────────────────────────────────────────────
  collectedAt: string;
}

// ─── Session State ────────────────────────────────────────────────────────────
const SESSION_START = Date.now();
let operationCount = 0;
let lastOpTime: number | null = null;

export function recordOperation() {
  operationCount++;
  lastOpTime = Date.now();
}

// ─── Behavioural Probes ───────────────────────────────────────────────────────
let _mouseMovedSincePageLoad   = false;
let _keyboardUsedSincePageLoad = false;
const _pageLoadTime            = Date.now();

if (typeof window !== 'undefined') {
  window.addEventListener('mousemove', () => { _mouseMovedSincePageLoad   = true; }, { once: true });
  window.addEventListener('keydown',   () => { _keyboardUsedSincePageLoad = true; }, { once: true });
}

// ─── Public Collector (now async — awaits the real SHA-256 fingerprint) ───────
export async function collectRiskContext(
  operationType: string,
  targetResource?: string,
  amount?: number
): Promise<RiskContext> {
  const nav = navigator as any;

  // Use the SAME collectDeviceFingerprint() as deviceKey.ts
  // This returns the SHA-256 hex digest — exactly what the server's
  // device-mismatch check should be comparing against.
  const deviceFingerprint = await collectDeviceFingerprint();

  return {
    // Device
    deviceFingerprint,                              // ← now a real SHA-256 hash
    screenResolution: `${screen.width}x${screen.height}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: nav.language,
    platform: nav.platform ?? 'unknown',
    hardwareConcurrency: nav.hardwareConcurrency ?? 0,
    colorDepth: screen.colorDepth,

    // Session
    sessionAgeMs: Date.now() - SESSION_START,
    previousOperationsCount: operationCount,
    lastOperationTimestamp: lastOpTime,

    // Behavioural
    timeOnPageMs: Date.now() - _pageLoadTime,
    mouseMovementDetected: _mouseMovedSincePageLoad,
    keyboardInteractionDetected: _keyboardUsedSincePageLoad,

    // Network
    connectionType: nav.connection?.effectiveType ?? 'unknown',

    // Operation
    operationType,
    targetResource,
    amount,

    collectedAt: new Date().toISOString(),
  };
}