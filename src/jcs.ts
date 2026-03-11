import canonicalize from 'canonicalize';
import { MalformedReceipt } from './errors.js';
import type { SarCore } from './types.js';

const CORE_KEYS: ReadonlySet<string> = new Set([
  'task_id_hash',
  'verdict',
  'confidence',
  'reason_code',
  'ts',
  'verifier_kid',
]);

/** Returns true if value is a plain object (not from a foreign prototype). */
function isPlainObject(val: unknown): val is Record<string, unknown> {
  if (val === null || typeof val !== 'object' || Array.isArray(val)) return false;
  const proto = Object.getPrototypeOf(val);
  return proto === Object.prototype || proto === null;
}

/**
 * Validate and extract a safe, plain-object clone of the SarCore fields.
 * Rejects non-plain objects to defend against prototype pollution.
 */
export function safeCoreClone(core: SarCore): SarCore {
  if (!isPlainObject(core)) {
    throw new MalformedReceipt('Core must be a plain object');
  }
  for (const key of CORE_KEYS) {
    if (!(key in core)) {
      throw new MalformedReceipt(`Missing required core field: ${key}`);
    }
  }
  // Deep-clone via JSON round-trip to strip prototype chain
  return JSON.parse(JSON.stringify({
    task_id_hash: core.task_id_hash,
    verdict: core.verdict,
    confidence: core.confidence,
    reason_code: core.reason_code,
    ts: core.ts,
    verifier_kid: core.verifier_kid,
  })) as SarCore;
}

/**
 * JCS-canonicalize (RFC 8785) the core fields and return UTF-8 bytes.
 * Only the 6 core fields are included — never receipt_version, receipt_id,
 * sig_alg, sig, _perf, or _ext.
 */
export function canonicalizeCore(core: SarCore): Uint8Array {
  const safe = safeCoreClone(core);
  const json = canonicalize(safe);
  if (json === undefined) {
    throw new MalformedReceipt('JCS canonicalization returned undefined');
  }
  return new TextEncoder().encode(json);
}
