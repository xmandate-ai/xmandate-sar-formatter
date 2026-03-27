/** SAR v0.1 verdict values. */
export type Verdict = 'PASS' | 'FAIL' | 'INDETERMINATE';

/**
 * Core fields used for receipt_id derivation and signing.
 * These are the ONLY fields included in the JCS-canonicalized hash.
 */
export interface SarCore {
  task_id_hash: string;
  verdict: Verdict;
  confidence: number;
  reason_code: string;
  ts: string;
  verifier_kid: string;
}

/** Full SAR receipt (signed, with metadata). */
export interface SarReceipt extends SarCore {
  receipt_version: string;
  receipt_id: string;
  sig_alg: string;
  sig: string;
  counterparty?: string;
  _perf?: Record<string, number>;
  _ext?: Record<string, unknown>;
}

/** A single key entry in the JWKS-style SAR keys document. */
export interface SarKeyEntry {
  kid: string;
  kty: string;
  crv: string;
  x: string;
  created?: string;
}

/** JWKS-style document served at /.well-known/sar-keys.json */
export interface SarKeysDocument {
  keys: SarKeyEntry[];
}

/** Options for signReceipt. */
export interface SignOpts {
  privateKey: Uint8Array;
  receipt_version?: '0.1' | '0.2';
  counterparty?: string;
  _ext?: Record<string, unknown>;
  _perf?: Record<string, number>;
}

/** Key resolver function for offline verification. */
export type KeyResolver = (kid: string) => Promise<Uint8Array> | Uint8Array;
