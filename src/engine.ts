import { canonicalizeCore } from './jcs.js';
import {
  sha256,
  sha256Hex,
  bytesToHex,
  base64urlEncode,
  base64urlDecode,
  ed25519Sign,
  ed25519Verify,
} from './crypto.js';
import {
  MalformedReceipt,
  ReceiptIdMismatch,
  InvalidSignature,
} from './errors.js';
import type { SarCore, SarReceipt, SignOpts, KeyResolver } from './types.js';

/**
 * Derive the receipt_id from core fields.
 *
 * Algorithm:
 *   1. JCS-canonicalize the 6 core fields (RFC 8785)
 *   2. SHA-256 the canonical bytes
 *   3. Return "sha256:<hex>"
 */
export function deriveReceiptId(core: SarCore): string {
  const coreBytes = canonicalizeCore(core);
  return 'sha256:' + sha256Hex(coreBytes);
}

/**
 * Sign core fields and produce a complete SarReceipt.
 *
 * Signs the 32-byte SHA-256 digest of the JCS-canonicalized core
 * with the provided Ed25519 private key.
 */
export async function signReceipt(
  core: SarCore,
  opts: SignOpts,
): Promise<SarReceipt> {
  const coreBytes = canonicalizeCore(core);
  const digest = sha256(coreBytes);
  const receiptId = 'sha256:' + bytesToHex(digest);
  const sigBytes = await ed25519Sign(digest, opts.privateKey);

  return {
    receipt_version: opts.receipt_version ?? '0.1',
    receipt_id: receiptId,
    task_id_hash: core.task_id_hash,
    verdict: core.verdict,
    confidence: core.confidence,
    reason_code: core.reason_code,
    ts: core.ts,
    verifier_kid: core.verifier_kid,
    sig_alg: 'Ed25519',
    sig: 'base64url:' + base64urlEncode(sigBytes),
    ...(opts._ext && { _ext: opts._ext }),
    ...(opts._perf && { _perf: opts._perf }),
  };
}

const REQUIRED_RECEIPT_FIELDS = [
  'receipt_version',
  'receipt_id',
  'task_id_hash',
  'verdict',
  'confidence',
  'reason_code',
  'ts',
  'verifier_kid',
  'sig_alg',
  'sig',
] as const;

/**
 * Verify a SAR receipt.
 *
 * 1. Validate receipt shape
 * 2. Recompute receipt_id from core fields
 * 3. Compare receipt_id (throws ReceiptIdMismatch on mismatch)
 * 4. Resolve public key via resolveKey(kid)
 * 5. Verify Ed25519 signature over SHA-256 digest (throws InvalidSignature)
 *
 * Unknown reason_codes are non-fatal.
 * Returns true on success.
 */
export async function verifyReceipt(
  receipt: SarReceipt,
  resolveKey: KeyResolver,
): Promise<true> {
  // 1. Validate receipt shape
  if (receipt === null || typeof receipt !== 'object') {
    throw new MalformedReceipt('Receipt must be an object');
  }
  for (const field of REQUIRED_RECEIPT_FIELDS) {
    if (!(field in receipt)) {
      throw new MalformedReceipt(`Missing required field: ${field}`);
    }
  }
  if (receipt.receipt_version !== '0.1') {
    throw new MalformedReceipt(
      `Unsupported receipt_version: ${receipt.receipt_version}`,
    );
  }
  if (!/^sha256:[0-9a-fA-F]{64}$/.test(receipt.receipt_id)) {
    throw new MalformedReceipt(
      'receipt_id must be "sha256:" followed by 64 hex characters',
    );
  }
  if (
    !Number.isFinite(receipt.confidence) ||
    receipt.confidence < 0 ||
    receipt.confidence > 1
  ) {
    throw new MalformedReceipt(
      `confidence must be a finite number in [0, 1], got ${receipt.confidence}`,
    );
  }
  if (receipt.sig_alg !== 'Ed25519') {
    throw new MalformedReceipt(`Unsupported sig_alg: ${receipt.sig_alg}`);
  }
  if (!receipt.sig.startsWith('base64url:')) {
    throw new MalformedReceipt('sig must start with "base64url:" prefix');
  }

  // 2. Extract core and recompute receipt_id
  const core: SarCore = {
    task_id_hash: receipt.task_id_hash,
    verdict: receipt.verdict,
    confidence: receipt.confidence,
    reason_code: receipt.reason_code,
    ts: receipt.ts,
    verifier_kid: receipt.verifier_kid,
  };
  const coreBytes = canonicalizeCore(core);
  const digest = sha256(coreBytes);
  const expectedReceiptId = 'sha256:' + bytesToHex(digest);

  // 3. Compare receipt_id
  if (receipt.receipt_id !== expectedReceiptId) {
    throw new ReceiptIdMismatch(expectedReceiptId, receipt.receipt_id);
  }

  // 4. Resolve public key
  const pubKey = await resolveKey(receipt.verifier_kid);

  // 5. Verify Ed25519 signature over the 32-byte digest
  const sigB64 = receipt.sig.slice('base64url:'.length);
  const sigBytes = base64urlDecode(sigB64);
  const valid = await ed25519Verify(sigBytes, digest, pubKey);
  if (!valid) {
    throw new InvalidSignature();
  }

  return true;
}

// Re-export canonicalizeCore for public API
export { canonicalizeCore } from './jcs.js';
