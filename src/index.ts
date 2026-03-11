// SAR v0.1 types
export type {
  Verdict,
  SarCore,
  SarReceipt,
  SarKeyEntry,
  SarKeysDocument,
  SignOpts,
  KeyResolver,
} from './types.js';

// Error classes
export {
  MalformedReceipt,
  ReceiptIdMismatch,
  KeyNotFound,
  InvalidSignature,
} from './errors.js';

// Engine (core API)
export {
  canonicalizeCore,
  deriveReceiptId,
  signReceipt,
  verifyReceipt,
} from './engine.js';

// Key resolution helpers
export {
  fetchSarKeys,
  parseSarKeysDocument,
  resolveKidFromDocument,
  resolveKidFromWellKnown,
} from './keys.js';

// Crypto utilities
export {
  sha256Hex,
  base64urlEncode,
  base64urlDecode,
  hashTaskId,
} from './crypto.js';
