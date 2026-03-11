import { KeyNotFound, MalformedReceipt } from './errors.js';
import { base64urlDecode } from './crypto.js';
import type { SarKeysDocument } from './types.js';

/**
 * Fetch the SAR keys document from an origin's well-known endpoint.
 * Works in Node 20+ (global fetch) and Cloudflare Workers.
 */
export async function fetchSarKeys(origin: string): Promise<SarKeysDocument> {
  const url = `${origin.replace(/\/+$/, '')}/.well-known/sar-keys.json`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new MalformedReceipt(`Failed to fetch SAR keys: HTTP ${res.status}`);
  }
  const doc: unknown = await res.json();
  return parseSarKeysDocument(doc);
}

/**
 * Parse and validate a SAR keys document (JWKS-style).
 */
export function parseSarKeysDocument(doc: unknown): SarKeysDocument {
  if (
    doc === null ||
    typeof doc !== 'object' ||
    !('keys' in doc) ||
    !Array.isArray((doc as Record<string, unknown>).keys)
  ) {
    throw new MalformedReceipt('Invalid SAR keys document: missing "keys" array');
  }
  return doc as SarKeysDocument;
}

/**
 * Resolve an Ed25519 public key (32 bytes) by kid from a SAR keys document.
 */
export function resolveKidFromDocument(
  doc: SarKeysDocument,
  kid: string,
): Uint8Array {
  const entry = doc.keys.find((k) => k.kid === kid);
  if (!entry) {
    throw new KeyNotFound(kid);
  }
  if (entry.kty !== 'OKP' || entry.crv !== 'Ed25519' || !entry.x) {
    throw new MalformedReceipt(
      `Key ${kid} is not a valid Ed25519 key (kty=${entry.kty}, crv=${entry.crv})`,
    );
  }
  const pubKey = base64urlDecode(entry.x);
  if (pubKey.length !== 32) {
    throw new MalformedReceipt(
      `Key ${kid} has invalid length: expected 32 bytes, got ${pubKey.length}`,
    );
  }
  return pubKey;
}

/**
 * Fetch SAR keys from origin and resolve a specific kid to 32-byte Ed25519 public key.
 */
export async function resolveKidFromWellKnown(
  origin: string,
  kid: string,
): Promise<Uint8Array> {
  const doc = await fetchSarKeys(origin);
  return resolveKidFromDocument(doc, kid);
}
