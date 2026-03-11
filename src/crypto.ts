import { sha256 as _sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import * as ed from '@noble/ed25519';

// Configure @noble/ed25519 to use @noble/hashes for SHA-512.
// This makes sign/verify work synchronously and is portable across
// Node.js and edge runtimes (Cloudflare Workers).
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m));

/** SHA-256 hash, returns 32 bytes. */
export function sha256(data: Uint8Array): Uint8Array {
  return _sha256(data);
}

/** SHA-256 hash, returns lowercase hex string. */
export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

/** Convert bytes to lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** Base64url encode (no padding), per RFC 4648 section 5. */
export function base64urlEncode(bytes: Uint8Array): string {
  let binStr = '';
  for (let i = 0; i < bytes.length; i++) {
    binStr += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binStr);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Base64url decode (handles missing padding). */
export function base64urlDecode(str: string): Uint8Array {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) {
    bytes[i] = binStr.charCodeAt(i);
  }
  return bytes;
}

/**
 * Sign a 32-byte SHA-256 digest with an Ed25519 private key.
 * Returns the 64-byte signature.
 */
export async function ed25519Sign(
  digest: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  return await ed.signAsync(digest, privateKey);
}

/**
 * Verify an Ed25519 signature over a 32-byte SHA-256 digest.
 * Returns true if valid, false otherwise.
 */
export async function ed25519Verify(
  signature: Uint8Array,
  digest: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  return await ed.verifyAsync(signature, digest, publicKey);
}

/**
 * Convenience: hash a raw task ID to "sha256:<hex>".
 */
export function hashTaskId(rawTaskId: string | Uint8Array): string {
  const bytes =
    typeof rawTaskId === 'string'
      ? new TextEncoder().encode(rawTaskId)
      : rawTaskId;
  return 'sha256:' + sha256Hex(bytes);
}
