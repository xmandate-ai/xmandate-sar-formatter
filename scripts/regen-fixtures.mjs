#!/usr/bin/env node
/**
 * Regenerate all SAR v0.1 test fixtures with a deterministic Ed25519 keypair.
 *
 * The keypair is derived from a fixed seed so that fixtures are stable
 * across runs. This is critical for cross-implementation conformance:
 * third parties validating against these fixtures need pinned values.
 *
 * Run: node scripts/regen-fixtures.mjs
 */

import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import canonicalize from 'canonicalize';

// Configure @noble/ed25519 to use @noble/hashes for SHA-512
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(__dirname, '..', 'test', 'fixtures');

const KID = 'xmandate-ed25519-test-01';
const FIXED_CREATED = '2026-02-14T00:00:00Z';

// ---------- Deterministic key material ----------
// TEST KEY - NOT FOR PRODUCTION USE
// Derived from SHA-256 of a fixed seed string for reproducibility.
const privKey = new Uint8Array(
  createHash('sha256').update('xmandate-sar-v0.1-test-fixtures').digest(),
);
const pubKey = await ed.getPublicKeyAsync(privKey);

function base64urlEncode(bytes) {
  let binStr = '';
  for (let i = 0; i < bytes.length; i++) {
    binStr += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binStr);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sha256(data) {
  return createHash('sha256').update(data).digest();
}

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

console.log(`kid: ${KID}`);
console.log(`Public key (base64url): ${base64urlEncode(pubKey)}`);

// ---------- sar-keys.json ----------
const keysDoc = {
  keys: [
    {
      kid: KID,
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64urlEncode(pubKey),
      created: FIXED_CREATED,
    },
  ],
};
writeFileSync(
  resolve(FIXTURES_DIR, 'sar-keys.json'),
  JSON.stringify(keysDoc, null, 2) + '\n',
);
console.log('Wrote sar-keys.json');

// ---------- Helper: sign a core and return common fields ----------
async function signCore(input) {
  const canonicalJson = canonicalize(input);
  const canonicalBytes = new TextEncoder().encode(canonicalJson);
  const digestHex = sha256Hex(canonicalBytes);
  const receiptId = `sha256:${digestHex}`;
  const digest = sha256(canonicalBytes);
  const sigBytes = await ed.signAsync(digest, privKey);
  const sig = `base64url:${base64urlEncode(sigBytes)}`;
  return { canonicalJson, receiptId, digest, sig, sigBytes };
}

// ============================================================
// POSITIVE FIXTURES
// ============================================================

const positiveFixtures = [
  {
    file: 'sar-v0.1-pass.json',
    description: 'SAR v0.1 PASS fixture (canonical test vector)',
    input: {
      task_id_hash: 'sha256:fixture-task-001',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'SPEC_MATCH',
      ts: '2026-02-14T12:00:00Z',
      verifier_kid: KID,
    },
  },
  {
    file: 'sar-v0.1-fail.json',
    description: 'SAR v0.1 FAIL fixture (controlled mismatch test vector)',
    input: {
      task_id_hash: 'sha256:fixture-task-001',
      verdict: 'FAIL',
      confidence: 1,
      reason_code: 'SPEC_MISMATCH',
      ts: '2026-02-14T12:00:00Z',
      verifier_kid: KID,
    },
  },
  {
    file: 'sar-v0.1-indeterminate.json',
    description: 'SAR v0.1 INDETERMINATE fixture (honest ambiguity test vector)',
    input: {
      task_id_hash: 'sha256:fixture-task-001',
      verdict: 'INDETERMINATE',
      confidence: 0,
      reason_code: 'SPEC_AMBIGUOUS',
      ts: '2026-02-14T12:00:00Z',
      verifier_kid: KID,
    },
  },
];

for (const def of positiveFixtures) {
  const { canonicalJson, receiptId, sig } = await signCore(def.input);

  const fixture = {
    description: def.description,
    sar_version: '0.1',
    input: def.input,
    canonical_json: canonicalJson,
    receipt_id: receiptId,
    public_key_kid: KID,
    sig,
    verification_steps: def.verification_steps || [
      '1. JCS-canonicalize `input` (RFC 8785).',
      '2. Confirm it matches `canonical_json` byte-for-byte.',
      '3. SHA256(canonical_json bytes) => receipt_id hex.',
      '4. Verify Ed25519 signature over the hash bytes using public key from sar-keys.json.',
    ],
  };

  writeFileSync(
    resolve(FIXTURES_DIR, def.file),
    JSON.stringify(fixture, null, 2) + '\n',
  );
  console.log(`Wrote ${def.file} (receipt_id: ${receiptId})`);
}

console.log('\nDone. Run `npm test` to verify.');
