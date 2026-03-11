#!/usr/bin/env node
/**
 * Regenerate all SAR v0.1 test fixtures with a new Ed25519 keypair
 * and kid = "xmandate-ed25519-test-01".
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

const NEW_KID = 'xmandate-ed25519-test-01';

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

// Generate new keypair
const privKey = ed.utils.randomPrivateKey();
const pubKey = await ed.getPublicKeyAsync(privKey);

console.log(`New kid: ${NEW_KID}`);
console.log(`Public key (base64url): ${base64urlEncode(pubKey)}`);

// Write sar-keys.json
const keysDoc = {
  keys: [
    {
      kid: NEW_KID,
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64urlEncode(pubKey),
      created: new Date().toISOString(),
    },
  ],
};
writeFileSync(
  resolve(FIXTURES_DIR, 'sar-keys.json'),
  JSON.stringify(keysDoc, null, 2) + '\n',
);
console.log('Wrote sar-keys.json');

// Fixture definitions
const fixtures = [
  {
    file: 'sar-v0.1-pass.json',
    description: 'SAR v0.1 PASS fixture (canonical test vector)',
    input: {
      task_id_hash: 'sha256:fixture-task-001',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'SPEC_MATCH',
      ts: '2026-02-14T12:00:00Z',
      verifier_kid: NEW_KID,
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
      verifier_kid: NEW_KID,
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
      verifier_kid: NEW_KID,
    },
  },
];

for (const { file, description, input } of fixtures) {
  // JCS canonicalize
  const canonicalJson = canonicalize(input);

  // SHA-256 of canonical bytes
  const canonicalBytes = new TextEncoder().encode(canonicalJson);
  const digestHex = sha256Hex(canonicalBytes);
  const receiptId = `sha256:${digestHex}`;

  // Sign the 32-byte digest
  const digest = sha256(canonicalBytes);
  const sigBytes = await ed.signAsync(digest, privKey);
  const sig = `base64url:${base64urlEncode(sigBytes)}`;

  const fixture = {
    description,
    sar_version: '0.1',
    input,
    canonical_json: canonicalJson,
    receipt_id: receiptId,
    public_key_kid: NEW_KID,
    sig,
    verification_steps: [
      '1. JCS-canonicalize `input` (RFC 8785).',
      '2. Confirm it matches `canonical_json` byte-for-byte.',
      '3. SHA256(canonical_json bytes) => receipt_id hex.',
      '4. Verify Ed25519 signature over the hash bytes using public key from sar-keys.json.',
    ],
  };

  writeFileSync(
    resolve(FIXTURES_DIR, file),
    JSON.stringify(fixture, null, 2) + '\n',
  );
  console.log(`Wrote ${file} (receipt_id: ${receiptId})`);
}

console.log('\nDone. Run `npm test` to verify.');
