import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalizeCore,
  deriveReceiptId,
  verifyReceipt,
  signReceipt,
  resolveKidFromDocument,
  parseSarKeysDocument,
  base64urlDecode,
} from '../src/index.js';
import type { SarCore, SarReceipt, SarKeysDocument } from '../src/index.js';
import {
  MalformedReceipt,
  ReceiptIdMismatch,
  InvalidSignature,
  KeyNotFound,
} from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadFixture(name: string): Record<string, unknown> {
  const raw = readFileSync(resolve(__dirname, 'fixtures', name), 'utf-8');
  return JSON.parse(raw) as Record<string, unknown>;
}

const passFixture = loadFixture('sar-v0.1-pass.json');
const failFixture = loadFixture('sar-v0.1-fail.json');
const indeterminateFixture = loadFixture('sar-v0.1-indeterminate.json');
const specialCharsFixture = loadFixture('sar-v0.1-special-chars.json');
const indeterminateTimeoutFixture = loadFixture('sar-v0.2-indeterminate-evaluator-timeout.json');
const indeterminateConflictFixture = loadFixture('sar-v0.2-indeterminate-conflict.json');
const passRotatedKeyFixture = loadFixture('sar-v0.2-pass-rotated-key.json');
const indeterminateRotatedKeyFixture = loadFixture('sar-v0.2-indeterminate-rotated-key.json');
const keysDoc = loadFixture('sar-keys.json') as unknown as SarKeysDocument;

// Helper: build a SarReceipt from a fixture
function fixtureToReceipt(fixture: Record<string, unknown>): SarReceipt {
  const input = fixture.input as SarCore;
  return {
    receipt_version: fixture.sar_version as string,
    receipt_id: fixture.receipt_id as string,
    ...input,
    sig_alg: 'Ed25519',
    sig: fixture.sig as string,
  };
}

// Key resolver using the local keys fixture
function localKeyResolver(kid: string): Uint8Array {
  return resolveKidFromDocument(keysDoc, kid);
}

const FIXTURES = [
  { name: 'PASS', fixture: passFixture },
  { name: 'FAIL', fixture: failFixture },
  { name: 'INDETERMINATE', fixture: indeterminateFixture },
  { name: 'SPECIAL_CHARS', fixture: specialCharsFixture },
  { name: 'INDETERMINATE_EVALUATOR_TIMEOUT', fixture: indeterminateTimeoutFixture },
  { name: 'INDETERMINATE_CONFLICT', fixture: indeterminateConflictFixture },
  { name: 'PASS_ROTATED_KEY', fixture: passRotatedKeyFixture },
  { name: 'INDETERMINATE_ROTATED_KEY', fixture: indeterminateRotatedKeyFixture },
] as const;

describe('SAR v0.1 fixture compatibility', () => {
  for (const { name, fixture } of FIXTURES) {
    describe(`${name} fixture`, () => {
      const input = fixture.input as SarCore;
      const expectedCanonical = fixture.canonical_json as string;
      const expectedReceiptId = fixture.receipt_id as string;

      it('canonicalizeCore matches fixture canonical_json byte-for-byte', () => {
        const coreBytes = canonicalizeCore(input);
        const canonical = new TextDecoder().decode(coreBytes);
        expect(canonical).toBe(expectedCanonical);
      });

      it('deriveReceiptId matches fixture receipt_id exactly', () => {
        const receiptId = deriveReceiptId(input);
        expect(receiptId).toBe(expectedReceiptId);
      });

      it('verifyReceipt succeeds with fixture pubkey', async () => {
        const receipt = fixtureToReceipt(fixture);
        const result = await verifyReceipt(receipt, localKeyResolver);
        expect(result).toBe(true);
      });
    });
  }
});

describe('receipt_id integrity', () => {
  it('tampered core field causes ReceiptIdMismatch', async () => {
    const receipt = fixtureToReceipt(passFixture);
    // Tamper with verdict
    receipt.verdict = 'FAIL';
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(ReceiptIdMismatch);
  });

  it('tampered receipt_id causes ReceiptIdMismatch', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.receipt_id = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(ReceiptIdMismatch);
  });
});

describe('signature integrity', () => {
  it('tampered signature causes InvalidSignature', async () => {
    const receipt = fixtureToReceipt(passFixture);
    // Flip a byte in the signature
    const sigB64 = receipt.sig.slice('base64url:'.length);
    const sigBytes = base64urlDecode(sigB64);
    sigBytes[0] ^= 0xff;
    const { base64urlEncode } = await import('../src/crypto.js');
    receipt.sig = 'base64url:' + base64urlEncode(sigBytes);
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(InvalidSignature);
  });
});

describe('_ext isolation', () => {
  it('modifying _ext does NOT change receipt_id', () => {
    const core = passFixture.input as SarCore;
    const baseId = deriveReceiptId(core);

    // Create a receipt-like object with _ext and verify the core derivation is unaffected
    const coreWithExt = { ...core, _ext: { 'x402': { payment_hash: 'abc123' } } };
    // deriveReceiptId only uses core fields, _ext should not appear
    const extId = deriveReceiptId(coreWithExt as SarCore);
    expect(extId).toBe(baseId);
  });

  it('different _ext values produce identical receipt_id', () => {
    const core = passFixture.input as SarCore;
    const id1 = deriveReceiptId({ ...core } as SarCore);
    const id2 = deriveReceiptId({
      ...core,
      _ext: { some_ns: { data: [1, 2, 3] } },
    } as SarCore);
    expect(id1).toBe(id2);
  });
});

describe('signReceipt round-trip', () => {
  it('sign then verify succeeds', async () => {
    // Generate a throwaway Ed25519 keypair using @noble/ed25519
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const core: SarCore = {
      task_id_hash: 'sha256:test-task-round-trip',
      verdict: 'PASS',
      confidence: 0.95,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const receipt = await signReceipt(core, { privateKey: privKey });

    expect(receipt.receipt_version).toBe('0.1');
    expect(receipt.sig_alg).toBe('Ed25519');
    expect(receipt.sig.startsWith('base64url:')).toBe(true);
    expect(receipt.receipt_id.startsWith('sha256:')).toBe(true);

    // Verify with the matching public key
    const result = await verifyReceipt(receipt, (_kid) => pubKey);
    expect(result).toBe(true);
  });
});

describe('_ext/_perf passthrough in signReceipt', () => {
  it('signReceipt includes _ext/_perf and verifyReceipt still passes', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const core: SarCore = {
      task_id_hash: 'sha256:test-ext-perf',
      verdict: 'PASS',
      confidence: 0.9,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const receipt = await signReceipt(core, {
      privateKey: privKey,
      _ext: { x402: { payment_hash: 'abc' } },
      _perf: { verify_ms: 42, total_ms: 100 },
    });

    expect(receipt._ext).toEqual({ x402: { payment_hash: 'abc' } });
    expect(receipt._perf).toEqual({ verify_ms: 42, total_ms: 100 });

    const result = await verifyReceipt(receipt, () => pubKey);
    expect(result).toBe(true);
  });

  it('receipt_id is identical with vs without _ext/_perf', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();

    const core: SarCore = {
      task_id_hash: 'sha256:test-invariance',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const withoutExt = await signReceipt(core, { privateKey: privKey });
    const withExt = await signReceipt(core, {
      privateKey: privKey,
      _ext: { ns: { data: 'test' } },
      _perf: { verify_ms: 50 },
    });

    expect(withExt.receipt_id).toBe(withoutExt.receipt_id);
  });

  it('signReceipt omits _ext/_perf when not provided', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();

    const core: SarCore = {
      task_id_hash: 'sha256:test-omit',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const receipt = await signReceipt(core, { privateKey: privKey });
    expect(receipt._ext).toBeUndefined();
    expect(receipt._perf).toBeUndefined();
  });
});

describe('input validation', () => {
  it('rejects receipt missing required fields', async () => {
    const partial = { receipt_version: '0.1' } as unknown as SarReceipt;
    await expect(
      verifyReceipt(partial, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects unsupported sig_alg', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.sig_alg = 'RSA-256';
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects sig without base64url: prefix', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.sig = receipt.sig.replace('base64url:', '');
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('accepts receipt_version "0.2"', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.receipt_version = '0.2';
    const result = await verifyReceipt(receipt, localKeyResolver);
    expect(result).toBe(true);
  });

  it('rejects unsupported receipt_version "0.3"', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.receipt_version = '0.3';
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects malformed receipt_id (wrong prefix)', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.receipt_id = 'md5:abc123';
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects receipt_id with wrong hex length', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.receipt_id = 'sha256:abc123';
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects confidence < 0', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.confidence = -0.1;
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects confidence > 1', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.confidence = 1.5;
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects NaN confidence', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.confidence = NaN;
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });

  it('rejects Infinity confidence', async () => {
    const receipt = fixtureToReceipt(passFixture);
    receipt.confidence = Infinity;
    await expect(
      verifyReceipt(receipt, localKeyResolver),
    ).rejects.toThrow(MalformedReceipt);
  });
});

describe('SAR keys parsing', () => {
  it('parseSarKeysDocument accepts valid document', () => {
    const doc = parseSarKeysDocument(keysDoc);
    expect(doc.keys).toHaveLength(2);
    expect(doc.keys[0].kid).toBe('xmandate-ed25519-test-01');
    expect(doc.keys[1].kid).toBe('xmandate-ed25519-test-02');
  });

  it('parseSarKeysDocument rejects invalid document', () => {
    expect(() => parseSarKeysDocument({})).toThrow(MalformedReceipt);
    expect(() => parseSarKeysDocument(null)).toThrow(MalformedReceipt);
    expect(() => parseSarKeysDocument({ keys: 'not-array' })).toThrow(MalformedReceipt);
  });

  it('resolveKidFromDocument returns 32-byte pubkey', () => {
    const pubKey = resolveKidFromDocument(keysDoc, 'xmandate-ed25519-test-01');
    expect(pubKey).toBeInstanceOf(Uint8Array);
    expect(pubKey.length).toBe(32);
  });

  it('resolveKidFromDocument throws KeyNotFound for unknown kid', () => {
    expect(() => resolveKidFromDocument(keysDoc, 'nonexistent-kid')).toThrow(
      KeyNotFound,
    );
  });
});

// ============================================================
// Inline gap tests
// ============================================================

describe('reason_code is opaque', () => {
  it('novel reason_code signs and verifies successfully', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const core: SarCore = {
      task_id_hash: 'sha256:test-novel-reason',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'CUSTOM_EVALUATOR_V2',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const receipt = await signReceipt(core, { privateKey: privKey });
    const result = await verifyReceipt(receipt, () => pubKey);
    expect(result).toBe(true);
  });
});

describe('wrong key rejection', () => {
  it('valid receipt with wrong public key throws InvalidSignature', async () => {
    const ed = await import('@noble/ed25519');
    const wrongKey = await ed.getPublicKeyAsync(ed.utils.randomPrivateKey());

    const receipt = fixtureToReceipt(passFixture);
    await expect(
      verifyReceipt(receipt, () => wrongKey),
    ).rejects.toThrow(InvalidSignature);
  });
});

describe('v0.2 counterparty support', () => {
  it('signReceipt with counterparty includes field in output', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();

    const core: SarCore = {
      task_id_hash: 'sha256:test-counterparty',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const receipt = await signReceipt(core, {
      privateKey: privKey,
      receipt_version: '0.2',
      counterparty: '0x1234567890abcdef1234567890abcdef12345678',
    });

    expect(receipt.receipt_version).toBe('0.2');
    expect(receipt.counterparty).toBe('0x1234567890abcdef1234567890abcdef12345678');
  });

  it('counterparty does not affect receipt_id', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();

    const core: SarCore = {
      task_id_hash: 'sha256:test-counterparty-isolation',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const without = await signReceipt(core, { privateKey: privKey });
    const with_ = await signReceipt(core, {
      privateKey: privKey,
      receipt_version: '0.2',
      counterparty: '0xdeadbeef',
    });

    expect(with_.receipt_id).toBe(without.receipt_id);
  });

  it('v0.2 receipt with counterparty verifies', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const core: SarCore = {
      task_id_hash: 'sha256:test-v02-verify',
      verdict: 'PASS',
      confidence: 0.95,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const receipt = await signReceipt(core, {
      privateKey: privKey,
      receipt_version: '0.2',
      counterparty: '0xabcdef',
    });

    const result = await verifyReceipt(receipt, () => pubKey);
    expect(result).toBe(true);
  });

  it('signReceipt omits counterparty when not provided', async () => {
    const ed = await import('@noble/ed25519');
    const privKey = ed.utils.randomPrivateKey();

    const core: SarCore = {
      task_id_hash: 'sha256:test-no-counterparty',
      verdict: 'PASS',
      confidence: 1,
      reason_code: 'SPEC_MATCH',
      ts: '2026-03-01T00:00:00Z',
      verifier_kid: 'test-key-01',
    };

    const receipt = await signReceipt(core, { privateKey: privKey });
    expect(receipt.counterparty).toBeUndefined();
  });
});

describe('RFC 8785 §3.2.2.2 short-form escapes', () => {
  const input = specialCharsFixture.input as SarCore;
  const expectedCanonical = specialCharsFixture.canonical_json as string;

  it('canonicalizeCore uses short-form \\b\\f\\n\\r\\t, never \\uXXXX long-form', () => {
    const coreBytes = canonicalizeCore(input);
    const canonical = new TextDecoder().decode(coreBytes);

    // Must use short-form escapes
    expect(canonical).toContain('\\b');
    expect(canonical).toContain('\\f');
    expect(canonical).toContain('\\n');
    expect(canonical).toContain('\\r');
    expect(canonical).toContain('\\t');

    // Must NOT use long-form \uXXXX equivalents
    expect(canonical).not.toContain('\\u0008');
    expect(canonical).not.toContain('\\u000c');
    expect(canonical).not.toContain('\\u000C');
    expect(canonical).not.toContain('\\u000a');
    expect(canonical).not.toContain('\\u000A');
    expect(canonical).not.toContain('\\u000d');
    expect(canonical).not.toContain('\\u000D');
    expect(canonical).not.toContain('\\u0009');

    // Must match fixture canonical_json byte-for-byte
    expect(canonical).toBe(expectedCanonical);
  });

  it('special-chars fixture verifies with deterministic keypair', async () => {
    const receipt = fixtureToReceipt(specialCharsFixture);
    const result = await verifyReceipt(receipt, localKeyResolver);
    expect(result).toBe(true);
  });
});

describe('INDETERMINATE edge cases', () => {
  it('evaluator-timeout: partial confidence (0.5) with INDETERMINATE verdict', () => {
    const input = indeterminateTimeoutFixture.input as SarCore;
    expect(input.verdict).toBe('INDETERMINATE');
    expect(input.confidence).toBe(0.5);
    expect(input.reason_code).toBe('EVALUATOR_TIMEOUT');

    const receiptId = deriveReceiptId(input);
    expect(receiptId).toBe(indeterminateTimeoutFixture.receipt_id);
  });

  it('evaluator-timeout fixture verifies', async () => {
    const receipt = fixtureToReceipt(indeterminateTimeoutFixture);
    const result = await verifyReceipt(receipt, localKeyResolver);
    expect(result).toBe(true);
  });

  it('conflict: low confidence (0.35) with INDETERMINATE verdict', () => {
    const input = indeterminateConflictFixture.input as SarCore;
    expect(input.verdict).toBe('INDETERMINATE');
    expect(input.confidence).toBe(0.35);
    expect(input.reason_code).toBe('CONFLICT');

    const receiptId = deriveReceiptId(input);
    expect(receiptId).toBe(indeterminateConflictFixture.receipt_id);
  });

  it('conflict fixture verifies', async () => {
    const receipt = fixtureToReceipt(indeterminateConflictFixture);
    const result = await verifyReceipt(receipt, localKeyResolver);
    expect(result).toBe(true);
  });
});

describe('key rotation', () => {
  it('sar-keys.json contains both kid-01 and kid-02', () => {
    const kid01Key = resolveKidFromDocument(keysDoc, 'xmandate-ed25519-test-01');
    const kid02Key = resolveKidFromDocument(keysDoc, 'xmandate-ed25519-test-02');
    expect(kid01Key).toBeInstanceOf(Uint8Array);
    expect(kid01Key.length).toBe(32);
    expect(kid02Key).toBeInstanceOf(Uint8Array);
    expect(kid02Key.length).toBe(32);
    // Keys must be different
    expect(Buffer.from(kid01Key).equals(Buffer.from(kid02Key))).toBe(false);
  });

  it('PASS fixture signed with kid-02 verifies via kid-indexed lookup', async () => {
    const receipt = fixtureToReceipt(passRotatedKeyFixture);
    expect(receipt.verifier_kid).toBe('xmandate-ed25519-test-02');
    const result = await verifyReceipt(receipt, localKeyResolver);
    expect(result).toBe(true);
  });

  it('INDETERMINATE fixture signed with kid-02 verifies via kid-indexed lookup', async () => {
    const receipt = fixtureToReceipt(indeterminateRotatedKeyFixture);
    expect(receipt.verifier_kid).toBe('xmandate-ed25519-test-02');
    const result = await verifyReceipt(receipt, localKeyResolver);
    expect(result).toBe(true);
  });

  it('kid-02 fixture fails verification with kid-01 key', async () => {
    const receipt = fixtureToReceipt(passRotatedKeyFixture);
    // Force resolution to kid-01 key regardless of kid in receipt
    const kid01Only = (_kid: string) =>
      resolveKidFromDocument(keysDoc, 'xmandate-ed25519-test-01');
    await expect(
      verifyReceipt(receipt, kid01Only),
    ).rejects.toThrow(InvalidSignature);
  });

  it('kid-01 fixture fails verification with kid-02 key', async () => {
    const receipt = fixtureToReceipt(passFixture);
    // Force resolution to kid-02 key regardless of kid in receipt
    const kid02Only = (_kid: string) =>
      resolveKidFromDocument(keysDoc, 'xmandate-ed25519-test-02');
    await expect(
      verifyReceipt(receipt, kid02Only),
    ).rejects.toThrow(InvalidSignature);
  });
});

// ── nutstrut DefaultVerifier vectors (cross-implementation) ──

const dvKeysDoc = loadFixture('dv-prod-sar-keys.json') as unknown as SarKeysDocument;

function dvKeyResolver(kid: string): Uint8Array {
  return resolveKidFromDocument(dvKeysDoc, kid);
}

const nutPASS = loadFixture('nutstrut-pass-basic.json');
const nutINDET = loadFixture('nutstrut-indeterminate-ambiguous.json');
const nutKID02 = loadFixture('nutstrut-pass-kid-02.json');
const nutUNKNOWN = loadFixture('nutstrut-negative-unknown-schema.json');

const NUTSTRUT_FIXTURES = [
  { name: 'pass-basic', fixture: nutPASS },
  { name: 'indeterminate-ambiguous', fixture: nutINDET },
  { name: 'pass-kid-02', fixture: nutKID02 },
  { name: 'negative-unknown-schema', fixture: nutUNKNOWN },
] as const;

describe('nutstrut DefaultVerifier vectors (cross-implementation)', () => {

  for (const { name, fixture } of NUTSTRUT_FIXTURES) {
    describe(name, () => {
      const input = fixture.input as SarCore;
      const expectedReceiptId = fixture.receipt_id as string;

      it('deriveReceiptId matches fixture receipt_id', () => {
        const receiptId = deriveReceiptId(input);
        expect(receiptId).toBe(expectedReceiptId);
      });

      it('verifyReceipt succeeds with DefaultVerifier production keys', async () => {
        const receipt = fixtureToReceipt(fixture);
        const result = await verifyReceipt(receipt, dvKeyResolver);
        expect(result).toBe(true);
      });
    });
  }

  it('indeterminate-ambiguous canonical_json matches byte-for-byte', () => {
    const input = nutINDET.input as SarCore;
    const coreBytes = canonicalizeCore(input);
    const canonical = new TextDecoder().decode(coreBytes);
    const expected = nutINDET.canonical_json as string;
    if (expected) {
      expect(canonical).toBe(expected);
    }
  });

  describe('_ext.operation_binding isolation', () => {
    it('receipt_id unchanged with _ext present', () => {
      const input = nutPASS.input as SarCore;
      const ext = nutPASS._ext as Record<string, unknown>;
      const baseId = deriveReceiptId(input);
      const withExtId = deriveReceiptId({ ...input, _ext: ext } as SarCore);
      expect(withExtId).toBe(baseId);
    });

    it('verifyReceipt passes when _ext.operation_binding is attached', async () => {
      const receipt = fixtureToReceipt(nutPASS);
      receipt._ext = nutPASS._ext as Record<string, unknown>;
      const result = await verifyReceipt(receipt, dvKeyResolver);
      expect(result).toBe(true);
    });

    it('verifyReceipt passes when _ext.operation_binding is stripped', async () => {
      const receipt = fixtureToReceipt(nutPASS);
      delete receipt._ext;
      const result = await verifyReceipt(receipt, dvKeyResolver);
      expect(result).toBe(true);
    });

    it('verifyReceipt passes when _ext.operation_binding is modified', async () => {
      const receipt = fixtureToReceipt(nutPASS);
      receipt._ext = {
        operation_binding: {
          operation_digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          operation_id: 'completely.different',
          resource_url: 'https://other.example.com/different',
          schema_id: 'x402-operation-binding/v42',
        },
      };
      const result = await verifyReceipt(receipt, dvKeyResolver);
      expect(result).toBe(true);
    });
  });

  describe('unknown schema_id', () => {
    it('SAR verification passes regardless of schema_id value', async () => {
      const receipt = fixtureToReceipt(nutUNKNOWN);
      receipt._ext = nutUNKNOWN._ext as Record<string, unknown>;
      const result = await verifyReceipt(receipt, dvKeyResolver);
      expect(result).toBe(true);
    });
  });

  describe('key rotation across DefaultVerifier keys', () => {
    it('indeterminate-ambiguous uses kid-01', () => {
      expect((nutINDET.input as SarCore).verifier_kid).toBe('sar-prod-ed25519-01');
    });

    it('pass-basic uses kid-02', () => {
      expect((nutPASS.input as SarCore).verifier_kid).toBe('sar-prod-ed25519-02');
    });

    it('both keys resolve from DefaultVerifier keys document', () => {
      const key1 = dvKeyResolver('sar-prod-ed25519-01');
      const key2 = dvKeyResolver('sar-prod-ed25519-02');
      expect(key1).toBeInstanceOf(Uint8Array);
      expect(key2).toBeInstanceOf(Uint8Array);
      expect(key1.length).toBe(32);
      expect(key2.length).toBe(32);
      expect(Buffer.from(key1).toString('hex')).not.toBe(Buffer.from(key2).toString('hex'));
    });

    it('kid-01 receipt fails verification when verifier_kid is changed to kid-02', async () => {
      const receipt = fixtureToReceipt(nutINDET);
      receipt.verifier_kid = 'sar-prod-ed25519-02';
      await expect(verifyReceipt(receipt, dvKeyResolver)).rejects.toThrow();
    });
  });

}); // close 'nutstrut DefaultVerifier vectors'
