# xmandate-sar-formatter

[![CI](https://github.com/xmandate-ai/xmandate-sar-formatter/actions/workflows/ci.yml/badge.svg)](https://github.com/xmandate-ai/xmandate-sar-formatter/actions/workflows/ci.yml)

TypeScript SDK for creating and verifying **Settlement Attestation Receipts (SAR v0.1)**.

A SAR receipt is a signed, tamper-evident attestation that an AI agent's task output was independently verified against its specification. The receipt binds the verification verdict to a cryptographic proof chain: JCS-canonicalized core fields, a deterministic receipt ID derived from their SHA-256 hash, and an Ed25519 signature over that hash.

This SDK implements the full receipt lifecycle — **canonicalize, derive, sign, and verify** — with zero external service dependencies. Portable across **Node.js 20+** and **edge runtimes** (Cloudflare Workers, Deno).

## Why

AI agents that settle payments on behalf of users need a trust layer. When Agent A pays Agent B for a completed task, both parties (and any auditor) need a cryptographic proof that:

1. The task output was checked against the specification
2. The check produced a clear verdict (PASS / FAIL / INDETERMINATE)
3. The verdict hasn't been tampered with after the fact
4. The verifier's identity is bound to the receipt via a public key

SAR receipts provide this proof. This SDK lets you produce and consume them.

## Install

```bash
npm install xmandate-sar-formatter
```

## Quick start

### Verify a receipt

```typescript
import {
  verifyReceipt,
  resolveKidFromWellKnown,
} from 'xmandate-sar-formatter';

// The receipt you received (e.g. from a verifier service or another agent)
const receipt = {
  receipt_version: '0.1',
  receipt_id: 'sha256:ccda32b6...',
  task_id_hash: 'sha256:a1b2c3...',
  verdict: 'PASS',
  confidence: 1,
  reason_code: 'SPEC_MATCH',
  ts: '2026-03-01T12:00:00Z',
  verifier_kid: 'xmandate-ed25519-01',
  sig_alg: 'Ed25519',
  sig: 'base64url:p--HkrJo...',
};

// Fetch the verifier's public key from their /.well-known/sar-keys.json
await verifyReceipt(receipt, (kid) =>
  resolveKidFromWellKnown('https://verifier.example.com', kid),
);
// Returns true on success.
// Throws MalformedReceipt, ReceiptIdMismatch, or InvalidSignature on failure.
```

### Sign a receipt

```typescript
import { signReceipt, hashTaskId } from 'xmandate-sar-formatter';
import type { SarCore } from 'xmandate-sar-formatter';

const core: SarCore = {
  task_id_hash: hashTaskId('order-12345'),    // "sha256:<hex>"
  verdict: 'PASS',
  confidence: 0.95,
  reason_code: 'SPEC_MATCH',
  ts: new Date().toISOString(),
  verifier_kid: 'xmandate-ed25519-01',        // your key ID
};

const receipt = await signReceipt(core, {
  privateKey: myEd25519PrivateKey,             // 32-byte Uint8Array
});
// receipt is a complete SarReceipt — ready to return or store.
```

### Verify offline (bundled keys)

If you already have the verifier's public key, skip the network call:

```typescript
import { verifyReceipt, base64urlDecode } from 'xmandate-sar-formatter';

const knownKeys: Record<string, Uint8Array> = {
  'xmandate-ed25519-01': base64urlDecode('RXM_zNUwGswdgebuLJltVibXrrHfOggnTObWXDurocI'),
};

await verifyReceipt(receipt, (kid) => {
  const key = knownKeys[kid];
  if (!key) throw new Error(`Unknown kid: ${kid}`);
  return key;
});
```

## How it works

A SAR receipt has **6 core fields** that form the trust anchor:

```
task_id_hash   — SHA-256 hash of the original task ID
verdict        — PASS | FAIL | INDETERMINATE
confidence     — number in [0, 1]
reason_code    — machine-readable reason (e.g. SPEC_MATCH, SPEC_MISMATCH)
ts             — ISO 8601 timestamp
verifier_kid   — key ID of the signing key
```

The receipt ID and signature are derived from these fields:

```
core fields
    |
    v
JCS canonicalize (RFC 8785)     -- deterministic JSON serialization
    |
    v
SHA-256 hash (32 bytes)
    |
    +--> receipt_id = "sha256:<hex>"
    |
    +--> Ed25519 sign with private key --> sig = "base64url:<bytes>"
```

Verification reverses this: recompute the receipt ID from core fields, compare it to the claimed ID, then verify the Ed25519 signature.

**Extension fields** (`_ext`, `_perf`) can carry additional metadata (payment hashes, timing data) without affecting the receipt ID or signature. They are intentionally excluded from the signed core.

## API reference

### Core functions

| Function | Description |
|---|---|
| `signReceipt(core, opts)` | Sign core fields and produce a complete `SarReceipt` |
| `verifyReceipt(receipt, resolveKey)` | Verify a receipt. Returns `true` or throws |
| `deriveReceiptId(core)` | Derive `"sha256:<hex>"` from core fields (no signing) |
| `canonicalizeCore(core)` | JCS-canonicalize core fields, returns UTF-8 `Uint8Array` |

### Key resolution

| Function | Description |
|---|---|
| `resolveKidFromWellKnown(origin, kid)` | Fetch `/.well-known/sar-keys.json` from origin and resolve a kid to a 32-byte Ed25519 public key |
| `resolveKidFromDocument(doc, kid)` | Resolve a kid from an already-fetched `SarKeysDocument` |
| `fetchSarKeys(origin)` | Fetch and parse a `SarKeysDocument` from an origin |
| `parseSarKeysDocument(doc)` | Validate a raw object as a `SarKeysDocument` |

### Utilities

| Function | Description |
|---|---|
| `hashTaskId(raw)` | SHA-256 hash a raw task ID string to `"sha256:<hex>"` |
| `sha256Hex(bytes)` | SHA-256 digest as lowercase hex |
| `base64urlEncode(bytes)` | Base64url encode (no padding, RFC 4648 section 5) |
| `base64urlDecode(str)` | Base64url decode |

### Types

```typescript
type Verdict = 'PASS' | 'FAIL' | 'INDETERMINATE';

interface SarCore {
  task_id_hash: string;
  verdict: Verdict;
  confidence: number;
  reason_code: string;
  ts: string;
  verifier_kid: string;
}

interface SarReceipt extends SarCore {
  receipt_version: string;
  receipt_id: string;
  sig_alg: string;
  sig: string;
  _perf?: Record<string, number>;
  _ext?: Record<string, unknown>;
}

type KeyResolver = (kid: string) => Promise<Uint8Array> | Uint8Array;
```

### Errors

| Error class | Thrown when |
|---|---|
| `MalformedReceipt` | Receipt is missing required fields, has invalid types, or fails structural validation |
| `ReceiptIdMismatch` | The recomputed receipt ID doesn't match the one in the receipt (indicates tampering) |
| `InvalidSignature` | Ed25519 signature verification failed |
| `KeyNotFound` | The `verifier_kid` was not found in the keys document |

All errors extend `Error` and can be caught by class:

```typescript
import { InvalidSignature, ReceiptIdMismatch } from 'xmandate-sar-formatter';

try {
  await verifyReceipt(receipt, resolveKey);
} catch (err) {
  if (err instanceof ReceiptIdMismatch) {
    // Core fields were modified after signing
  } else if (err instanceof InvalidSignature) {
    // Signature doesn't match — wrong key or tampered digest
  }
}
```

## Edge runtime support

All dependencies are pure JavaScript with no Node.js-specific APIs:

- **`@noble/ed25519`** — Ed25519 signatures
- **`@noble/hashes`** — SHA-256, SHA-512
- **`canonicalize`** — JCS (RFC 8785)

Works out of the box on Cloudflare Workers, Deno, Vercel Edge Functions, and any runtime with `Uint8Array` and `TextEncoder`.

```typescript
// Cloudflare Worker example
import { verifyReceipt, resolveKidFromWellKnown } from 'xmandate-sar-formatter';

export default {
  async fetch(request: Request): Promise<Response> {
    const receipt = await request.json();
    try {
      await verifyReceipt(receipt, (kid) =>
        resolveKidFromWellKnown('https://verifier.example.com', kid),
      );
      return new Response('Valid', { status: 200 });
    } catch (err) {
      return new Response(String(err), { status: 400 });
    }
  },
};
```

## Development

```bash
npm install
npm test              # run all 31 tests
npm run build         # compile TypeScript to dist/
```

Test fixtures are canonical SAR v0.1 test vectors with pre-computed signatures. To regenerate them with a fresh keypair:

```bash
node scripts/regen-fixtures.mjs
npm test
```

## License

MIT
