export class MalformedReceipt extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MalformedReceipt';
  }
}

export class ReceiptIdMismatch extends Error {
  constructor(expected: string, actual: string) {
    super(`Receipt ID mismatch: expected ${expected}, got ${actual}`);
    this.name = 'ReceiptIdMismatch';
  }
}

export class KeyNotFound extends Error {
  constructor(kid: string) {
    super(`Key not found for kid: ${kid}`);
    this.name = 'KeyNotFound';
  }
}

export class InvalidSignature extends Error {
  constructor() {
    super('Ed25519 signature verification failed');
    this.name = 'InvalidSignature';
  }
}
