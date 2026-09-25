/** Authenticated encryption (ChaCha20-Poly1305).
 *
 * WebCrypto does not offer ChaCha20-Poly1305, so we use audited pure-JS
 * @noble/ciphers. Interop with the Python `cryptography` backend is verified
 * against fixed vectors. */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from './random';

export const KEY_SIZE = 32;
export const NONCE_SIZE = 12;

export class AEADError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AEADError';
  }
}

/** Encrypt with a caller-supplied nonce (used by tests and vectors). */
export function encryptWithNonce(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (key.length !== KEY_SIZE) throw new AEADError(`invalid key size: ${key.length}`);
  if (nonce.length !== NONCE_SIZE) throw new AEADError(`invalid nonce size: ${nonce.length}`);
  return chacha20poly1305(key, nonce, ad).encrypt(plaintext);
}

/** Verify and decrypt. Raises {@link AEADError} on any failure. */
export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (key.length !== KEY_SIZE) throw new AEADError(`invalid key size: ${key.length}`);
  if (nonce.length !== NONCE_SIZE) throw new AEADError(`invalid nonce size: ${nonce.length}`);
  try {
    return chacha20poly1305(key, nonce, ad).decrypt(ciphertext);
  } catch {
    throw new AEADError('authentication failed');
  }
}

/** Encrypt and authenticate. Returns `[nonce, ciphertext]`. */
export function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): [Uint8Array, Uint8Array] {
  const nonce = randomBytes(NONCE_SIZE);
  return [nonce, encryptWithNonce(key, nonce, plaintext, ad)];
}
