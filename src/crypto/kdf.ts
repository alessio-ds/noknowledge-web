/** Key derivation functions.
 *
 * All key material goes through HKDF-SHA256 with an explicit, unique `info`
 * label per purpose. Chain keys use HMAC-SHA256 as in the Double Ratchet spec.
 * The labels are byte-identical to the Python reference: changing one breaks
 * interoperability with the desktop client. */

import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { concat, utf8Encode } from './bytes';

// Domain-separation labels. Never reuse a label for two purposes.
export const IDENTITY_INFO = utf8Encode('noknowledge/identity/v1');
export const X3DH_INFO = utf8Encode('noknowledge/x3dh/v1');
export const ROOT_INFO = utf8Encode('nk/ratchet-root/v1');
export const SK_COMMIT_INFO = utf8Encode('nk/sk-commit/v1');
export const CARD_SIGN_INFO = utf8Encode('nk/card/v1');
export const SPK_SIGN_INFO = utf8Encode('nk/spk/v1');
export const AUTH_SIGN_INFO = utf8Encode('nk/auth/v1');
export const ID_HASH_INFO = utf8Encode('nk-id');

/** X25519 domain separation prefix (RFC 7748 / X3DH): 32 bytes of 0xFF. */
export const F = new Uint8Array(32).fill(0xff);
export const ZERO_SALT = new Uint8Array(32);

/** HKDF-SHA256 extract-and-expand. */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length = 32,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

/** Double Ratchet root KDF: returns `[newRootKey, chainKey]`. */
export function kdfRk(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const out = hkdfSha256(dhOutput, rootKey, ROOT_INFO, 64);
  return [out.slice(0, 32), out.slice(32)];
}

/** Double Ratchet chain KDF: returns `[messageKey, nextChainKey]`. */
export function kdfCk(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const messageKey = hmac(sha256, chainKey, Uint8Array.of(0x01));
  const nextChainKey = hmac(sha256, chainKey, Uint8Array.of(0x02));
  return [messageKey, nextChainKey];
}

/** Binding value that proves knowledge of the X3DH session key. */
export function skCommitment(sk: Uint8Array): Uint8Array {
  return sha256(concat(SK_COMMIT_INFO, sk));
}
