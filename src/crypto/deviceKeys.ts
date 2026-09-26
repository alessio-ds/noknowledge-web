/** Per-device keys.
 *
 * The account identity is shared by every device, so it cannot authenticate one
 * device to another or carry a key agreement that distinguishes them. Each
 * device therefore generates its own Ed25519 signing key and X25519 agreement
 * key, and publishes the public halves in an account-signed record. The account
 * signature is what makes a device's word trustworthy: a relay cannot invent a
 * device, and no device can impersonate a sibling.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { randomBytes } from './random';

export const KEY_SIZE = 32;
export const SIGNATURE_SIZE = 64;

export class DeviceKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeviceKeyError';
  }
}

/** A fresh `[ed25519Private, x25519Private]` pair for one device. */
export function generateDeviceKeys(): [Uint8Array, Uint8Array] {
  return [randomBytes(KEY_SIZE), randomBytes(KEY_SIZE)];
}

export function signingPublic(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey);
}

export function agreementPublic(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

export function sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array {
  return ed25519.sign(data, privateKey);
}

export function verify(publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean {
  if (publicKey.length !== KEY_SIZE || signature.length !== SIGNATURE_SIZE) return false;
  try {
    return ed25519.verify(signature, data, publicKey);
  } catch {
    return false;
  }
}

/** X25519 shared secret, rejecting the degenerate all-zero output. */
export function agreement(privateKey: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  if (peerPublic.length !== KEY_SIZE) throw new DeviceKeyError('agreement key must be 32 bytes');
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(privateKey, peerPublic);
  } catch (error) {
    throw new DeviceKeyError(String(error));
  }
  if (shared.every((byte) => byte === 0)) throw new DeviceKeyError('degenerate agreement key');
  return shared;
}

export function newAgreementPrivate(): Uint8Array {
  return randomBytes(KEY_SIZE);
}