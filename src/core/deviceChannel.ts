/** The device-to-device channel.
 *
 * Two devices of one account talk directly, through each other's mailboxes, with
 * a key nobody else holds — not the relay, and not the account's contacts.
 * Byte-compatible with the Python reference (`core/device_channel.py`).
 *
 * Every record is sealed with ECIES: the sender generates an ephemeral X25519
 * key, agrees it with the recipient device's published agreement key, and
 * derives a one-purpose key from that secret. The record header is signed by the
 * sender's device key, so the recipient can tell which device spoke and check
 * that it really is a device of this account. Every header field is also the
 * AEAD associated data, so nothing can be altered in flight.
 */

import { sha256 } from '@noble/hashes/sha2';
import { decrypt, encryptWithNonce, AEADError } from '../crypto/aead';
import { concat, utf8Decode, utf8Encode } from '../crypto/bytes';
import { agreement, agreementPublic, newAgreementPrivate, sign, verify } from '../crypto/deviceKeys';
import { b64d, b64e, canonicalJsonBytes } from '../crypto/encoding';
import { DEVICE_SYNC_INFO, DEVICE_SYNC_ITEM_INFO, hkdfSha256 } from '../crypto/kdf';
import { randomBytes } from '../crypto/random';

export const MAGIC = utf8Encode('NKS1');
export const VERSION = 1;
/** magic(4) + version(1) + kind(1) + reserved(2) + header length(4). */
export const PREFIX_BYTES = 12;

// Record kinds. Numbers are wire-visible: never renumber one.
export const REQUEST = 1;
export const OFFER = 2;
export const ITEM = 3;
export const COMPLETE = 4;
export const APPROVAL = 5;
export const MIRROR = 6;

export class SyncError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SyncError';
  }
}

export function isDeviceRecord(blob: Uint8Array): boolean {
  if (blob.length < PREFIX_BYTES) return false;
  return MAGIC.every((byte, index) => blob[index] === byte);
}

function frame(kind: number, header: unknown, payload: Uint8Array): Uint8Array {
  const headerBytes = canonicalJsonBytes(header);
  const out = new Uint8Array(PREFIX_BYTES + headerBytes.length + payload.length);
  out.set(MAGIC, 0);
  out[4] = VERSION;
  out[5] = kind;
  out[8] = (headerBytes.length >>> 24) & 0xff;
  out[9] = (headerBytes.length >>> 16) & 0xff;
  out[10] = (headerBytes.length >>> 8) & 0xff;
  out[11] = headerBytes.length & 0xff;
  out.set(headerBytes, PREFIX_BYTES);
  out.set(payload, PREFIX_BYTES + headerBytes.length);
  return out;
}

export function parseRecord(blob: Uint8Array): [number, Record<string, unknown>, Uint8Array] {
  if (!isDeviceRecord(blob)) throw new SyncError('not a device record');
  const version = blob[4];
  if (version !== VERSION) throw new SyncError(`unsupported device record version: ${version}`);
  const kind = blob[5];
  const headerLength = (blob[8] << 24) | (blob[9] << 16) | (blob[10] << 8) | blob[11];
  if (headerLength <= 0 || blob.length < PREFIX_BYTES + headerLength) {
    throw new SyncError('device record is truncated');
  }
  let header: unknown;
  try {
    header = JSON.parse(utf8Decode(blob.slice(PREFIX_BYTES, PREFIX_BYTES + headerLength)));
  } catch {
    throw new SyncError('device record header is malformed');
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    throw new SyncError('device record header is not an object');
  }
  return [kind, header as Record<string, unknown>, blob.slice(PREFIX_BYTES + headerLength)];
}

export function transferKey(shared: Uint8Array, transferId: string): Uint8Array {
  return hkdfSha256(shared, utf8Encode(transferId), DEVICE_SYNC_INFO, 32);
}

export function itemKey(key: Uint8Array, seq: number): Uint8Array {
  const counter = new Uint8Array(4);
  counter[0] = (seq >>> 24) & 0xff;
  counter[1] = (seq >>> 16) & 0xff;
  counter[2] = (seq >>> 8) & 0xff;
  counter[3] = seq & 0xff;
  return hkdfSha256(key, new Uint8Array(0), concat(DEVICE_SYNC_ITEM_INFO, counter), 32);
}

export function newTransferId(): string {
  return b64e(randomBytes(16));
}

function unsigned(header: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(header)) {
    if (key !== 'sig') out[key] = value;
  }
  return out;
}

export function sealRecord(
  kind: number,
  plaintext: Uint8Array,
  options: {
    recipientSagree: Uint8Array;
    senderDeviceId: string;
    senderSdevPrivate: Uint8Array;
    transferId: string;
    seq?: number;
    extra?: Record<string, unknown>;
  },
): Uint8Array {
  const seq = options.seq ?? 0;
  const ephemeralPrivate = newAgreementPrivate();
  const shared = agreement(ephemeralPrivate, options.recipientSagree);
  const key = transferKey(shared, options.transferId);

  const header: Record<string, unknown> = {
    v: VERSION,
    transfer: options.transferId,
    from: options.senderDeviceId,
    eph: b64e(agreementPublic(ephemeralPrivate)),
    ts: Date.now(),
    seq,
    ...(options.extra ?? {}),
  };
  header.sig = b64e(sign(options.senderSdevPrivate, canonicalJsonBytes(unsigned(header))));

  const ad = canonicalJsonBytes(header);
  const nonce = randomBytes(12);
  const ciphertext = encryptWithNonce(itemKey(key, seq), nonce, plaintext, ad);
  return frame(kind, header, concat(nonce, ciphertext));
}

export function openRecord(
  blob: Uint8Array,
  options: {
    mySagreePrivate: Uint8Array;
    senderSdev: Uint8Array;
    senderDeviceId: string;
  },
): [number, Record<string, unknown>, Uint8Array] {
  const [kind, header, payload] = parseRecord(blob);
  if (String(header.from) !== options.senderDeviceId) {
    throw new SyncError('device record is from an unexpected device');
  }
  let signature: Uint8Array;
  let ephemeral: Uint8Array;
  let transferId: string;
  let seq: number;
  try {
    signature = b64d(String(header.sig));
    ephemeral = b64d(String(header.eph));
    transferId = String(header.transfer);
    seq = Number(header.seq ?? 0);
  } catch {
    throw new SyncError('device record header is incomplete');
  }
  if (!verify(options.senderSdev, signature, canonicalJsonBytes(unsigned(header)))) {
    throw new SyncError('device record signature is invalid');
  }

  const shared = agreement(options.mySagreePrivate, ephemeral);
  const key = transferKey(shared, transferId);
  if (payload.length <= 12) throw new SyncError('device record payload is truncated');
  const ad = canonicalJsonBytes(header);
  let plaintext: Uint8Array;
  try {
    plaintext = decrypt(itemKey(key, seq), payload.slice(0, 12), payload.slice(12), ad);
  } catch (error) {
    if (error instanceof AEADError) throw new SyncError('device record could not be opened');
    throw error;
  }
  return [kind, header, plaintext];
}

/** Ordered digest of the items in a transfer.
 *
 * Each item is authenticated on its own, so this exists to notice a transfer that
 * stopped early: the sender's final digest only matches if every item arrived, in
 * order. The running digest is a hex string between calls, so a receiver keeps it
 * in its store and resumes across restarts. */
export class HashChain {
  private digest: Uint8Array;

  constructor(seed = '', resumed = '') {
    this.digest = resumed ? hexToBytes(resumed) : sha256(utf8Encode(seed));
  }

  add(item: Uint8Array, seq: number): void {
    const counter = new Uint8Array(4);
    counter[0] = (seq >>> 24) & 0xff;
    counter[1] = (seq >>> 16) & 0xff;
    counter[2] = (seq >>> 8) & 0xff;
    counter[3] = seq & 0xff;
    this.digest = sha256(concat(this.digest, counter, item));
  }

  hexdigest(): string {
    return Array.from(this.digest)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }
}

function hexToBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}
