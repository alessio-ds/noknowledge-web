/** Wire message framing.
 *
 * A relay blob is a small JSON object whose only cleartext fields are a random
 * pseudonymous session id, the ratchet header and the ciphertext. The handshake
 * header (`init`) appears only on the first message of a session, and contains
 * only ephemeral public material — never an identity key. */

import { b64d, b64e, canonicalJsonBytes } from '../crypto/encoding';
import {
  DEFAULT_MAX,
  MAX_ATTACHMENT_ENVELOPE,
  padEnvelope,
  unpadEnvelope,
} from '../crypto/padding';
import { Ratchet } from '../crypto/ratchet';
import { WireError } from './errors';

export const WIRE_VERSION = 1;
export const ENVELOPE_VERSION = 1;

export function buildWire(
  sid: Uint8Array,
  header: unknown,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  init: Record<string, unknown> | null = null,
): Uint8Array {
  const wire: Record<string, unknown> = {
    v: WIRE_VERSION,
    sid: b64e(sid),
    hdr: header,
    nonce: b64e(nonce),
    ct: b64e(ciphertext),
  };
  if (init !== null) wire.init = init;
  return canonicalJsonBytes(wire);
}

export function parseWire(blob: Uint8Array | string): any {
  let text: string;
  if (typeof blob === 'string') text = blob;
  else {
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(blob);
    } catch {
      throw new WireError('wire message is not UTF-8');
    }
  }
  let wire: any;
  try {
    wire = JSON.parse(text);
  } catch {
    throw new WireError('wire message is not valid JSON');
  }
  if (wire === null || typeof wire !== 'object' || Array.isArray(wire)) {
    throw new WireError('wire message is not an object');
  }
  if (wire.v !== WIRE_VERSION) {
    throw new WireError(`unsupported wire version: ${wire.v}`);
  }
  for (const field of ['sid', 'hdr', 'nonce', 'ct']) {
    if (!(field in wire)) throw new WireError(`wire message is missing '${field}'`);
  }
  return wire;
}

/** Pad, encrypt and frame an envelope for the relay. */
export function seal(
  ratchet: Ratchet,
  envelope: Record<string, unknown>,
  sid: Uint8Array,
  init: Record<string, unknown> | null = null,
  maxSize: number | null = null,
): Uint8Array {
  const limit = maxSize ?? DEFAULT_MAX;
  const plaintext = padEnvelope(envelope, limit);
  const { header, nonce, ciphertext } = ratchet.encrypt(plaintext, init);
  return buildWire(sid, header, nonce, ciphertext, init);
}

/** Parse, decrypt and unpad a relay blob.
 *
 * Returns `[envelope, sid, init]` where `init` is present only for the first
 * message of a session. */
export function unseal(
  ratchet: Ratchet,
  blob: Uint8Array | string,
): [Record<string, unknown>, Uint8Array, Record<string, unknown> | null] {
  const wire = parseWire(blob);
  const init = wire.init ?? null;
  let plaintext: Uint8Array;
  try {
    plaintext = ratchet.decrypt(
      wire.hdr,
      b64d(String(wire.nonce)),
      b64d(String(wire.ct)),
      init,
    );
  } catch (error) {
    throw new WireError(`could not open message: ${(error as Error).message}`);
  }
  return [unpadEnvelope(plaintext), b64d(String(wire.sid)), init];
}

export function makeEnvelope(
  kind: string,
  body: Record<string, unknown>,
  messageId: string,
  timestampMs: number,
  auth?: Record<string, unknown> | null,
  card?: Record<string, unknown> | null,
): Record<string, unknown> {
  const envelope: Record<string, unknown> = {
    v: ENVELOPE_VERSION,
    type: kind,
    id: messageId,
    ts: Math.trunc(timestampMs),
    body,
  };
  if (auth != null) envelope.auth = auth;
  if (card != null) envelope.card = card;
  return envelope;
}

export function envelopeMaxSize(kind: string): number {
  return kind === 'file' ? MAX_ATTACHMENT_ENVELOPE : DEFAULT_MAX;
}
