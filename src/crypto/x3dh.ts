/** Anonymous X3DH handshake.
 *
 * Classic X3DH places the initiator's identity key in the clear, which would
 * hand the relay the sender's identity. noknowledge instead contributes only an
 * ephemeral key: the initiator's identity is proven *inside* the encrypted
 * payload by the `auth` block. This is what makes the relay unable to learn who
 * sent a message.
 *
 *     SK = HKDF( F || DH(EK, IK_b) || DH(EK, SPK_b) [|| DH(EK, OPK_b)] ) */

import { x25519 } from '@noble/curves/ed25519';
import { concat } from './bytes';
import { b64d, b64e, canonicalJsonBytes } from './encoding';
import { Identity, computeIdentityId } from './identity';
import { AUTH_SIGN_INFO, F, X3DH_INFO, ZERO_SALT, hkdfSha256, skCommitment } from './kdf';
import { PrekeyBundle, PrekeyError, verifyBundle } from './prekeys';
import { randomBytes } from './random';

export const INIT_VERSION = 1;
export const KEY_SIZE = 32;

export class HandshakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HandshakeError';
  }
}

export function generateKeypair(): [Uint8Array, Uint8Array] {
  const priv = randomBytes(32);
  return [priv, x25519.getPublicKey(priv)];
}

export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  try {
    return x25519.getSharedSecret(privateKey, publicKey);
  } catch {
    throw new HandshakeError('malformed X25519 key');
  }
}

/** Everything the initiator needs to start a ratchet and emit message one. */
export interface Initiation {
  ekPublic: Uint8Array;
  ekPrivate: Uint8Array;
  spkId: number;
  opkId: number | null;
  sk: Uint8Array;
}

export function initDict(initiation: Initiation): Record<string, unknown> {
  return {
    ek: b64e(initiation.ekPublic),
    spk_id: initiation.spkId,
    opk_id: initiation.opkId,
  };
}

/** Perform the initiator half of the handshake.
 *
 * `expectedIsign` and `expectedIdh` must come from the signed contact card,
 * never from the relay response. */
export function initiate(
  bundle: PrekeyBundle,
  expectedIsign: Uint8Array,
  expectedIdh: Uint8Array,
  ephemeralPrivate?: Uint8Array,
): Initiation {
  try {
    verifyBundle(bundle, expectedIsign);
  } catch (error) {
    if (error instanceof PrekeyError) throw new HandshakeError(`prekey bundle rejected: ${error.message}`);
    throw error;
  }
  if (bundle.idh.length !== expectedIdh.length || !bundle.idh.every((b, i) => b === expectedIdh[i])) {
    throw new HandshakeError('bundle identity key disagrees with the contact card');
  }

  const ekPrivate = ephemeralPrivate ?? randomBytes(32);
  const ekPublic = x25519.getPublicKey(ekPrivate);
  const dh1 = dh(ekPrivate, bundle.idh);
  const dh2 = dh(ekPrivate, bundle.spk);
  let dh3: Uint8Array = new Uint8Array(0);
  let opkId: number | null = null;
  if (bundle.opks.length > 0) {
    const [id, opkPublic] = bundle.opks[0];
    opkId = id;
    dh3 = dh(ekPrivate, opkPublic);
  }
  const sk = hkdfSha256(concat(F, dh1, dh2, dh3), ZERO_SALT, X3DH_INFO, KEY_SIZE);
  return { ekPublic, ekPrivate, spkId: bundle.spkId, opkId, sk };
}

/** Perform the responder half of the handshake, returning the shared secret. */
export function respond(
  identityXPrivate: Uint8Array,
  signedPrekeyPrivate: Uint8Array,
  opkPrivate: Uint8Array | null,
  ekPublic: Uint8Array,
): Uint8Array {
  const dh1 = dh(identityXPrivate, ekPublic);
  const dh2 = dh(signedPrekeyPrivate, ekPublic);
  const dh3 = opkPrivate ? dh(opkPrivate, ekPublic) : new Uint8Array(0);
  return hkdfSha256(concat(F, dh1, dh2, dh3), ZERO_SALT, X3DH_INFO, KEY_SIZE);
}

// -- sender authentication (sealed-sender style) ------------------------

export interface Auth {
  v: number;
  id: string;
  isign: string;
  idh: string;
  sk_commit: string;
  sig: string;
}

/** Build the in-ciphertext proof binding a sender identity to a session. */
export function buildAuth(
  identity: Identity,
  sid: Uint8Array,
  init: Record<string, unknown>,
  sk: Uint8Array,
): Auth {
  const commit = skCommitment(sk);
  const message = concat(AUTH_SIGN_INFO, sid, canonicalJsonBytes(init), commit);
  return {
    v: INIT_VERSION,
    id: identity.identityId,
    isign: b64e(identity.edPublicBytes),
    idh: b64e(identity.xPublicBytes),
    sk_commit: b64e(commit),
    sig: b64e(identity.sign(message)),
  };
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Verify the sender proof. Returns `false` on any failure. */
export function verifyAuth(
  auth: any,
  sid: Uint8Array,
  init: Record<string, unknown>,
  sk: Uint8Array,
): boolean {
  try {
    if (auth?.v !== INIT_VERSION) return false;
    const expectedCommit = skCommitment(sk);
    if (!constantTimeEqual(b64d(String(auth.sk_commit)), expectedCommit)) return false;
    const isign = b64d(String(auth.isign));
    const idh = b64d(String(auth.idh));
    if (computeIdentityId(isign, idh) !== auth.id) return false;
    const message = concat(AUTH_SIGN_INFO, sid, canonicalJsonBytes(init), expectedCommit);
    return Identity.verify(isign, b64d(String(auth.sig)), message);
  } catch {
    return false;
  }
}
