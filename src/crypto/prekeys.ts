/** Prekey bundles: signed prekeys and one-time prekeys for asynchronous X3DH.
 *
 * A recipient publishes a signed bundle under a random `bundle_id`. The relay
 * returns at most one unused one-time prekey per fetch, consumed atomically.
 * Because the bundle carries an Ed25519 signature over the signed prekey, a
 * malicious relay cannot substitute keys without detection. */

import { concat, u32be } from './bytes';
import { b64d, b64e, canonicalJsonBytes } from './encoding';
import { Identity } from './identity';
import { SPK_SIGN_INFO } from './kdf';
import { randomBytes } from './random';

export const BUNDLE_VERSION = 1;
export const BUNDLE_ID_SIZE = 16;
export const MAX_OPKS = 100;

export class PrekeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PrekeyError';
  }
}

function spkSignature(
  identity: Identity,
  bundleId: Uint8Array,
  spkId: number,
  spk: Uint8Array,
): Uint8Array {
  return identity.sign(concat(SPK_SIGN_INFO, bundleId, u32be(spkId), spk));
}

export class PrekeyBundle {
  constructor(
    public bundleId: Uint8Array,
    public isign: Uint8Array,
    public idh: Uint8Array,
    public spkId: number,
    public spk: Uint8Array,
    public spkSig: Uint8Array,
    public opks: Array<[number, Uint8Array]> = [],
  ) {}

  /** Full client-side representation, including identity keys. */
  toDict(): Record<string, unknown> {
    return {
      v: BUNDLE_VERSION,
      bundle_id: b64e(this.bundleId),
      isign: b64e(this.isign),
      idh: b64e(this.idh),
      spk_id: this.spkId,
      spk: b64e(this.spk),
      spk_sig: b64e(this.spkSig),
      opks: this.opks.map(([opkId, opk]) => ({ opk_id: opkId, opk: b64e(opk) })),
    };
  }

  /** What is published to a relay: **no identity keys**. */
  toPublicDict(): Record<string, unknown> {
    return {
      v: BUNDLE_VERSION,
      bundle_id: b64e(this.bundleId),
      spk_id: this.spkId,
      spk: b64e(this.spk),
      spk_sig: b64e(this.spkSig),
      opks: this.opks.map(([opkId, opk]) => ({ opk_id: opkId, opk: b64e(opk) })),
    };
  }

  static fromDict(data: any): PrekeyBundle {
    if (data?.v !== BUNDLE_VERSION) {
      throw new PrekeyError(`unsupported bundle version: ${data?.v}`);
    }
    try {
      return new PrekeyBundle(
        b64d(String(data.bundle_id)),
        data.isign ? b64d(String(data.isign)) : new Uint8Array(0),
        data.idh ? b64d(String(data.idh)) : new Uint8Array(0),
        Number(data.spk_id),
        b64d(String(data.spk)),
        b64d(String(data.spk_sig)),
        (data.opks ?? []).map((o: any): [number, Uint8Array] => [
          Number(o.opk_id),
          b64d(String(o.opk)),
        ]),
      );
    } catch {
      throw new PrekeyError('malformed prekey bundle');
    }
  }

  /** Rehydrate a published bundle using identity keys from the card. */
  static fromPublic(data: Uint8Array | string | Record<string, unknown>, isign: Uint8Array, idh: Uint8Array): PrekeyBundle {
    let obj: any = data;
    if (typeof data === 'string') obj = JSON.parse(data);
    else if (data instanceof Uint8Array) obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
    const bundle = PrekeyBundle.fromDict(obj);
    bundle.isign = isign;
    bundle.idh = idh;
    return bundle;
  }

  /** Canonical wire form published to the relay (no identity keys). */
  toBytes(): Uint8Array {
    return canonicalJsonBytes(this.toPublicDict());
  }
}

/** Build and sign a bundle for publication. */
export function makeBundle(
  identity: Identity,
  bundleId: Uint8Array,
  spkId: number,
  spkPublic: Uint8Array,
  opks: Array<[number, Uint8Array]> = [],
): PrekeyBundle {
  if (bundleId.length !== BUNDLE_ID_SIZE) throw new PrekeyError('bundle_id must be 16 bytes');
  if (opks.length > MAX_OPKS) throw new PrekeyError(`at most ${MAX_OPKS} one-time prekeys per bundle`);
  return new PrekeyBundle(
    bundleId,
    identity.edPublicBytes,
    identity.xPublicBytes,
    spkId,
    spkPublic,
    spkSignature(identity, bundleId, spkId, spkPublic),
    [...opks],
  );
}

/** Verify a bundle against the identity key taken from a signed card. */
export function verifyBundle(bundle: PrekeyBundle, expectedIsign: Uint8Array): void {
  if (bundle.isign.length !== expectedIsign.length || !bundle.isign.every((b, i) => b === expectedIsign[i])) {
    throw new PrekeyError('bundle identity key does not match the contact card');
  }
  if (bundle.spk.length !== 32 || bundle.idh.length !== 32) {
    throw new PrekeyError('bundle contains malformed public keys');
  }
  const message = concat(SPK_SIGN_INFO, bundle.bundleId, u32be(bundle.spkId), bundle.spk);
  if (!Identity.verify(bundle.isign, bundle.spkSig, message)) {
    throw new PrekeyError('signed prekey signature is invalid');
  }
}

export function newBundleId(): Uint8Array {
  return randomBytes(BUNDLE_ID_SIZE);
}
