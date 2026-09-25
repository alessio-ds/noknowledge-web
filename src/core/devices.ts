/** Per-account device lists: the piece that makes seed recovery useful.
 *
 * An **account** is an identity — the 24 words. A **device** is one mailbox plus
 * its own prekeys and its own ratchet sessions.
 *
 * Devices cannot share a mailbox: whichever device polled first would consume
 * the message and ack it, and devices cannot share ratchet state because each
 * would advance the chain independently and diverge.
 *
 * So each device registers itself in a signed **device list** stored at an
 * address anyone can derive from the account's *public* keys. A sender looks the
 * list up, gives each device its own Double Ratchet session, and delivers a copy
 * to each.
 *
 * Byte-compatible with the Python reference (`core/devices.py`): the same hash
 * address, the same signed payload and the same sealed record.
 *
 * The stored record is *sealed* under a key derived from the account's public
 * signing and agreement keys. Anyone holding the contact card can open it (they
 * have those keys), but the relay sees only an opaque box and so cannot group an
 * account's mailboxes together or link the record to an identity id. */

import { decrypt, encrypt, AEADError } from '../crypto/aead';
import { concat } from '../crypto/bytes';
import { b64d, b64e, canonicalJsonBytes } from '../crypto/encoding';
import { Identity, computeIdentityId } from '../crypto/identity';
import {
  DEVICE_LIST_ENC_INFO,
  DEVICE_LIST_ID_INFO,
  DEVICE_SIGN_INFO,
  ZERO_SALT,
  hkdfSha256,
} from '../crypto/kdf';
import { randomBytes } from '../crypto/random';
import { sha256 } from '@noble/hashes/sha2';

export const DEVICE_LIST_VERSION = 1;
export const DEVICE_ID_SIZE = 16;

/** Key used for the single-device fallback when a peer has no device list yet
 * (an older client, or a contact added before this feature existed). */
export const LEGACY_DEVICE = 'legacy';

export class DeviceListError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeviceListError';
  }
}

/** Address of an account's device list, derivable by anyone from its keys. */
export function deviceListId(edPublic: Uint8Array, xPublic: Uint8Array): string {
  const digest = sha256(concat(DEVICE_LIST_ID_INFO, edPublic, xPublic));
  return b64e(digest.slice(0, 16));
}

export function newDeviceId(): string {
  return b64e(randomBytes(DEVICE_ID_SIZE));
}

export interface DeviceInboxView {
  id: string;
  w: string;
}

export class DeviceEntry {
  constructor(
    public deviceId: string,
    public inbox: DeviceInboxView,
    public relays: string[],
    public bundleId: string,
    public name = '',
  ) {}

  toDict(): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      device: this.deviceId,
      inbox: { id: this.inbox.id, w: this.inbox.w },
      relays: [...this.relays],
      bundle: this.bundleId,
    };
    if (this.name) payload.name = this.name;
    return payload;
  }

  static fromDict(data: any): DeviceEntry {
    try {
      return new DeviceEntry(
        String(data.device),
        { id: String(data.inbox.id), w: String(data.inbox.w) },
        [...data.relays].map((url: unknown) => String(url)),
        String(data.bundle),
        String(data.name ?? ''),
      );
    } catch {
      throw new DeviceListError('malformed device entry');
    }
  }
}

export class DeviceList {
  constructor(
    public account: string,
    public devices: DeviceEntry[],
    public updated: number,
    public isign: Uint8Array,
    public idh: Uint8Array,
    public signature: Uint8Array = new Uint8Array(0),
    public version: number = DEVICE_LIST_VERSION,
  ) {}

  // -- serialisation ----------------------------------------------------

  address(): string {
    return deviceListId(this.isign, this.idh);
  }

  payload(): Record<string, unknown> {
    return {
      v: this.version,
      account: this.account,
      isign: b64e(this.isign),
      idh: b64e(this.idh),
      // The relay's prekey endpoint requires a bundle_id field; the device list
      // address serves as one, which keeps the relay unchanged.
      bundle_id: this.address(),
      updated: Math.trunc(this.updated),
      devices: this.devices.map((device) => device.toDict()),
    };
  }

  private signedBytes(): Uint8Array {
    return concat(DEVICE_SIGN_INFO, canonicalJsonBytes(this.payload()));
  }

  /** The signed plaintext, before sealing. */
  toBytes(): Uint8Array {
    const data = this.payload();
    data.sig = b64e(this.signature);
    return canonicalJsonBytes(data);
  }

  static fromBytes(data: Uint8Array | string | Record<string, unknown>): DeviceList {
    let parsed: any = data;
    if (typeof parsed === 'string' || parsed instanceof Uint8Array) {
      const text = typeof parsed === 'string' ? parsed : new TextDecoder('utf-8').decode(parsed);
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new DeviceListError('device list is not valid JSON');
      }
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new DeviceListError('device list is not an object');
    }
    if (parsed.v !== DEVICE_LIST_VERSION) {
      throw new DeviceListError(`unsupported device list version: ${parsed.v}`);
    }
    let isign: Uint8Array;
    let idh: Uint8Array;
    let account: string;
    let devices: DeviceEntry[];
    let updated: number;
    let signature: Uint8Array;
    try {
      isign = b64d(String(parsed.isign));
      idh = b64d(String(parsed.idh));
      account = String(parsed.account);
      devices = (parsed.devices as any[]).map((entry) => DeviceEntry.fromDict(entry));
      updated = Number(parsed.updated);
      signature = b64d(String(parsed.sig));
    } catch (error) {
      if (error instanceof DeviceListError) throw error;
      throw new DeviceListError('malformed device list');
    }

    if (computeIdentityId(isign, idh) !== account) {
      throw new DeviceListError('device list account does not match its keys');
    }
    if (devices.length === 0) throw new DeviceListError('device list has no devices');

    const listing = new DeviceList(account, devices, updated, isign, idh, signature);
    if (!Identity.verify(isign, signature, listing.signedBytes())) {
      throw new DeviceListError('device list signature is invalid');
    }
    return listing;
  }

  // -- construction -----------------------------------------------------

  static create(identity: Identity, devices: DeviceEntry[], updated?: number): DeviceList {
    const listing = new DeviceList(
      identity.identityId,
      [...devices],
      Math.trunc(updated ?? Date.now()),
      identity.edPublicBytes,
      identity.xPublicBytes,
    );
    listing.signature = identity.sign(listing.signedBytes());
    return listing;
  }

  /** A copy of this list with `entry` added or replaced. */
  withDevice(entry: DeviceEntry): DeviceList {
    const others = this.devices.filter((device) => device.deviceId !== entry.deviceId);
    return new DeviceList(this.account, [...others, entry], Date.now(), this.isign, this.idh);
  }

  /** Whether this list is really the one for the peer we asked about. */
  belongsTo(account: string, isign: Uint8Array, idh: Uint8Array): boolean {
    return this.account === account && bytesEqual(this.isign, isign) && bytesEqual(this.idh, idh);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let index = 0; index < a.length; index += 1) if (a[index] !== b[index]) return false;
  return true;
}

// -- sealed storage -------------------------------------------------------
//
// The record the relay holds must not tie an identity id to a set of mailboxes.
// The key is derived from public values the peer already has, so this is
// obfuscation against the relay, not secrecy against the peer.

/** Sealing key for one account's device list, from its public keys. */
export function deviceListKey(isign: Uint8Array, idh: Uint8Array): Uint8Array {
  return hkdfSha256(concat(isign, idh), ZERO_SALT, DEVICE_LIST_ENC_INFO, 32);
}

/** The opaque record to publish on a relay. */
export function sealDeviceList(listing: DeviceList): Uint8Array {
  const [nonce, ciphertext] = encrypt(deviceListKey(listing.isign, listing.idh), listing.toBytes());
  return canonicalJsonBytes({
    v: DEVICE_LIST_VERSION,
    // The prekey endpoint keys its rows by this field, so it has to stay
    // visible; it is a public hash of the account keys, nothing more.
    bundle_id: listing.address(),
    box: b64e(concat(nonce, ciphertext)),
  });
}

/** Open a record fetched from a relay, using the peer's public keys. */
export function openDeviceList(
  data: Uint8Array | string | Record<string, unknown>,
  isign: Uint8Array,
  idh: Uint8Array,
): DeviceList {
  let raw: any = data;
  if (typeof raw === 'string' || raw instanceof Uint8Array) {
    const text = typeof raw === 'string' ? raw : new TextDecoder('utf-8').decode(raw);
    if (text.length === 0 || text[0] !== '{') {
      // A relay answered with something that is not a record at all.
      throw new DeviceListError('device list is not valid JSON');
    }
    try {
      raw = JSON.parse(text);
    } catch {
      throw new DeviceListError('device list is not valid JSON');
    }
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new DeviceListError('device list is not an object');
  }
  if (raw.box === undefined || raw.box === null) {
    // Unsealed record: nothing published by this version looks like that, but an
    // older or handcrafted one may, and reading it is harmless.
    return DeviceList.fromBytes(raw);
  }
  let blob: Uint8Array;
  try {
    blob = b64d(String(raw.box));
  } catch {
    throw new DeviceListError('device list box is not valid base64');
  }
  if (blob.length <= 12) throw new DeviceListError('device list box is truncated');
  let plaintext: Uint8Array;
  try {
    plaintext = decrypt(deviceListKey(isign, idh), blob.slice(0, 12), blob.slice(12));
  } catch (error) {
    if (error instanceof AEADError) throw new DeviceListError('device list could not be opened');
    throw error;
  }
  return DeviceList.fromBytes(plaintext);
}