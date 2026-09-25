/** Identity: an Ed25519 signing key and an X25519 key-agreement key.
 *
 * Both keys are derived deterministically from a BIP39 mnemonic, so an identity
 * can be restored from 24 words. The derived `identity_id` is a cryptographic
 * fingerprint computed offline; it is never transmitted to a relay. The vault
 * format is byte-compatible with the Python desktop client. */

import { gcm } from '@noble/ciphers/aes';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha2';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { concat, utf8Decode, utf8Encode } from './bytes';
import { b32e, b64d, b64e, canonicalJsonBytes } from './encoding';
import { ID_HASH_INFO, IDENTITY_INFO, hkdfSha256 } from './kdf';
import { randomBytes } from './random';

export const MNEMONIC_STRENGTH = 256; // 24 words
export const VAULT_VERSION = 1;
export const PBKDF2_ITERATIONS = 600_000;
export const ED_SEED_SIZE = 32;
export const X_SEED_SIZE = 32;

export class IdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityError';
  }
}

/** 26-character Crockford base32 fingerprint of the public keys. */
export function computeIdentityId(edPublic: Uint8Array, xPublic: Uint8Array): string {
  return b32e(sha256(concat(ID_HASH_INFO, edPublic, xPublic))).slice(0, 26);
}

export function deriveKeys(seed: Uint8Array): { edSeed: Uint8Array; xSeed: Uint8Array } {
  const root = hkdfSha256(seed, new Uint8Array(0), IDENTITY_INFO, 64);
  return { edSeed: root.slice(0, 32), xSeed: root.slice(32, 64) };
}

function normalizeMnemonic(mnemonic: string): string {
  return mnemonic.trim().split(/\s+/).join(' ');
}

/** A long-term identity. Pure data plus signing; performs no I/O. */
export class Identity {
  readonly edPrivate: Uint8Array;
  readonly xPrivate: Uint8Array;
  readonly edPublic: Uint8Array;
  readonly xPublic: Uint8Array;
  label: string | null;

  constructor(edPrivate: Uint8Array, xPrivate: Uint8Array, label: string | null = null) {
    if (edPrivate.length !== ED_SEED_SIZE) throw new IdentityError('invalid Ed25519 seed length');
    if (xPrivate.length !== X_SEED_SIZE) throw new IdentityError('invalid X25519 seed length');
    this.edPrivate = edPrivate;
    this.xPrivate = xPrivate;
    this.edPublic = ed25519.getPublicKey(edPrivate);
    this.xPublic = x25519.getPublicKey(xPrivate);
    this.label = label;
  }

  get edPrivateBytes(): Uint8Array {
    return this.edPrivate;
  }

  get xPrivateBytes(): Uint8Array {
    return this.xPrivate;
  }

  get edPublicBytes(): Uint8Array {
    return this.edPublic;
  }

  get xPublicBytes(): Uint8Array {
    return this.xPublic;
  }

  get identityId(): string {
    return computeIdentityId(this.edPublic, this.xPublic);
  }

  sign(data: Uint8Array): Uint8Array {
    return ed25519.sign(data, this.edPrivate);
  }

  static verify(edPublic: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean {
    if (edPublic.length !== 32 || signature.length !== 64) return false;
    try {
      return ed25519.verify(signature, data, edPublic);
    } catch {
      return false;
    }
  }

  // -- construction -----------------------------------------------------

  /** Create a new identity. Returns `[identity, mnemonic]`. */
  static generate(label?: string | null, passphrase?: string): [Identity, string] {
    const mnemonic = generateMnemonic(wordlist, MNEMONIC_STRENGTH);
    return [Identity.fromMnemonic(mnemonic, passphrase ?? '', label ?? null), mnemonic];
  }

  static fromMnemonic(
    mnemonic: string,
    passphrase = '',
    label: string | null = null,
  ): Identity {
    const normalized = normalizeMnemonic(mnemonic);
    if (!validateMnemonic(normalized, wordlist)) {
      throw new IdentityError('invalid BIP39 mnemonic');
    }
    const seed = mnemonicToSeedSync(normalized, passphrase);
    const { edSeed, xSeed } = deriveKeys(seed);
    return new Identity(edSeed, xSeed, label);
  }

  static fromPrivateBytes(
    edSeed: Uint8Array,
    xSeed: Uint8Array,
    label: string | null = null,
  ): Identity {
    return new Identity(edSeed, xSeed, label);
  }

  // -- vault persistence ------------------------------------------------

  private secretBlob(): Uint8Array {
    return concat(this.edPrivate, this.xPrivate);
  }

  /** Serialise the identity, optionally encrypted under a passphrase. */
  toVault(passphrase?: string): Uint8Array {
    const secret = this.secretBlob();
    const payload: Record<string, unknown> = {
      v: VAULT_VERSION,
      id: this.identityId,
      label: this.label,
      encrypted: Boolean(passphrase),
    };
    if (passphrase) {
      const salt = randomBytes(16);
      const iterations = PBKDF2_ITERATIONS;
      const key = pbkdf2(sha256, utf8Encode(passphrase), salt, {
        c: iterations,
        dkLen: 32,
      });
      const nonce = randomBytes(12);
      const aad = canonicalJsonBytes({ id: this.identityId });
      const blob = gcm(key, nonce, aad).encrypt(secret);
      payload.kdf = { salt: b64e(salt), iterations };
      payload.nonce = b64e(nonce);
      payload.secret = b64e(blob);
    } else {
      payload.secret = b64e(secret);
    }
    return utf8Encode(JSON.stringify(payload, null, 2));
  }

  static fromVault(data: string | Uint8Array, passphrase?: string): Identity {
    let text: string;
    if (typeof data === 'string') text = data;
    else text = utf8Decode(data);
    let payload: any;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new IdentityError('vault is not valid JSON');
    }
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new IdentityError('vault is not a JSON object');
    }
    if (payload.v !== VAULT_VERSION) {
      throw new IdentityError(`unsupported vault version: ${payload.v}`);
    }
    const blob = b64d(String(payload.secret));
    let secret: Uint8Array;
    if (payload.encrypted) {
      if (!passphrase) throw new IdentityError('vault is encrypted but no passphrase was given');
      const kdfParams = payload.kdf ?? {};
      const key = pbkdf2(sha256, utf8Encode(passphrase), b64d(String(kdfParams.salt)), {
        c: Number(kdfParams.iterations),
        dkLen: 32,
      });
      try {
        secret = gcm(key, b64d(String(payload.nonce)), canonicalJsonBytes({ id: payload.id })).decrypt(blob);
      } catch {
        throw new IdentityError('wrong passphrase or corrupted vault');
      }
    } else {
      if (passphrase) throw new IdentityError('vault is not encrypted; remove the passphrase');
      secret = blob;
    }
    if (secret.length !== ED_SEED_SIZE + X_SEED_SIZE) {
      throw new IdentityError('vault secret has the wrong length');
    }
    const identity = Identity.fromPrivateBytes(
      secret.slice(0, ED_SEED_SIZE),
      secret.slice(ED_SEED_SIZE),
      payload.label ?? null,
    );
    if (identity.identityId !== payload.id) {
      throw new IdentityError('vault does not match its recorded identity id');
    }
    return identity;
  }
}

