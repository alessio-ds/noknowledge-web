/** Double Ratchet.
 *
 * Implements the Signal Double Ratchet over the X3DH root key: symmetric chain
 * keys for per-message forward secrecy, and a DH ratchet for post-compromise
 * security. Out-of-order messages are supported through a bounded skipped-key
 * cache; replays fail because message keys are consumed on use.
 *
 * Decryption is **transactional**: if authentication fails, the session state is
 * rolled back exactly. A tampered or unrelated message therefore cannot desync
 * an otherwise healthy session. */

import { x25519 } from '@noble/curves/ed25519';
import * as aead from './aead';
import { concat, equalBytes, utf8Encode } from './bytes';
import { b64d, b64e, canonicalJsonBytes } from './encoding';
import { kdfCk, kdfRk } from './kdf';
import { randomBytes } from './random';

export const MAX_SKIP = 1000;
export const AD_DOMAIN = utf8Encode('nk/v1/msg');

export class RatchetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RatchetError';
  }
}

export class DuplicateMessage extends RatchetError {
  constructor(message: string) {
    super(message);
    this.name = 'DuplicateMessage';
  }
}

export class SkippedTooFar extends RatchetError {
  constructor(message: string) {
    super(message);
    this.name = 'SkippedTooFar';
  }
}

function newKeypair(): [Uint8Array, Uint8Array] {
  const priv = randomBytes(32);
  return [priv, x25519.getPublicKey(priv)];
}

function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

export class RatchetState {
  constructor(
    public rootKey: Uint8Array,
    public sendingChain: Uint8Array | null = null,
    public receivingChain: Uint8Array | null = null,
    public dhSelfPrivate: Uint8Array | null = null,
    public dhSelfPublic: Uint8Array | null = null,
    public dhRemote: Uint8Array | null = null,
    public sendCount = 0,
    public recvCount = 0,
    public prevSendCount = 0,
    public skipped: Map<string, Uint8Array> = new Map(),
  ) {}

  clone(): RatchetState {
    return new RatchetState(
      this.rootKey.slice(),
      this.sendingChain ? this.sendingChain.slice() : null,
      this.receivingChain ? this.receivingChain.slice() : null,
      this.dhSelfPrivate ? this.dhSelfPrivate.slice() : null,
      this.dhSelfPublic ? this.dhSelfPublic.slice() : null,
      this.dhRemote ? this.dhRemote.slice() : null,
      this.sendCount,
      this.recvCount,
      this.prevSendCount,
      new Map(this.skipped),
    );
  }

  toDict(): Record<string, unknown> {
    const skipped: Record<string, string> = {};
    for (const [key, value] of this.skipped) skipped[key] = b64e(value);
    return {
      v: 1,
      rk: b64e(this.rootKey),
      cks: this.sendingChain ? b64e(this.sendingChain) : null,
      ckr: this.receivingChain ? b64e(this.receivingChain) : null,
      dhs_priv: this.dhSelfPrivate ? b64e(this.dhSelfPrivate) : null,
      dhs_pub: this.dhSelfPublic ? b64e(this.dhSelfPublic) : null,
      dhr: this.dhRemote ? b64e(this.dhRemote) : null,
      ns: this.sendCount,
      nr: this.recvCount,
      pn: this.prevSendCount,
      skipped,
    };
  }

  static fromDict(data: any): RatchetState {
    const skipped = new Map<string, Uint8Array>();
    for (const [key, value] of Object.entries(data?.skipped ?? {})) {
      skipped.set(key, b64d(String(value)));
    }
    return new RatchetState(
      b64d(String(data.rk)),
      data.cks ? b64d(String(data.cks)) : null,
      data.ckr ? b64d(String(data.ckr)) : null,
      data.dhs_priv ? b64d(String(data.dhs_priv)) : null,
      data.dhs_pub ? b64d(String(data.dhs_pub)) : null,
      data.dhr ? b64d(String(data.dhr)) : null,
      Number(data.ns ?? 0),
      Number(data.nr ?? 0),
      Number(data.pn ?? 0),
      skipped,
    );
  }
}

export interface EncryptedHeader {
  dh: string;
  pn: number;
  n: number;
}

function skippedKey(dh: Uint8Array | null, number: number): string {
  return `${b64e(dh ?? new Uint8Array(0))}:${number}`;
}

function associatedData(header: unknown, adContext: unknown): Uint8Array {
  return concat(AD_DOMAIN, canonicalJsonBytes({ init: adContext ?? {}, hdr: header }));
}

/** A bidirectional Double Ratchet session. */
export class Ratchet {
  constructor(public state: RatchetState) {}

  /** Start a session; performs the initial DH ratchet step. */
  static initiator(
    sessionKey: Uint8Array,
    remoteRatchetPublic: Uint8Array,
    keypair?: [Uint8Array, Uint8Array],
  ): Ratchet {
    const [priv, pub] = keypair ?? newKeypair();
    const state = new RatchetState(sessionKey, null, null, priv, pub, remoteRatchetPublic);
    const [rootKey, sendingChain] = kdfRk(state.rootKey, dh(priv, remoteRatchetPublic));
    state.rootKey = rootKey;
    state.sendingChain = sendingChain;
    return new Ratchet(state);
  }

  /** Start the receiving side, rooted at our signed prekey. */
  static responder(
    sessionKey: Uint8Array,
    signedPrekeyPrivate: Uint8Array,
    signedPrekeyPublic: Uint8Array,
  ): Ratchet {
    return new Ratchet(
      new RatchetState(sessionKey, null, null, signedPrekeyPrivate, signedPrekeyPublic, null),
    );
  }

  /** Returns `{header, nonce, ciphertext}`. */
  encrypt(
    plaintext: Uint8Array,
    adContext: unknown = null,
  ): { header: EncryptedHeader; nonce: Uint8Array; ciphertext: Uint8Array } {
    if (this.state.sendingChain === null) {
      throw new RatchetError('no sending chain; receive a message first');
    }
    const [messageKey, nextChain] = kdfCk(this.state.sendingChain);
    this.state.sendingChain = nextChain;
    const header: EncryptedHeader = {
      dh: b64e(this.state.dhSelfPublic as Uint8Array),
      pn: this.state.prevSendCount,
      n: this.state.sendCount,
    };
    const [nonce, ciphertext] = aead.encrypt(
      messageKey,
      plaintext,
      associatedData(header, adContext),
    );
    this.state.sendCount += 1;
    return { header, nonce, ciphertext };
  }

  /** Verify and decrypt. Session state only advances on success. */
  decrypt(
    header: unknown,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    adContext: unknown = null,
  ): Uint8Array {
    const snapshot = this.state.clone();
    try {
      return this.decryptInner(header, nonce, ciphertext, adContext);
    } catch (error) {
      this.state = snapshot;
      throw error;
    }
  }

  private decryptInner(
    header: any,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    adContext: unknown,
  ): Uint8Array {
    let remoteDh: Uint8Array;
    let number: number;
    let prevCount: number;
    try {
      remoteDh = b64d(String(header.dh));
      number = Number(header.n);
      prevCount = Number(header.pn);
    } catch {
      throw new RatchetError('malformed header');
    }

    if (this.state.dhRemote === null || !equalBytes(this.state.dhRemote, remoteDh) || this.state.receivingChain === null) {
      if (this.state.receivingChain !== null) this.skipKeys(prevCount);
      this.dhRatchet(remoteDh);
    }

    const key = skippedKey(remoteDh, number);
    let messageKey = this.state.skipped.get(key);
    if (messageKey !== undefined) this.state.skipped.delete(key);
    else {
      if (number < this.state.recvCount) {
        throw new DuplicateMessage('message key already consumed');
      }
      if (number > this.state.recvCount + MAX_SKIP) {
        throw new SkippedTooFar(`would skip ${number - this.state.recvCount} messages`);
      }
      this.skipKeys(number);
      const [derived, nextChain] = kdfCk(this.state.receivingChain as Uint8Array);
      messageKey = derived;
      this.state.receivingChain = nextChain;
      this.state.recvCount += 1;
    }

    return aead.decrypt(messageKey, nonce, ciphertext, associatedData(header, adContext));
  }

  private dhRatchet(remoteDh: Uint8Array): void {
    this.state.prevSendCount = this.state.sendCount;
    this.state.sendCount = 0;
    this.state.recvCount = 0;
    this.state.dhRemote = remoteDh;
    if (this.state.dhSelfPrivate === null) {
      throw new RatchetError('ratchet has no local DH key');
    }
    const [rootKey, receivingChain] = kdfRk(
      this.state.rootKey,
      dh(this.state.dhSelfPrivate, remoteDh),
    );
    this.state.rootKey = rootKey;
    this.state.receivingChain = receivingChain;
    const [priv, pub] = newKeypair();
    this.state.dhSelfPrivate = priv;
    this.state.dhSelfPublic = pub;
    const [nextRootKey, sendingChain] = kdfRk(this.state.rootKey, dh(priv, remoteDh));
    this.state.rootKey = nextRootKey;
    this.state.sendingChain = sendingChain;
  }

  private skipKeys(until: number): void {
    if (this.state.receivingChain === null) return;
    if (this.state.recvCount + MAX_SKIP < until) {
      throw new SkippedTooFar(`skipped-key cache would exceed ${MAX_SKIP}`);
    }
    while (this.state.recvCount < until) {
      const [messageKey, nextChain] = kdfCk(this.state.receivingChain);
      this.state.skipped.set(skippedKey(this.state.dhRemote, this.state.recvCount), messageKey);
      this.state.receivingChain = nextChain;
      this.state.recvCount += 1;
    }
  }
}
