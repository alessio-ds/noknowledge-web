/** Signed contact cards.
 *
 * A card is the entire invitation: identity public keys, a prekey bundle handle,
 * the recipient's mailbox write capability, and the relay set. It is signed by
 * the owner, so it can be relayed through untrusted channels (chat, QR,
 * screenshots) without tampering. */

import { concat } from '../crypto/bytes';
import { b64d, b64e, canonicalJsonBytes, cardDecode, cardEncode } from '../crypto/encoding';
import { Identity, computeIdentityId } from '../crypto/identity';
import { CARD_SIGN_INFO } from '../crypto/kdf';
import { MailboxCapability } from '../wire/backends/base';

export const CARD_VERSION = 1;

export class CardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CardError';
  }
}

export class ContactCard {
  constructor(
    public identityId: string,
    public isign: Uint8Array,
    public idh: Uint8Array,
    public bundleId: string,
    public inbox: MailboxCapability,
    public relays: string[] = [],
    public name: string | null = null,
    public signature: Uint8Array | null = null,
  ) {}

  // -- serialisation ----------------------------------------------------

  payload(): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      v: CARD_VERSION,
      id: this.identityId,
      isign: b64e(this.isign),
      idh: b64e(this.idh),
      bundle: this.bundleId,
      inbox: this.inbox.cardView(),
      relays: [...this.relays],
    };
    if (this.name) payload.name = this.name;
    return payload;
  }

  signedDict(): Record<string, unknown> {
    const payload = this.payload();
    payload.sig = b64e(this.signature ?? new Uint8Array(0));
    return payload;
  }

  private signedBytes(): Uint8Array {
    return concat(CARD_SIGN_INFO, canonicalJsonBytes(this.payload()));
  }

  to_string(): string {
    return cardEncode(this.signedDict());
  }

  toString(): string {
    return this.to_string();
  }

  static fromString(text: string): ContactCard {
    let data: unknown;
    try {
      data = cardDecode(text);
    } catch (error) {
      throw new CardError((error as Error).message);
    }
    return ContactCard.fromDict(data as any);
  }

  static fromDict(data: any): ContactCard {
    if (data?.v !== CARD_VERSION) {
      throw new CardError(`unsupported card version: ${data?.v}`);
    }
    let isign: Uint8Array;
    let idh: Uint8Array;
    let identityId: string;
    let bundleId: string;
    let inbox: MailboxCapability;
    let relays: string[];
    let name: string | null;
    let signature: Uint8Array;
    try {
      isign = b64d(String(data.isign));
      idh = b64d(String(data.idh));
      identityId = String(data.id);
      bundleId = String(data.bundle);
      inbox = MailboxCapability.fromCardView(data.inbox);
      relays = [...(data.relays ?? [])];
      name = data.name ?? null;
      signature = b64d(String(data.sig));
    } catch {
      throw new CardError('malformed contact card');
    }

    if (relays.length === 0) throw new CardError('contact card has no relays');
    if (computeIdentityId(isign, idh) !== identityId) {
      throw new CardError('contact card id does not match its public keys');
    }
    inbox.validate();

    const card = new ContactCard(identityId, isign, idh, bundleId, inbox, relays, name, signature);
    if (!Identity.verify(isign, signature, card.signedBytes())) {
      throw new CardError('contact card signature is invalid');
    }
    return card;
  }

  static create(
    identity: Identity,
    bundleId: string,
    inbox: MailboxCapability,
    relays: string[],
    name: string | null = null,
  ): ContactCard {
    const card = new ContactCard(
      identity.identityId,
      identity.edPublicBytes,
      identity.xPublicBytes,
      bundleId,
      new MailboxCapability(inbox.mailboxId, inbox.writeToken),
      [...relays],
      name,
    );
    card.signature = identity.sign(card.signedBytes());
    return card;
  }
}
