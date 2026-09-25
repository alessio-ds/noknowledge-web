/** The noknowledge client.
 *
 * Orchestrates identity provisioning, contact cards, X3DH handshakes, Double
 * Ratchet sessions, capability mailboxes, receipts and attachments. All relay
 * access goes through {@link MultiRelayBackend}, so the relay set is the unit of
 * availability and a single relay failure is invisible to callers.
 *
 * This is a faithful port of the Python `core.client`; only the at-rest store
 * and the file API differ (IndexedDB and in-memory bytes instead of SQLite and
 * paths). */

import { x25519 } from '@noble/curves/ed25519';
import { equalBytes, toHex } from '../crypto/bytes';
import { b64d, b64e } from '../crypto/encoding';
import { Identity } from '../crypto/identity';
import { PrekeyBundle, makeBundle } from '../crypto/prekeys';
import { Ratchet } from '../crypto/ratchet';
import { randomBytes } from '../crypto/random';
import { buildAuth, initDict, initiate as x3dhInitiate, respond as x3dhRespond, verifyAuth } from '../crypto/x3dh';
import type { Transport } from '../wire/transport';
import { MailboxCapability, type FetchedMessage } from '../wire/backends/base';
import { MultiRelayBackend, normalizeRelayUrls } from '../wire/backends/multiRelay';
import {
  envelopeMaxSize,
  makeEnvelope,
  parseWire,
  seal,
  unseal,
} from '../wire/protocol';
import {
  AttachmentError,
  decodeManifest,
  decryptAttachment,
  encryptAttachment,
  manifestDict,
} from './attachments';
import { CardError, ContactCard } from './card';
import { Session } from './session';
import type { Contact, LocalStore, Message, OutboxEntry } from './store';

export const DEFAULT_OPK_COUNT = 20;

/** After this many failed opens, a blob is acknowledged anyway so one poison
 * message cannot block a mailbox forever. */
const MAX_DECRYPT_ATTEMPTS = 5;

export class ClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClientError';
  }
}

export class NotProvisioned extends ClientError {
  constructor(message = 'client has no mailbox/prekeys yet') {
    super(message);
    this.name = 'NotProvisioned';
  }
}

export class UnknownContact extends ClientError {
  constructor(contactId: string) {
    super(`unknown contact: ${contactId}`);
    this.name = 'UnknownContact';
  }
}

function nowMs(): number {
  return Date.now();
}

function newId(): string {
  return toHex(randomBytes(16));
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function x25519Public(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

export class Client {
  readonly identity: Identity;
  readonly store: LocalStore;
  readonly relays: string[];
  readonly backend: MultiRelayBackend;
  readonly identityId: string;
  readonly opkCount: number;
  name: string;

  private readonly peerBackends = new Map<string, MultiRelayBackend>();
  private ownInbox: MailboxCapability | null = null;
  private bundleId: string | null = null;
  private cardCache: ContactCard | null = null;
  /** Serializes state-mutating work. The UI long-polls while the user sends;
   * without this, a sync and a send both load and save the same session and the
   * last writer silently destroys ratchet state. */
  private opChain: Promise<unknown> = Promise.resolve();
  private readonly retryCounts = new Map<string, number>();

  constructor(
    identity: Identity,
    store: LocalStore,
    relays: string[],
    name?: string | null,
    transport?: Transport,
    backend?: MultiRelayBackend,
    opkCount: number = DEFAULT_OPK_COUNT,
  ) {
    this.identity = identity;
    this.store = store;
    this.relays = normalizeRelayUrls([...relays]);
    if (this.relays.length === 0) throw new Error('at least one relay URL is required');
    this.backend = backend ?? new MultiRelayBackend(this.relays, transport);
    this.identityId = identity.identityId;
    this.name = name || identity.label || this.identityId.slice(0, 8);
    this.opkCount = opkCount;
  }

  private runExclusive<T>(task: () => Promise<T>): Promise<T> {
    const run = this.opChain.then(task, task);
    this.opChain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  // -- provisioning -----------------------------------------------------

  get isProvisioned(): boolean {
    return this.cardCache !== null;
  }

  /** Ensure the mailbox, prekeys and card exist, then return the card. */
  card(): Promise<ContactCard> {
    return this.runExclusive(() => this.cardInner());
  }

  private async cardInner(): Promise<ContactCard> {
    await this.provisionInner();
    return this.cardCache as ContactCard;
  }

  async cardString(): Promise<string> {
    return (await this.card()).to_string();
  }

  provision(): Promise<ContactCard> {
    return this.runExclusive(() => this.provisionInner());
  }

  private async provisionInner(): Promise<ContactCard> {
    if (this.cardCache) return this.cardCache;

    const inboxJson = await this.store.getState(this.identityId, 'inbox');
    if (inboxJson) {
      this.ownInbox = MailboxCapability.fromJson(inboxJson);
      this.bundleId = await this.store.getState(this.identityId, 'bundle_id');
      const storedName = await this.store.getState(this.identityId, 'name');
      if (storedName) this.name = storedName;
      try {
        await this.backend.registerMailbox(this.ownInbox);
      } catch {
        /* an unreachable relay must not block startup */
      }
      try {
        const prekeys = await this.store.loadPrekeys(this.identityId);
        if (prekeys) await this.publishBundle(prekeys);
      } catch {
        /* ditto */
      }
    } else {
      this.ownInbox = await this.backend.createMailbox();
      this.bundleId = b64e(randomBytes(16));
      const prekeys = this.generatePrekeys(this.opkCount);
      await this.store.savePrekeys(this.identityId, prekeys);
      await this.publishBundle(prekeys);
      await this.store.setState(this.identityId, 'inbox', this.ownInbox.toJson());
      await this.store.setState(this.identityId, 'bundle_id', this.bundleId);
      await this.store.setState(this.identityId, 'name', this.name);
    }

    if (!this.bundleId || !this.ownInbox) throw new NotProvisioned();
    this.cardCache = ContactCard.create(
      this.identity,
      this.bundleId,
      this.ownInbox,
      this.relays,
      this.name,
    );
    return this.cardCache;
  }

  private generatePrekeys(count: number): Record<string, unknown> {
    const spkPrivate = randomBytes(32);
    const spkPublic = x25519Public(spkPrivate);
    const opks: Record<string, { priv: string; pub: string }> = {};
    for (let index = 1; index <= count; index++) {
      const priv = randomBytes(32);
      opks[String(index)] = { priv: b64e(priv), pub: b64e(x25519Public(priv)) };
    }
    return {
      spk_id: 1,
      spk_private: b64e(spkPrivate),
      spk_public: b64e(spkPublic),
      opks,
      next_opk_id: count + 1,
    };
  }

  private async publishBundle(prekeys: any): Promise<void> {
    if (!this.bundleId) throw new NotProvisioned();
    const bundle = makeBundle(
      this.identity,
      b64d(this.bundleId),
      Number(prekeys.spk_id),
      b64d(prekeys.spk_public),
      Object.entries(prekeys.opks).map(([key, value]: [string, any]) => [
        Number(key),
        b64d(value.pub),
      ]),
    );
    await this.backend.publishBundle(this.bundleId, bundle.toBytes());
  }

  // -- contacts ---------------------------------------------------------

  addContact(cardString: string, nickname?: string | null): Promise<Contact> {
    return this.runExclusive(() => this.addContactInner(cardString, nickname ?? null));
  }

  private async addContactInner(cardString: string, nickname: string | null): Promise<Contact> {
    let card: ContactCard;
    try {
      card = ContactCard.fromString(cardString);
    } catch (error) {
      if (error instanceof CardError) throw new ClientError(`invalid contact card: ${error.message}`);
      throw error;
    }
    if (card.identityId === this.identityId) {
      throw new ClientError('cannot add your own card as a contact');
    }
    return this.storeCard(card, nickname);
  }

  private async storeCard(
    card: ContactCard,
    nickname: string | null = null,
    session?: Record<string, unknown> | null,
  ): Promise<Contact> {
    const existing = await this.store.getContact(this.identityId, card.identityId);
    const contact: Contact = {
      id: card.identityId,
      identity_id: this.identityId,
      nickname: nickname || existing?.nickname || card.name || card.identityId.slice(0, 8),
      isign: b64e(card.isign),
      idh: b64e(card.idh),
      bundle_id: card.bundleId,
      inbox: card.inbox.cardView(),
      relays: card.relays,
      session: session !== undefined ? session : existing?.session ?? null,
      verified: existing ? existing.verified : false,
      created_at: existing ? existing.created_at : nowMs() / 1000,
    };
    await this.store.upsertContact(this.identityId, contact);
    return (await this.store.getContact(this.identityId, card.identityId)) ?? contact;
  }

  async listContacts(): Promise<Contact[]> {
    return this.store.listContacts(this.identityId);
  }

  async removeContact(contactId: string): Promise<void> {
    await this.store.deleteContact(this.identityId, contactId);
  }

  private async requireContact(contactId: string): Promise<Contact> {
    const contact = await this.store.getContact(this.identityId, contactId);
    if (!contact) throw new UnknownContact(contactId);
    return contact;
  }

  // -- sessions ---------------------------------------------------------

  private loadSession(contact: Contact): Session | null {
    return contact.session ? Session.fromDict(contact.session) : null;
  }

  private async saveSession(contactId: string, session: Session): Promise<void> {
    await this.store.setContactSession(this.identityId, contactId, session.toDict());
  }

  private async findSession(sid: Uint8Array): Promise<[Contact | null, Session | null]> {
    for (const contact of await this.store.listContacts(this.identityId)) {
      if (contact.session) {
        const session = Session.fromDict(contact.session);
        if (equalBytes(session.sid, sid)) return [contact, session];
      }
    }
    return [null, null];
  }

  private async fetchBundle(contact: Contact): Promise<PrekeyBundle> {
    let payload: unknown;
    try {
      payload = await this.backendFor(contact.relays).fetchBundle(contact.bundle_id);
    } catch (error) {
      throw new ClientError(`could not fetch prekey bundle: ${String(error)}`);
    }
    try {
      return PrekeyBundle.fromPublic(payload as any, b64d(contact.isign), b64d(contact.idh));
    } catch (error) {
      throw new ClientError(`invalid prekey bundle: ${String(error)}`);
    }
  }

  private async ensureOutboundSession(contact: Contact): Promise<Session> {
    const existing = this.loadSession(contact);
    if (existing) return existing;
    const bundle = await this.fetchBundle(contact);
    const initiation = x3dhInitiate(bundle, b64d(contact.isign), b64d(contact.idh));
    const session = new Session(
      randomBytes(16),
      Ratchet.initiator(initiation.sk, bundle.spk),
      initiation.sk,
      initDict(initiation),
      false,
    );
    await this.saveSession(contact.id, session);
    return session;
  }

  // -- sending ----------------------------------------------------------

  private recipientCapability(contact: Contact): MailboxCapability {
    return MailboxCapability.fromCardView(contact.inbox);
  }

  /** A backend that can reach a peer, using the relays from *their* card. */
  private backendFor(relays: string[] | null | undefined): MultiRelayBackend {
    const urls = normalizeRelayUrls([...(relays ?? [])]);
    if (urls.length === 0) return this.backend;
    const key = urls.join('\n');
    if (key === this.relays.join('\n')) return this.backend;
    let backend = this.peerBackends.get(key);
    if (!backend) {
      backend = new MultiRelayBackend(urls, this.backend.transport);
      this.peerBackends.set(key, backend);
    }
    return backend;
  }

  private async sendEnvelope(
    contact: Contact,
    session: Session,
    envelope: Record<string, unknown>,
    kind: string,
  ): Promise<Uint8Array> {
    let init: Record<string, unknown> | null = null;
    let outgoing = envelope;
    if (session.isPending) {
      if (!session.sk || !session.init) throw new ClientError('pending session is missing handshake material');
      init = session.init;
      outgoing = { ...envelope };
      outgoing.auth = buildAuth(this.identity, session.sid, session.init, session.sk);
      outgoing.card = (await this.cardInner()).signedDict();
    }
    const blob = seal(session.ratchet, outgoing, session.sid, init, envelopeMaxSize(kind));
    await this.backendFor(contact.relays).put(this.recipientCapability(contact), blob);
    return blob;
  }

  sendText(contactId: string, text: string): Promise<string> {
    return this.runExclusive(() => this.sendTextInner(contactId, text));
  }

  private async sendTextInner(contactId: string, text: string): Promise<string> {
    await this.provisionInner();
    const contact = await this.requireContact(contactId);
    const session = await this.ensureOutboundSession(contact);
    const messageId = newId();
    const envelope = makeEnvelope('text', { text }, messageId, nowMs());
    const blob = await this.sendEnvelope(contact, session, envelope, 'text');
    await this.saveSession(contactId, session);
    await this.store.addMessage({
      id: messageId,
      identity_id: this.identityId,
      contact_id: contactId,
      direction: 'sent',
      type: 'text',
      body: { text },
      remote_id: null,
      ts: nowMs(),
      state: 'sent',
      meta: null,
    });
    await this.queueOutbox(contact, messageId, blob);
    return messageId;
  }

  sendFile(
    contactId: string,
    data: Uint8Array,
    filename: string,
    mime: string,
    caption = '',
  ): Promise<string> {
    return this.runExclusive(() => this.sendFileInner(contactId, data, filename, mime, caption));
  }

  private async sendFileInner(
    contactId: string,
    data: Uint8Array,
    filename: string,
    mime: string,
    caption: string,
  ): Promise<string> {
    await this.provisionInner();
    const contact = await this.requireContact(contactId);
    const session = await this.ensureOutboundSession(contact);
    const attachment = encryptAttachment(data);
    const capability = this.recipientCapability(contact);
    const backend = this.backendFor(contact.relays);
    const chunkIds: string[] = [];
    for (const chunk of attachment.chunks) {
      chunkIds.push(await backend.putBlob(capability, chunk.ciphertext));
    }
    const manifest = manifestDict(attachment, chunkIds);
    manifest.name = filename;
    manifest.mime = mime;

    const messageId = newId();
    const body = { caption, attachment: manifest };
    const envelope = makeEnvelope('file', body, messageId, nowMs());
    const blob = await this.sendEnvelope(contact, session, envelope, 'file');
    await this.saveSession(contactId, session);
    await this.store.addMessage({
      id: messageId,
      identity_id: this.identityId,
      contact_id: contactId,
      direction: 'sent',
      type: 'file',
      body,
      remote_id: null,
      ts: nowMs(),
      state: 'sent',
      meta: null,
    });
    await this.queueOutbox(contact, messageId, blob);
    return messageId;
  }

  private async queueOutbox(
    contact: Contact,
    messageId: string,
    blob: Uint8Array,
  ): Promise<void> {
    const entry: OutboxEntry = {
      id: messageId,
      identity_id: this.identityId,
      contact_id: contact.id,
      mailbox_id: contact.inbox.id,
      relay: null,
      payload: b64e(blob),
      seq: 1, // already accepted by at least one relay
      created_at: nowMs() / 1000,
    };
    await this.store.outboxAdd(entry);
  }

  /** Re-send messages that no relay accepted. Returns the count re-sent. */
  async flushOutbox(): Promise<number> {
    let sent = 0;
    for (const entry of await this.store.outboxList(this.identityId)) {
      if (entry.seq) continue;
      const contact = await this.store.getContact(this.identityId, entry.contact_id);
      if (!contact) continue;
      try {
        await this.backendFor(contact.relays).put(
          this.recipientCapability(contact),
          b64d(entry.payload),
        );
        await this.store.outboxMarkSent(entry.id);
        sent += 1;
      } catch {
        continue;
      }
    }
    return sent;
  }

  // -- receiving --------------------------------------------------------

  async sync(wait = 0): Promise<Message[]> {
    await this.provision();
    const capability = this.ownInbox as MailboxCapability;
    // The long-poll must NOT hold the operation lock, or a user's send would
    // block for up to `wait` seconds. Only processing is serialized.
    const fetched = await this.backend.fetch(capability, {}, wait);
    return this.runExclusive(() => this.processFetched(capability, fetched));
  }

  private async processFetched(
    capability: MailboxCapability,
    fetched: FetchedMessage[],
  ): Promise<Message[]> {
    const newMessages: Message[] = [];
    const ackable: Record<string, number> = {};
    const blocked = new Set<string>();

    for (const item of [...fetched].sort((a, b) => a.seq - b.seq)) {
      if (blocked.has(item.relay)) continue;
      try {
        const message = await this.handleBlob(capability, item.blob);
        if (message) newMessages.push(message);
        ackable[item.relay] = Math.max(ackable[item.relay] ?? 0, item.seq);
        this.retryCounts.delete(`${item.relay}:${item.seq}`);
      } catch {
        const key = `${item.relay}:${item.seq}`;
        const attempts = (this.retryCounts.get(key) ?? 0) + 1;
        this.retryCounts.set(key, attempts);
        if (attempts >= MAX_DECRYPT_ATTEMPTS) {
          ackable[item.relay] = Math.max(ackable[item.relay] ?? 0, item.seq);
          this.retryCounts.delete(key);
        } else {
          // Acknowledging deletes server-side, so never ack past a blob we could
          // not open: leave it for the next poll, when state is consistent.
          blocked.add(item.relay);
        }
      }
    }

    if (Object.keys(ackable).length > 0) await this.backend.ack(capability, ackable);
    return newMessages;
  }

  private async handleBlob(
    ownCapability: MailboxCapability,
    blob: Uint8Array,
  ): Promise<Message | null> {
    const wire = parseWire(blob);
    const sid = b64d(String(wire.sid));
    let [contact, session] = await this.findSession(sid);

    let fresh = false;
    let pendingOpk: number | null = null;
    if (!session) {
      if (!('init' in wire)) return null;
      const started = await this.beginInbound(wire);
      if (!started) return null;
      [session, pendingOpk] = started;
      fresh = true;
    }

    let envelope: Record<string, unknown>;
    try {
      [envelope] = unseal(session.ratchet, blob);
    } catch (error) {
      // A session matched, so this really is ours: propagate so the caller does
      // not acknowledge (and thereby delete) a message it could not open.
      throw error;
    }

    if (fresh) {
      contact = await this.finishInbound(session, envelope, pendingOpk);
      if (!contact) return null;
    } else {
      if (!contact) return null;
      if (!session.established) {
        session.established = true;
        session.sk = null;
      }
    }

    await this.saveSession(contact.id, session);
    return this.processEnvelope(contact, session, envelope, ownCapability);
  }

  private async beginInbound(wire: any): Promise<[Session, number | null] | null> {
    const init = wire.init;
    const prekeys = await this.store.loadPrekeys(this.identityId);
    if (!prekeys) return null;
    if (Number(init.spk_id) !== Number(prekeys.spk_id)) return null;
    const opkId: number | null = init.opk_id ?? null;
    let opkPrivate: Uint8Array | null = null;
    if (opkId !== null) {
      const entry = prekeys.opks?.[String(opkId)];
      if (!entry) return null; // already consumed: one-time prekey is spent
      opkPrivate = b64d(entry.priv);
    }
    let sessionKey: Uint8Array;
    try {
      sessionKey = x3dhRespond(
        this.identity.xPrivateBytes,
        b64d(prekeys.spk_private),
        opkPrivate,
        b64d(String(init.ek)),
      );
    } catch {
      return null;
    }
    const session = new Session(
      b64d(String(wire.sid)),
      Ratchet.responder(sessionKey, b64d(prekeys.spk_private), b64d(prekeys.spk_public)),
      sessionKey,
      init,
      false,
    );
    return [session, opkId];
  }

  private async finishInbound(
    session: Session,
    envelope: Record<string, unknown>,
    opkId: number | null,
  ): Promise<Contact | null> {
    const auth = envelope.auth;
    const cardDict = envelope.card;
    if (!isObject(auth) || !isObject(cardDict)) return null;
    if (!session.sk || !session.init) return null;
    if (!verifyAuth(auth, session.sid, session.init, session.sk)) return null;
    let card: ContactCard;
    try {
      card = ContactCard.fromDict(cardDict);
    } catch {
      return null;
    }
    if (card.identityId !== auth.id) return null;
    if (!equalBytes(card.isign, b64d(String(auth.isign)))) return null;

    const contact = await this.storeCard(card, null, session.toDict());
    await this.consumeOpk(opkId);
    session.established = true;
    session.sk = null;
    await this.saveSession(contact.id, session);
    return contact;
  }

  private async consumeOpk(opkId: number | null): Promise<void> {
    if (opkId === null) return;
    const prekeys = await this.store.loadPrekeys(this.identityId);
    if (!prekeys) return;
    if (prekeys.opks && prekeys.opks[String(opkId)] !== undefined) {
      delete prekeys.opks[String(opkId)];
      await this.store.savePrekeys(this.identityId, prekeys);
    }
  }

  private async processEnvelope(
    contact: Contact,
    session: Session,
    envelope: Record<string, unknown>,
    ownCapability: MailboxCapability,
  ): Promise<Message | null> {
    const kind = envelope.type as string | undefined;
    const envelopeId = envelope.id as string | undefined;
    const body = (envelope.body ?? {}) as Record<string, unknown>;

    if (kind === 'text' || kind === 'file') {
      if (!envelopeId) return null;
      const duplicate = await this.store.findByRemoteId(this.identityId, envelopeId, 'received');
      if (duplicate) return null;
      const message: Message = {
        id: newId(),
        identity_id: this.identityId,
        contact_id: contact.id,
        direction: 'received',
        type: kind,
        body,
        remote_id: envelopeId,
        ts: Number(envelope.ts) || nowMs(),
        state: 'received',
        meta: null,
      };
      await this.store.addMessage(message);
      await this.sendReceipt(contact, session, envelopeId, 'delivered');
      return this.store.getMessage(message.id);
    }

    if (kind === 'receipt') {
      const target = body.of as string | undefined;
      if (target) {
        const state = (body.kind as string) || 'read';
        await this.store.updateMessage(target, { state });
        await this.store.outboxRemove(target);
      }
      return null;
    }

    return null;
  }

  private async sendReceipt(
    contact: Contact,
    session: Session,
    ofId: string,
    kind = 'delivered',
  ): Promise<void> {
    const envelope = makeEnvelope('receipt', { of: ofId, kind }, newId(), nowMs());
    await this.sendEnvelope(contact, session, envelope, 'receipt');
    await this.saveSession(contact.id, session);
  }

  markRead(contactId: string, messageId: string): Promise<void> {
    return this.runExclusive(() => this.markReadInner(contactId, messageId));
  }

  private async markReadInner(contactId: string, messageId: string): Promise<void> {
    const contact = await this.requireContact(contactId);
    const session = this.loadSession(contact);
    if (!session) throw new ClientError('no session with this contact');
    const message = await this.store.getMessage(messageId);
    if (!message) throw new ClientError(`unknown message: ${messageId}`);
    const target = message.remote_id || messageId;
    await this.sendReceipt(contact, session, target, 'read');
  }

  // -- reading ----------------------------------------------------------

  async messages(contactId: string): Promise<Message[]> {
    return this.store.listMessages(this.identityId, contactId);
  }

  async downloadAttachment(
    message: Message,
    onProgress?: (done: number, total: number) => void,
  ): Promise<Uint8Array> {
    await this.provision();
    const manifest = (message.body as any)?.attachment;
    if (!manifest) throw new AttachmentError('message has no attachment');
    const decoded = decodeManifest(manifest);
    const capability = this.ownInbox as MailboxCapability;
    const ciphertexts: Uint8Array[] = [];
    const total = decoded.chunkIds.length;
    onProgress?.(0, total);
    for (const chunkId of decoded.chunkIds) {
      ciphertexts.push(await this.backend.getBlob(capability, chunkId));
      onProgress?.(ciphertexts.length, total);
    }
    return decryptAttachment(decoded.key, decoded.nonces, ciphertexts, decoded.sha256);
  }

  close(): void {
    this.peerBackends.clear();
  }
}
