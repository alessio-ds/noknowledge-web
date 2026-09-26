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
import * as syncMod from './sync';
import {
  DeviceEntry,
  DeviceKeys,
  DeviceList,
  DeviceListError,
  LEGACY_DEVICE,
  deviceListId,
  newDeviceId,
  openDeviceList,
  sealDeviceList,
} from './devices';
import { isDeviceRecord } from './deviceChannel';
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

/** Session state for one contact.
 *
 * `outbound` sessions are keyed by the *peer's* device id, `inbound` ones by
 * *our* device id. They are kept apart on purpose: sharing one map let a receipt
 * write clobber the very session needed to read the reply. */
interface ContactState {
  devices: DeviceEntry[];
  outbound: Record<string, Session>;
  inbound: Record<string, Session>;
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
  /** Sibling device key records, so mirroring does not refetch per message. */
  readonly siblingKeyCache = new Map<string, { record: DeviceKeys; ts: number }>();
  private deviceListCache: DeviceList | null = null;
  private deviceListCacheTs = 0;
  private syncMessageIndexCache: Promise<Map<string, Message>> | null = null;
  private ownInbox: MailboxCapability | null = null;
  private bundleId: string | null = null;
  private cardCache: ContactCard | null = null;
  /** This device's identifier within the account, once provisioned. */
  private deviceId: string | null = null;
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
    await this.ensureDeviceRegistered();
    return this.cardCache;
  }

  // -- devices ----------------------------------------------------------

  /** This device's id, or null before provisioning (never provisions). */
  get currentDeviceId(): string | null {
    return this.deviceId;
  }

  /** This device's id within the account, once provisioned. */
  async thisDeviceId(): Promise<string> {
    await this.provisionInner();
    return this.deviceId as string;
  }

  private deviceEntry(): DeviceEntry {
    if (!this.ownInbox || !this.bundleId) throw new NotProvisioned();
    return new DeviceEntry(
      this.deviceId ?? LEGACY_DEVICE,
      { id: this.ownInbox.mailboxId, w: this.ownInbox.writeToken },
      [...this.relays],
      this.bundleId,
      this.name ?? '',
    );
  }

  get deviceListAddress(): string {
    return deviceListId(this.identity.edPublicBytes, this.identity.xPublicBytes);
  }

  /** Add (or refresh) this device in the account's signed device list.
   *
   * This is what makes a recovered account work: the device gets its own mailbox
   * and prekeys, then publishes itself so senders start delivering a copy here
   * too. */
  private async ensureDeviceRegistered(): Promise<void> {
    if (this.deviceId === null) {
      this.deviceId =
        (await this.store.getState(this.identityId, 'device_id')) ?? newDeviceId();
      await this.store.setState(this.identityId, 'device_id', this.deviceId);
    }
    const entry = this.deviceEntry();
    const existing = await this.fetchOwnDeviceList();
    const alreadyAdvertised = (existing?.devices ?? []).some(
      (device) =>
        device.deviceId === entry.deviceId &&
        device.inbox.id === entry.inbox.id &&
        device.inbox.w === entry.inbox.w &&
        device.bundleId === entry.bundleId &&
        device.relays.join('\n') === entry.relays.join('\n'),
    );
    if (alreadyAdvertised) {
      // Already advertised exactly like this: republishing would only burn a
      // relay's prekey quota and churn the record.
      return;
    }
    const entries = (existing?.devices ?? []).filter(
      (device) => device.deviceId !== entry.deviceId,
    );
    entries.push(entry);
    const listing = DeviceList.create(this.identity, entries);
    try {
      await this.backend.publishBundle(listing.address(), sealDeviceList(listing));
    } catch {
      // A relay refusing the record must not break provisioning; senders simply
      // fall back to the inbox in our contact card.
    }
    this.deviceListCache = listing;
    this.deviceListCacheTs = Date.now();
    // Our own sync keys, so sibling devices can seal records to us.
    await syncMod.publishDeviceKeys(this);
  }

  /** This account's device list, refetched at most every `maxAge` seconds.
   *
   * Mirroring and receipt handling look siblings up constantly, so going to the
   * relay every time would put a round trip in the middle of a send. */
  async ownDeviceList(maxAge = 300): Promise<DeviceList | null> {
    if (this.deviceListCache && Date.now() - this.deviceListCacheTs < maxAge * 1000) {
      return this.deviceListCache;
    }
    const listing = await this.fetchOwnDeviceList();
    if (listing) {
      this.deviceListCache = listing;
      this.deviceListCacheTs = Date.now();
    }
    return listing ?? this.deviceListCache;
  }

  /** The message index of an in-flight back-fill, built once and shared. */
  async syncMessageIndex(): Promise<Map<string, Message>> {
    if (this.syncMessageIndexCache === null) {
      this.syncMessageIndexCache = import('./history').then((mod) => mod.messageIndex(this));
    }
    return this.syncMessageIndexCache;
  }

  resetSyncMessageIndex(): void {
    this.syncMessageIndexCache = null;
  }

  private async fetchOwnDeviceList(): Promise<DeviceList | null> {
    let payload: unknown;
    try {
      payload = await this.backend.fetchBundle(this.deviceListAddress);
    } catch {
      return null;
    }
    let listing: DeviceList;
    try {
      listing = openDeviceList(
        payload as any,
        this.identity.edPublicBytes,
        this.identity.xPublicBytes,
      );
    } catch (error) {
      if (error instanceof DeviceListError) return null;
      return null;
    }
    if (
      !listing.belongsTo(
        this.identityId,
        this.identity.edPublicBytes,
        this.identity.xPublicBytes,
      )
    ) {
      return null;
    }
    return listing;
  }

  /** Every device currently registered to this account. */
  async devices(): Promise<DeviceEntry[]> {
    await this.provisionInner();
    const listing = await this.fetchOwnDeviceList();
    return listing ? listing.devices : [this.deviceEntry()];
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
  //
  // A contact may have several devices, each with its own mailbox and its own
  // Double Ratchet session, so sessions are keyed by device id. The stored blob
  // is either the v2 container below or a bare v1 session, read as the legacy
  // device so existing contacts keep working.

  private loadState(contact: Contact): ContactState {
    const raw = contact.session as any;
    if (raw && raw.v === 2) {
      const devices: DeviceEntry[] = [];
      for (const data of raw.devices ?? []) {
        try {
          devices.push(DeviceEntry.fromDict(data));
        } catch {
          continue;
        }
      }
      const parse = (bucket: any): Record<string, Session> => {
        const out: Record<string, Session> = {};
        for (const [key, value] of Object.entries(bucket ?? {})) {
          out[key] = Session.fromDict(value);
        }
        return out;
      };
      return { devices, outbound: parse(raw.outbound), inbound: parse(raw.inbound) };
    }
    if (raw) {
      // v1 blob: a single session, always an outbound one.
      return { devices: [], outbound: { [LEGACY_DEVICE]: Session.fromDict(raw) }, inbound: {} };
    }
    return { devices: [], outbound: {}, inbound: {} };
  }

  private toStoredState(state: ContactState): Record<string, unknown> {
    return {
      v: 2,
      devices: state.devices.map((device) => device.toDict()),
      outbound: Object.fromEntries(
        Object.entries(state.outbound).map(([key, session]) => [key, session.toDict()]),
      ),
      inbound: Object.fromEntries(
        Object.entries(state.inbound).map(([key, session]) => [key, session.toDict()]),
      ),
    };
  }

  private async saveState(contactId: string, state: ContactState): Promise<void> {
    await this.store.setContactSession(this.identityId, contactId, this.toStoredState(state));
  }

  private cachedDevices(contact: Contact): DeviceEntry[] {
    const devices = this.loadState(contact).devices;
    return devices.length > 0 ? devices : [this.legacyDevice(contact)];
  }

  /** The single inbox advertised in a contact card, pre-device-lists. */
  private legacyDevice(contact: Contact): DeviceEntry {
    return new DeviceEntry(
      LEGACY_DEVICE,
      { id: contact.inbox.id, w: contact.inbox.w },
      [...(contact.relays ?? [])],
      contact.bundle_id,
      contact.nickname ?? '',
    );
  }

  /** Locate a session by its wire id across every contact and bucket. */
  private async findSession(
    sid: Uint8Array,
  ): Promise<
    [Contact | null, ContactState | null, 'outbound' | 'inbound' | null, string | null, Session | null]
  > {
    const contacts = await this.store.listContacts(this.identityId);
    for (const contact of contacts) {
      const state = this.loadState(contact);
      for (const bucket of ['outbound', 'inbound'] as const) {
        for (const [key, session] of Object.entries(state[bucket])) {
          if (equalBytes(session.sid, sid)) return [contact, state, bucket, key, session];
        }
      }
    }
    return [null, null, null, null, null];
  }

  private async fetchPeerDeviceList(contact: Contact): Promise<DeviceList | null> {
    const address = deviceListId(b64d(contact.isign), b64d(contact.idh));
    let payload: unknown;
    try {
      payload = await this.backendFor(contact.relays).fetchBundle(address);
    } catch {
      return null;
    }
    let listing: DeviceList;
    try {
      listing = openDeviceList(payload as any, b64d(contact.isign), b64d(contact.idh));
    } catch (error) {
      if (error instanceof DeviceListError) return null;
      return null;
    }
    if (!listing.belongsTo(contact.id, b64d(contact.isign), b64d(contact.idh))) return null;
    return listing;
  }

  /** The peer's devices, freshly fetched, else the last known set. */
  private async peerDevices(contact: Contact): Promise<DeviceEntry[]> {
    const listing = await this.fetchPeerDeviceList(contact);
    if (listing) return listing.devices;
    return this.cachedDevices(contact);
  }

  private async fetchDeviceBundle(contact: Contact, device: DeviceEntry): Promise<PrekeyBundle> {
    let payload: unknown;
    try {
      payload = await this.backendFor(device.relays).fetchBundle(device.bundleId);
    } catch (error) {
      throw new ClientError(`could not fetch prekey bundle: ${String(error)}`);
    }
    try {
      return PrekeyBundle.fromPublic(payload as any, b64d(contact.isign), b64d(contact.idh));
    } catch (error) {
      throw new ClientError(`invalid prekey bundle: ${String(error)}`);
    }
  }

  private async startSession(contact: Contact, device: DeviceEntry): Promise<Session> {
    const bundle = await this.fetchDeviceBundle(contact, device);
    const initiation = x3dhInitiate(bundle, b64d(contact.isign), b64d(contact.idh));
    return new Session(
      randomBytes(16),
      Ratchet.initiator(initiation.sk, bundle.spk),
      initiation.sk,
      initDict(initiation),
      false,
    );
  }

  /** One outbound session per device of the peer, creating any missing. */
  private async ensureOutboundSessions(
    contact: Contact,
    state: ContactState,
  ): Promise<DeviceEntry[]> {
    const devices = await this.peerDevices(contact);
    const targets = devices.length > 0 ? devices : [this.legacyDevice(contact)];
    for (const device of targets) {
      if (!state.outbound[device.deviceId]) {
        state.outbound[device.deviceId] = await this.startSession(contact, device);
      }
    }
    // Sessions for devices the peer no longer advertises are kept, not deleted:
    // a stale list must never destroy history.
    return targets;
  }

  // -- sending ----------------------------------------------------------

  /** The write capability for one device's mailbox. */
  deviceCapability(device: DeviceEntry): MailboxCapability {
    return MailboxCapability.fromCardView(device.inbox);
  }

  /** A backend that can reach a peer, using the relays from *their* card. */
  backendFor(relays: string[] | null | undefined): MultiRelayBackend {
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
    device: DeviceEntry,
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
    await this.backendFor(device.relays).put(this.deviceCapability(device), blob);
    return blob;
  }

  /** Deliver one copy per device, sealed with that device's own session.
   *
   * `envelopeFor(device)` builds the plaintext for one device, so a file
   * transfer can carry that device's own chunk ids. */
  private async fanOut(
    contact: Contact,
    devices: DeviceEntry[],
    sessions: Record<string, Session>,
    envelopeFor: (device: DeviceEntry) => Record<string, unknown>,
    kind: string,
  ): Promise<Array<[DeviceEntry, Uint8Array]>> {
    const results: Array<[DeviceEntry, Uint8Array]> = [];
    for (const device of devices) {
      const session = sessions[device.deviceId];
      const blob = await this.sendEnvelope(contact, device, session, envelopeFor(device), kind);
      results.push([device, blob]);
    }
    return results;
  }

  sendText(contactId: string, text: string): Promise<string> {
    return this.runExclusive(() => this.sendTextInner(contactId, text));
  }

  private async sendTextInner(contactId: string, text: string): Promise<string> {
    await this.provisionInner();
    const contact = await this.requireContact(contactId);
    const state = this.loadState(contact);
    const devices = await this.ensureOutboundSessions(contact, state);
    state.devices = devices;
    const messageId = newId();
    const envelope = makeEnvelope('text', { text }, messageId, nowMs());
    const blobs = await this.fanOut(contact, devices, state.outbound, () => envelope, 'text');
    await this.saveState(contactId, state);
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
    for (const [device, blob] of blobs) {
      await this.queueOutbox(contact, device, messageId, blob);
    }
    await this.mirrorSent(contactId, messageId);
    return messageId;
  }

  private async mirrorSent(contactId: string, messageId: string): Promise<void> {
    const row = await this.store.getMessage(messageId);
    if (!row) return;
    try {
      await syncMod.mirrorMessage(this, contactId, row);
    } catch {
      // Mirroring is a convenience: never fail a send over it.
    }
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
    const state = this.loadState(contact);
    const devices = await this.ensureOutboundSessions(contact, state);
    state.devices = devices;
    const attachment = encryptAttachment(data);

    // Each device's mailbox needs its own chunk ids, so the manifest is built
    // per device and travels inside that device's copy of the message.
    const bodies: Record<string, Record<string, unknown>> = {};
    for (const device of devices) {
      const backend = this.backendFor(device.relays);
      const capability = this.deviceCapability(device);
      const chunkIds: string[] = [];
      for (const chunk of attachment.chunks) {
        chunkIds.push(await backend.putBlob(capability, chunk.ciphertext));
      }
      const manifest = manifestDict(attachment, chunkIds);
      manifest.name = filename;
      manifest.mime = mime;
      bodies[device.deviceId] = { caption, attachment: manifest };
    }
    // Keep our own copy under the manifest we record locally, so the file stays
    // downloadable after the relay drops it and can travel with a history
    // transfer to another device.
    const localManifest = bodies[devices[0].deviceId].attachment as any;
    for (let index = 0; index < attachment.chunks.length; index += 1) {
      await this.store.putLocalBlob(
        String(localManifest.chunks[index].id),
        attachment.chunks[index].ciphertext,
      );
    }

    const messageId = newId();
    const blobs = await this.fanOut(
      contact,
      devices,
      state.outbound,
      (device) => makeEnvelope('file', bodies[device.deviceId], messageId, nowMs()),
      'file',
    );
    await this.saveState(contactId, state);
    await this.store.addMessage({
      id: messageId,
      identity_id: this.identityId,
      contact_id: contactId,
      direction: 'sent',
      type: 'file',
      body: bodies[devices[0].deviceId],
      remote_id: null,
      ts: nowMs(),
      state: 'sent',
      meta: null,
    });
    for (const [device, blob] of blobs) {
      await this.queueOutbox(contact, device, messageId, blob);
    }
    await this.mirrorSent(contactId, messageId);
    return messageId;
  }

  private async queueOutbox(
    contact: Contact,
    device: DeviceEntry,
    messageId: string,
    blob: Uint8Array,
  ): Promise<void> {
    const entry: OutboxEntry = {
      // One row per device copy. The message id is the prefix, so the receipt
      // for a message clears every device's row.
      id: `${messageId}:${device.deviceId}`,
      identity_id: this.identityId,
      contact_id: contact.id,
      mailbox_id: device.inbox.id,
      relay: device.relays.join(','),
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
      const device = this.cachedDevices(contact).find(
        (candidate) => candidate.inbox.id === entry.mailbox_id,
      );
      if (!device) continue;
      try {
        await this.backendFor(device.relays).put(
          this.deviceCapability(device),
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
        let message: Message | null = null;
        if (isDeviceRecord(item.blob)) {
          // A record from another device of this account. Its own failure modes
          // (unknown device, bad signature, truncated transfer) must not block
          // the mailbox; a truncated transfer is simply resumed later.
          try {
            await syncMod.handleRecord(this, item.blob);
          } catch {
            message = null;
          }
        } else {
          message = await this.handleBlob(item.blob);
        }
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

  private async handleBlob(blob: Uint8Array): Promise<Message | null> {
    const wire = parseWire(blob);
    const sid = b64d(String(wire.sid));
    let [contact, state, bucket, key, session] = await this.findSession(sid);

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
      // The peer addressed our own inbox directly, so this session belongs to
      // this device.
      state = this.loadState(contact);
      bucket = 'inbound';
      key = this.deviceId ?? LEGACY_DEVICE;
    } else if (!session.established) {
      session.established = true;
      session.sk = null;
    }

    if (!contact || !state || !bucket || !key) {
      return null;
    }
    state[bucket][key] = session;
    await this.saveState(contact.id, state);
    return this.processEnvelope(contact, envelope);
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

    const contact = await this.storeCard(card, null, null);
    await this.consumeOpk(opkId);
    session.established = true;
    session.sk = null;
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
    envelope: Record<string, unknown>,
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
      await this.sendReceipt(contact, envelopeId, 'delivered');
      return this.store.getMessage(message.id);
    }

    if (kind === 'receipt') {
      const target = body.of as string | undefined;
      if (target) {
        const state = (body.kind as string) || 'read';
        await this.store.updateMessage(target, { state });
        // One row per device copy, all prefixed by the message id.
        await this.store.outboxRemoveForMessage(target);
        const row = await this.store.getMessage(target);
        if (row) {
          try {
            await syncMod.mirrorState(this, contact.id, row);
          } catch {
            /* best effort */
          }
        }
      }
      return null;
    }

    return null;
  }

  /** Tell every device of the peer that we opened its copy of a message. */
  private async sendReceipt(contact: Contact, ofId: string, kind = 'delivered'): Promise<void> {
    const envelope = makeEnvelope('receipt', { of: ofId, kind }, newId(), nowMs());
    try {
      // Re-read: the caller's contact may predate a session saved moments ago (a
      // stale row would rewrite the store and drop that session).
      const fresh = (await this.store.getContact(this.identityId, contact.id)) ?? contact;
      const state = this.loadState(fresh);
      const devices = await this.ensureOutboundSessions(fresh, state);
      state.devices = devices;
      await this.fanOut(fresh, devices, state.outbound, () => envelope, 'receipt');
      await this.saveState(fresh.id, state);
    } catch {
      // A receipt is best effort: never let it fail the message it acks.
    }
  }

  markRead(contactId: string, messageId: string): Promise<void> {
    return this.runExclusive(() => this.markReadInner(contactId, messageId));
  }

  private async markReadInner(contactId: string, messageId: string): Promise<void> {
    const contact = await this.requireContact(contactId);
    const message = await this.store.getMessage(messageId);
    if (!message) throw new ClientError(`unknown message: ${messageId}`);
    // The peer knows this message by *its* envelope id, which we recorded as
    // remote_id; referencing our local id would be meaningless to them.
    const target = message.remote_id || messageId;
    await this.sendReceipt(contact, target, 'read');
    // Our other devices should show this as read too.
    try {
      await syncMod.mirrorState(this, contactId, { ...message, state: 'read' });
    } catch {
      /* best effort */
    }
  }

  // -- device sync ------------------------------------------------------

  /** Ask this account's other devices for the past. */
  requestHistory(sinceMs?: number | null): Promise<string[]> {
    return this.runExclusive(async () => {
      await this.provisionInner();
      return syncMod.requestHistory(this, sinceMs);
    });
  }

  /** Devices waiting for a human here to approve their history request. */
  historyRequests(): Promise<syncMod.SyncRequest[]> {
    return this.runExclusive(async () => {
      await this.provisionInner();
      return syncMod.pendingRequests(this);
    });
  }

  /** Approve a device and send it the history it asked for. */
  approveHistory(
    deviceId: string,
    sinceMs?: number | null,
    onProgress?: (done: number, total: number) => void,
  ): Promise<{ device_id: string; items: number; skipped: number }> {
    return this.runExclusive(async () => {
      await this.provisionInner();
      return syncMod.approveDevice(this, deviceId, sinceMs, undefined, onProgress);
    });
  }

  denyHistory(deviceId: string): Promise<void> {
    return this.runExclusive(async () => {
      await this.provisionInner();
      await syncMod.denyDevice(this, deviceId);
    });
  }

  revokeHistoryApproval(deviceId: string): Promise<void> {
    return this.runExclusive(async () => {
      await this.provisionInner();
      await syncMod.revokeApproval(this, deviceId);
    });
  }

  approvedDevices(): Promise<string[]> {
    return this.runExclusive(async () => {
      await this.provisionInner();
      return syncMod.approvedDevices(this);
    });
  }

  syncStatus(): Promise<syncMod.SyncStatus[]> {
    return this.runExclusive(async () => {
      await this.provisionInner();
      return syncMod.syncStatus(this);
    });
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
      let ciphertext = await this.store.getLocalBlob(chunkId);
      if (ciphertext === null) {
        ciphertext = await this.backend.getBlob(capability, chunkId);
        await this.store.putLocalBlob(chunkId, ciphertext);
      }
      ciphertexts.push(ciphertext);
      onProgress?.(ciphertexts.length, total);
    }
    return decryptAttachment(decoded.key, decoded.nonces, ciphertexts, decoded.sha256);
  }

  close(): void {
    this.peerBackends.clear();
  }
}
