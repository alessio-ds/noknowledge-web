/** Encrypted local storage on IndexedDB.
 *
 * Everything sensitive — message bodies, ratchet state, prekey secrets, outbox
 * payloads, contact keys — is stored as AEAD ciphertext under a key derived
 * from the user's passphrase. Unlike the desktop client, which keeps a SQLite
 * database per identity, this store seals whole records; the record key is the
 * only cleartext, and it contains no secret material. */

import { openDB, type IDBPDatabase } from 'idb';
import { decrypt, encryptWithNonce } from '../crypto/aead';
import { concat, utf8Decode, utf8Encode } from '../crypto/bytes';
import { b64d, b64e } from '../crypto/encoding';
import { randomBytes } from '../crypto/random';

export const LOCAL_KEY_SIZE = 32;
const DB_NAME = 'noknowledge-web';
const DB_VERSION = 1;
const STORE = 'records';

export interface Contact {
  id: string;
  identity_id: string;
  nickname: string | null;
  isign: string;
  idh: string;
  bundle_id: string;
  inbox: { id: string; w: string };
  relays: string[];
  session: Record<string, unknown> | null;
  verified: boolean;
  created_at: number;
}

export interface Message {
  id: string;
  identity_id: string;
  contact_id: string;
  direction: 'sent' | 'received';
  type: string;
  body: Record<string, unknown> | null;
  remote_id: string | null;
  ts: number;
  state: string | null;
  meta: Record<string, unknown> | null;
}

export interface OutboxEntry {
  id: string;
  identity_id: string;
  contact_id: string;
  mailbox_id: string;
  relay: string | null;
  payload: string;
  seq: number | null;
  created_at: number;
}

export class LocalStore {
  private constructor(
    private readonly db: IDBPDatabase,
    readonly key: Uint8Array,
    readonly identityId: string,
    /** Distinguishes two stores for the *same* identity in one browser.
     * A real device is a browser profile, so this is empty there; tests and
     * advanced setups use it to keep a second device's records apart. */
    private readonly namespace = '',
  ) {}

  static async open(key: Uint8Array, identityId: string, namespace = ''): Promise<LocalStore> {
    if (key.length !== LOCAL_KEY_SIZE) throw new Error('local store key must be 32 bytes');
    const db = await openDB(DB_NAME, DB_VERSION, {
      upgrade(database) {
        if (!database.objectStoreNames.contains(STORE)) {
          database.createObjectStore(STORE, { keyPath: 'k' });
        }
      },
    });
    return new LocalStore(db, key, identityId, namespace);
  }

  /** Drop every record for this identity (used by "delete account"). */
  async destroy(): Promise<void> {
    const keys = await this.db.getAllKeys(STORE);
    const prefix = `${this.identityId}${this.scopeSuffix}:`;
    await Promise.all(
      keys
        .map((key) => String(key))
        .filter((key) => key.includes(prefix) || key.endsWith(`:${this.identityId}${this.scopeSuffix}`))
        .map((key) => this.db.delete(STORE, key)),
    );
  }

  // -- plumbing ---------------------------------------------------------

  private get scopeSuffix(): string {
    return this.namespace ? `#${this.namespace}` : '';
  }

  private recordKey(kind: string, id: string): string {
    return `${kind}:${this.identityId}${this.scopeSuffix}:${id}`;
  }

  private seal(value: unknown): string {
    const nonce = randomBytes(12);
    const ciphertext = encryptWithNonce(this.key, nonce, utf8Encode(JSON.stringify(value)));
    return b64e(concat(nonce, ciphertext));
  }

  private openRecord(blob: string): any {
    const raw = b64d(blob);
    return JSON.parse(utf8Decode(decrypt(this.key, raw.slice(0, 12), raw.slice(12))));
  }

  private async put(kind: string, id: string, value: unknown): Promise<void> {
    await this.db.put(STORE, { k: this.recordKey(kind, id), v: this.seal(value) });
  }

  private async get(kind: string, id: string): Promise<any | null> {
    const record = await this.db.get(STORE, this.recordKey(kind, id));
    return record ? this.openRecord(record.v) : null;
  }

  private async delete(kind: string, id: string): Promise<void> {
    await this.db.delete(STORE, this.recordKey(kind, id));
  }

  private async list(kind: string): Promise<any[]> {
    const prefix = `${kind}:${this.identityId}${this.scopeSuffix}:`;
    const records = await this.db.getAll(STORE);
    return records
      .filter((record: any) => String(record.k).startsWith(prefix))
      .map((record: any) => this.openRecord(record.v));
  }

  // -- contacts ---------------------------------------------------------

  async upsertContact(identityId: string, contact: Contact): Promise<void> {
    await this.put('contact', contact.id, contact);
  }

  async getContact(identityId: string, contactId: string): Promise<Contact | null> {
    return this.get('contact', contactId);
  }

  async listContacts(identityId: string): Promise<Contact[]> {
    const contacts = await this.list('contact');
    return contacts.sort((a, b) => a.created_at - b.created_at);
  }

  async deleteContact(identityId: string, contactId: string): Promise<void> {
    await this.delete('contact', contactId);
  }

  async setContactSession(
    identityId: string,
    contactId: string,
    session: Record<string, unknown> | null,
  ): Promise<void> {
    const contact = await this.getContact(identityId, contactId);
    if (!contact) return;
    contact.session = session;
    await this.put('contact', contactId, contact);
  }

  // -- messages ---------------------------------------------------------

  async addMessage(message: Message): Promise<void> {
    await this.put('message', message.id, message);
  }

  async getMessage(messageId: string): Promise<Message | null> {
    return this.get('message', messageId);
  }

  async listMessages(identityId: string, contactId: string): Promise<Message[]> {
    const messages = await this.list('message');
    return messages
      .filter((message) => message.contact_id === contactId)
      .sort((a, b) => a.ts - b.ts);
  }

  /** Look up a message by the peer-assigned envelope id. */
  async findByRemoteId(
    identityId: string,
    remoteId: string,
    direction?: string,
  ): Promise<Message | null> {
    const messages = await this.list('message');
    return (
      messages.find(
        (message) =>
          message.remote_id === remoteId && (direction === undefined || message.direction === direction),
      ) ?? null
    );
  }

  async updateMessage(messageId: string, fields: Partial<Message>): Promise<void> {
    const message = await this.getMessage(messageId);
    if (!message) return;
    await this.put('message', messageId, { ...message, ...fields });
  }

  // -- prekeys ----------------------------------------------------------

  async savePrekeys(identityId: string, data: Record<string, unknown>): Promise<void> {
    await this.put('prekeys', 'data', data);
  }

  async loadPrekeys(identityId: string): Promise<any | null> {
    return this.get('prekeys', 'data');
  }

  // -- outbox -----------------------------------------------------------

  async outboxAdd(entry: OutboxEntry): Promise<void> {
    await this.put('outbox', entry.id, entry);
  }

  async outboxList(identityId: string, contactId?: string): Promise<OutboxEntry[]> {
    const entries = await this.list('outbox');
    return entries
      .filter((entry) => (contactId ? entry.contact_id === contactId : true))
      .sort((a, b) => a.created_at - b.created_at);
  }

  async outboxRemove(entryId: string): Promise<void> {
    await this.delete('outbox', entryId);
  }

  /** Clear every per-device row for one message (ids are `msg:device`). */
  async outboxRemoveForMessage(messageId: string): Promise<void> {
    const prefix = `${messageId}:`;
    const entries = await this.list('outbox');
    await Promise.all(
      entries
        .filter((entry) => entry.id === messageId || String(entry.id).startsWith(prefix))
        .map((entry) => this.delete('outbox', entry.id)),
    );
  }

  async outboxMarkSent(entryId: string): Promise<void> {
    const entry = await this.get('outbox', entryId);
    if (!entry) return;
    entry.seq = 1;
    await this.put('outbox', entryId, entry);
  }

  async outboxCount(identityId: string): Promise<number> {
    return (await this.list('outbox')).length;
  }

  // -- cursors ----------------------------------------------------------

  async getCursors(identityId: string, mailboxId: string): Promise<Record<string, number>> {
    const cursors: Record<string, number> = {};
    for (const cursor of await this.list('cursor')) {
      if (cursor.mailbox_id === mailboxId) cursors[cursor.relay] = Number(cursor.seq);
    }
    return cursors;
  }

  async setCursor(
    identityId: string,
    mailboxId: string,
    relay: string,
    seq: number,
  ): Promise<void> {
    const id = `${mailboxId}:${relay}`;
    const existing = await this.get('cursor', id);
    await this.put('cursor', id, {
      mailbox_id: mailboxId,
      relay,
      seq: Math.max(Number(existing?.seq ?? 0), Math.trunc(seq)),
    });
  }

  // -- key/value state --------------------------------------------------

  async setState(identityId: string, key: string, value: unknown): Promise<void> {
    await this.put('state', key, value);
  }

  async getState(identityId: string, key: string, fallback: any = null): Promise<any> {
    const value = await this.get('state', key);
    return value === null ? fallback : value;
  }
}
