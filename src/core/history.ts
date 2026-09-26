/** History bundles: one format for export files and device back-fill.
 *
 * A bundle is the portable form of "what this account knows": contacts, messages
 * and the attachment ciphertext we hold locally. It is used twice, with the same
 * merge rules and therefore the same guarantees: as an **encrypted export file**
 * the user can move between machines, and as the **item stream** a device sends
 * to a sibling when back-filling history.
 *
 * Byte-compatible with the Python reference (`core/history.py`), including the
 * export file layout, so a file written by the desktop client imports in the
 * browser and the other way round.
 */

import { sha256 } from '@noble/hashes/sha2';
import { decrypt, encrypt, AEADError } from '../crypto/aead';
import { utf8Decode, utf8Encode } from '../crypto/bytes';
import { b64d, b64e, canonicalJsonBytes } from '../crypto/encoding';
import { zlibCompress, zlibDecompress } from '../crypto/zlib';
import type { Client } from './client';
import type { Contact, LocalStore, Message } from './store';

export const HISTORY_VERSION = 1;

/** Bytes at the start of an export file. */
export const HISTORY_MAGIC = utf8Encode('NKX1');

/** Default ceiling on attachment bytes carried by one bundle. */
export const DEFAULT_BUDGET_BYTES = 100 * 1024 * 1024;

/** Matching the Python reference and the account vault. */
export const PBKDF2_ITERATIONS = 600_000;

const STATE_RANK: Record<string, number> = { received: 0, sent: 0, delivered: 1, read: 2 };

/** How far along a message is, so a merge never moves it backwards. */
export function stateRank(state: unknown): number {
  return STATE_RANK[String(state)] ?? 0;
}

export class HistoryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HistoryError';
  }
}

export interface Bundle {
  v: number;
  created: number;
  from_device: string;
  range: { since: number; until: number };
  contacts: Array<Record<string, unknown>>;
  messages: Array<Record<string, unknown>>;
  chunks: Array<{ id: string; ct: string }>;
  skipped: Array<{ id: string; reason: string }>;
}

export interface MergeCounts {
  contacts: number;
  messages: number;
  updates: number;
  chunks: number;
}

// -- collection ------------------------------------------------------------

export function contactItem(contact: Contact): Record<string, unknown> {
  return {
    id: contact.id,
    isign: contact.isign,
    idh: contact.idh,
    bundle: contact.bundle_id,
    inbox: contact.inbox ?? {},
    relays: [...(contact.relays ?? [])],
    nickname: contact.nickname,
    verified: Boolean(contact.verified),
    created_at: Math.trunc(contact.created_at),
  };
}

export function messageItem(message: Message): Record<string, unknown> {
  return {
    contact_id: message.contact_id,
    direction: message.direction,
    type: message.type,
    body: message.body,
    remote_id: message.remote_id,
    ts: Math.trunc(message.ts),
    state: message.state,
  };
}

function bodyDigest(body: unknown): string {
  const raw = canonicalJsonBytes(body ?? {});
  return Array.from(sha256(raw))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);
}

/** Identity of a message for dedup, shared with the Python client. */
export function messageKey(item: Record<string, unknown>): string {
  const remoteId = item.remote_id;
  if (remoteId) {
    return ['r', item.contact_id, item.direction, String(remoteId)].join('\u0000');
  }
  return [
    'l',
    item.contact_id,
    item.direction,
    String(Math.trunc(Number(item.ts) || 0)),
    String(item.type),
    bodyDigest(item.body),
  ].join('\u0000');
}

export async function buildBundle(
  client: Client,
  options: {
    sinceMs?: number | null;
    untilMs?: number | null;
    budgetBytes?: number;
    includeAttachments?: boolean;
  } = {},
): Promise<Bundle> {
  const budgetBytes = options.budgetBytes ?? DEFAULT_BUDGET_BYTES;
  const includeAttachments = options.includeAttachments !== false;
  const until = Math.trunc(options.untilMs ?? Date.now());
  const since = Math.trunc(options.sinceMs ?? 0);
  const store: LocalStore = client.store;

  const contacts = (await store.listContacts(client.identityId)).map(contactItem);
  const allMessages = await store.listAllMessages(client.identityId);
  const messages = allMessages
    .filter((message) => message.ts >= since && message.ts <= until)
    .map(messageItem);

  const chunks: Array<{ id: string; ct: string }> = [];
  const skipped: Array<{ id: string; reason: string }> = [];
  if (includeAttachments) {
    const seen = new Set<string>();
    let used = 0;
    for (const item of messages) {
      const attachment = ((item.body as any)?.attachment ?? {}) as Record<string, unknown>;
      for (const entry of (attachment.chunks as any[]) ?? []) {
        const chunkId = String((entry as any)?.id ?? '');
        if (!chunkId || seen.has(chunkId)) continue;
        seen.add(chunkId);
        const ciphertext = await store.getLocalBlob(chunkId);
        if (ciphertext === null) {
          skipped.push({ id: chunkId, reason: 'not held here' });
          continue;
        }
        if (used + ciphertext.length > budgetBytes) {
          skipped.push({ id: chunkId, reason: 'over budget' });
          continue;
        }
        used += ciphertext.length;
        chunks.push({ id: chunkId, ct: b64e(ciphertext) });
      }
    }
  }

  return {
    v: HISTORY_VERSION,
    created: Date.now(),
    from_device: client.currentDeviceId ?? 'legacy',
    range: { since, until },
    contacts,
    messages,
    chunks,
    skipped,
  };
}

export function encodeBundle(bundle: Bundle): Uint8Array {
  return canonicalJsonBytes(bundle);
}

export function decodeBundle(data: Uint8Array | string): Bundle {
  const text = typeof data === 'string' ? data : utf8Decode(data);
  let bundle: any;
  try {
    bundle = JSON.parse(text);
  } catch {
    throw new HistoryError('history bundle is not valid JSON');
  }
  if (bundle === null || typeof bundle !== 'object' || bundle.v !== HISTORY_VERSION) {
    throw new HistoryError('unsupported history bundle version');
  }
  for (const field of ['contacts', 'messages', 'chunks']) {
    if (!Array.isArray(bundle[field])) throw new HistoryError(`history bundle is missing ${field}`);
  }
  return bundle as Bundle;
}

// -- merge -----------------------------------------------------------------

async function mergeContact(client: Client, item: Record<string, unknown>): Promise<boolean> {
  const contactId = String(item.id ?? '');
  if (!contactId) return false;
  const existing = await client.store.getContact(client.identityId, contactId);
  if (existing) {
    // Routing is kept as it is: live traffic already keeps our view of the
    // peer's card fresh, and a stale bundle must not point delivery backwards.
    return false;
  }
  try {
    b64d(String(item.isign));
    b64d(String(item.idh));
  } catch {
    throw new HistoryError('malformed contact in history bundle');
  }
  await client.store.upsertContact(client.identityId, {
    id: contactId,
    identity_id: client.identityId,
    nickname: (item.nickname as string | null) ?? null,
    isign: String(item.isign),
    idh: String(item.idh),
    bundle_id: String(item.bundle ?? ''),
    inbox: (item.inbox as { id: string; w: string }) ?? { id: '', w: '' },
    relays: [...((item.relays as string[]) ?? [])],
    session: null,
    verified: Boolean(item.verified),
    created_at: Number(item.created_at) || Date.now() / 1000,
  });
  return true;
}

export function newCounts(): MergeCounts {
  return { contacts: 0, messages: 0, updates: 0, chunks: 0 };
}

/** Index every message we already hold, so a merge stays linear. */
export async function messageIndex(client: Client): Promise<Map<string, Message>> {
  const known = new Map<string, Message>();
  for (const message of await client.store.listAllMessages(client.identityId)) {
    known.set(messageKey(message as unknown as Record<string, unknown>), message);
  }
  return known;
}

export async function mergeContacts(
  client: Client,
  items: Array<Record<string, unknown>> | undefined | null,
  counts: MergeCounts,
): Promise<void> {
  for (const item of items ?? []) {
    if (await mergeContact(client, item)) counts.contacts += 1;
  }
}

export async function mergeChunks(
  client: Client,
  items: Array<{ id: string; ct: string }> | undefined | null,
  counts: MergeCounts,
): Promise<void> {
  for (const chunk of items ?? []) {
    const chunkId = String(chunk.id ?? '');
    if (!chunkId) continue;
    let ciphertext: Uint8Array;
    try {
      ciphertext = b64d(String(chunk.ct));
    } catch {
      throw new HistoryError('malformed attachment chunk in history bundle');
    }
    if (!(await client.store.hasLocalBlob(chunkId))) {
      await client.store.putLocalBlob(chunkId, ciphertext);
      counts.chunks += 1;
    }
  }
}

/** Merge message items, deduplicating on the shared message key.
 *
 * `known` is the index from {@link messageIndex}; it is updated in place so a
 * stream of items (device back-fill) stays linear. */
export async function mergeMessages(
  client: Client,
  items: Array<Record<string, unknown> | undefined | null> | undefined | null,
  known: Map<string, Message>,
  counts: MergeCounts,
): Promise<void> {
  for (const item of items ?? []) {
    if (!item || !item.contact_id) continue;
    if (!item.contact_id) continue;
    const key = messageKey(item);
    const existing = known.get(key);
    if (existing) {
      if (stateRank(item.state) > stateRank(existing.state)) {
        await client.store.updateMessage(existing.id, { state: String(item.state) });
        counts.updates += 1;
      }
      continue;
    }
    // A mirrored message brings its own id so both devices agree on it.
    const id = String(item.id ?? b64e(crypto.getRandomValues(new Uint8Array(16))));
    const message: Message = {
      id,
      identity_id: client.identityId,
      contact_id: String(item.contact_id),
      direction: (item.direction as 'sent' | 'received') ?? 'received',
      type: String(item.type ?? 'text'),
      body: (item.body as Record<string, unknown>) ?? null,
      remote_id: (item.remote_id as string | null) ?? null,
      ts: Number(item.ts) || 0,
      state: (item.state as string | null) ?? null,
      meta: null,
    };
    await client.store.addMessage(message);
    known.set(key, message);
    counts.messages += 1;
  }
}

export async function mergeBundle(client: Client, bundle: Bundle): Promise<MergeCounts> {
  const counts = newCounts();
  await mergeContacts(client, bundle.contacts, counts);
  const known = await messageIndex(client);
  await mergeMessages(client, bundle.messages, known, counts);
  await mergeChunks(client, bundle.chunks, counts);
  return counts;
}

// -- encrypted export file -------------------------------------------------
//
// Layout: magic | version | u32 header length | header | nonce | ciphertext

async function exportKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new HistoryError('WebCrypto is unavailable');
  const base = await subtle.importKey(
    'raw',
    utf8Encode(passphrase) as unknown as BufferSource,
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as unknown as BufferSource, iterations, hash: 'SHA-256' },
    base,
    256,
  );
  return new Uint8Array(bits);
}

export interface ExportHeader {
  v: number;
  created: number;
  kdf: { salt: string; iterations: number };
  counts: { contacts: number; messages: number; chunks: number; skipped: number };
}

export function readExportHeader(data: Uint8Array): ExportHeader {
  if (!isHistoryFile(data)) throw new HistoryError('not a noknowledge history file');
  const version = data[4];
  const length = (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
  let header: ExportHeader;
  try {
    header = JSON.parse(utf8Decode(data.slice(9, 9 + length)));
  } catch {
    throw new HistoryError('history file is truncated');
  }
  if (version !== HISTORY_VERSION || header?.v !== HISTORY_VERSION) {
    throw new HistoryError('unsupported history file version');
  }
  return header;
}

export function isHistoryFile(data: Uint8Array): boolean {
  if (data.length < HISTORY_MAGIC.length) return false;
  return HISTORY_MAGIC.every((byte, index) => data[index] === byte);
}

export async function exportHistory(
  client: Client,
  passphrase: string,
  options: { sinceMs?: number | null; budgetBytes?: number; includeAttachments?: boolean } = {},
): Promise<Uint8Array> {
  if (!passphrase) throw new HistoryError('a passphrase is required to export history');
  const bundle = await buildBundle(client, options);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = PBKDF2_ITERATIONS;
  const key = await exportKey(passphrase, salt, iterations);
  const header: ExportHeader = {
    v: HISTORY_VERSION,
    created: bundle.created,
    kdf: { salt: b64e(salt), iterations },
    counts: {
      contacts: bundle.contacts.length,
      messages: bundle.messages.length,
      chunks: bundle.chunks.length,
      skipped: bundle.skipped.length,
    },
  };
  const headerBytes = canonicalJsonBytes(header);
  const plaintext = zlibCompress(encodeBundle(bundle), 9);
  const [nonce, ciphertext] = encrypt(key, plaintext, HISTORY_MAGIC);

  const out = new Uint8Array(9 + headerBytes.length + nonce.length + ciphertext.length);
  out.set(HISTORY_MAGIC, 0);
  out[4] = HISTORY_VERSION;
  out[5] = (headerBytes.length >>> 24) & 0xff;
  out[6] = (headerBytes.length >>> 16) & 0xff;
  out[7] = (headerBytes.length >>> 8) & 0xff;
  out[8] = headerBytes.length & 0xff;
  out.set(headerBytes, 9);
  out.set(nonce, 9 + headerBytes.length);
  out.set(ciphertext, 9 + headerBytes.length + nonce.length);
  return out;
}

export async function importHistory(
  client: Client,
  data: Uint8Array,
  passphrase: string,
): Promise<MergeCounts> {
  const header = readExportHeader(data);
  if (!passphrase) throw new HistoryError('this history file needs its passphrase');
  let salt: Uint8Array;
  let iterations: number;
  try {
    salt = b64d(String(header.kdf.salt));
    iterations = Number(header.kdf.iterations);
  } catch {
    throw new HistoryError('malformed history file header');
  }

  const length = (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
  const body = data.slice(9 + length);
  if (body.length <= 12) throw new HistoryError('history file is truncated');
  const key = await exportKey(passphrase, salt, iterations);
  let plaintext: Uint8Array;
  try {
    plaintext = decrypt(key, body.slice(0, 12), body.slice(12), HISTORY_MAGIC);
  } catch (error) {
    if (error instanceof AEADError) {
      throw new HistoryError('wrong passphrase, or the file is damaged');
    }
    throw error;
  }
  let bundle: Bundle;
  try {
    bundle = decodeBundle(zlibDecompress(plaintext));
  } catch (error) {
    if (error instanceof HistoryError) throw error;
    throw new HistoryError('history file is damaged');
  }
  return mergeBundle(client, bundle);
}
