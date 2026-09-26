/** History bundles: export files and the shape device back-fill will reuse. */

import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { Client } from '../src/core/client';
import {
  HISTORY_MAGIC,
  HistoryError,
  buildBundle,
  decodeBundle,
  encodeBundle,
  exportHistory,
  importHistory,
  isHistoryFile,
  readExportHeader,
} from '../src/core/history';
import { LocalStore } from '../src/core/store';
import { b64e } from '../src/crypto/encoding';
import { Identity } from '../src/crypto/identity';
import { randomBytes } from '../src/crypto/random';

let counter = 0;
function namespace(): string {
  counter += 1;
  return `history-${counter}`;
}

async function storeClient(name: string, identity?: Identity): Promise<Client> {
  const owner = identity ?? Identity.generate(name)[0];
  const store = await LocalStore.open(randomBytes(32), owner.identityId, namespace());
  return new Client(owner, store, ['http://127.0.0.1:1'], name);
}

async function addContact(client: Client, contactId: string, nickname = 'Bob'): Promise<void> {
  await client.store.upsertContact(client.identityId, {
    id: contactId,
    identity_id: client.identityId,
    nickname,
    isign: b64e(randomBytes(32)),
    idh: b64e(randomBytes(32)),
    bundle_id: 'bundle',
    inbox: { id: 'mailbox', w: 'write-token' },
    relays: ['https://relay.example'],
    session: null,
    verified: false,
    created_at: 1,
  });
}

async function addMessage(client: Client, contactId: string, overrides: Record<string, unknown> = {}) {
  const message = {
    id: b64e(randomBytes(16)),
    identity_id: client.identityId,
    contact_id: contactId,
    direction: 'received' as const,
    type: 'text',
    body: { text: 'hello' },
    remote_id: 'env-1',
    ts: 1000,
    state: 'received',
    meta: null,
    ...overrides,
  };
  await client.store.addMessage(message as any);
  return message;
}

describe('history bundles', () => {
  it('round-trips contacts, messages and attachment chunks', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    await addMessage(source, 'bob-id');
    await addMessage(source, 'bob-id', { direction: 'sent', remote_id: null, ts: 2000, body: { text: 'mine' } });

    const bundle = await buildBundle(source);
    expect(bundle.contacts).toHaveLength(1);
    expect(bundle.messages).toHaveLength(2);

    const target = await storeClient('target');
    const counts = await importHistoryBundle(target, bundle);

    expect(counts).toEqual({ contacts: 1, messages: 2, updates: 0, chunks: 0 });
    const messages = await target.messages('bob-id');
    expect(messages.map((message) => (message.body as any).text).sort()).toEqual(['hello', 'mine']);
  });

  it('is idempotent, so a carbon plus a back-fill collapse into one row', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    await addMessage(source, 'bob-id');
    const bundle = await buildBundle(source);

    const target = await storeClient('target');
    expect((await importHistoryBundle(target, bundle)).messages).toBe(1);
    expect(await importHistoryBundle(target, bundle)).toEqual({
      contacts: 0,
      messages: 0,
      updates: 0,
      chunks: 0,
    });
    expect(await target.messages('bob-id')).toHaveLength(1);
  });

  it('never downgrades read state', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    await addMessage(source, 'bob-id', { state: 'read' });
    const bundle = await buildBundle(source);

    const target = await storeClient('target');
    await addContact(target, 'bob-id');
    await addMessage(target, 'bob-id', { state: 'received' });

    const counts = await importHistoryBundle(target, bundle);

    expect(counts.messages).toBe(0);
    expect(counts.updates).toBe(1);
    expect((await target.messages('bob-id'))[0].state).toBe('read');

    bundle.messages[0].state = 'received';
    await importHistoryBundle(target, bundle);
    expect((await target.messages('bob-id'))[0].state).toBe('read');
  });

  it('keeps a local nickname, verification flag and routing', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id', 'Bob from source');
    const bundle = await buildBundle(source);

    const target = await storeClient('target');
    await addContact(target, 'bob-id', 'My Bob');
    const contact = await target.store.getContact(target.identityId, 'bob-id');
    await target.store.upsertContact(target.identityId, { ...contact!, verified: true, relays: ['https://new.example'] });

    expect((await importHistoryBundle(target, bundle)).contacts).toBe(0);
    const merged = await target.store.getContact(target.identityId, 'bob-id');
    expect(merged?.nickname).toBe('My Bob');
    expect(merged?.verified).toBe(true);
    expect(merged?.relays).toEqual(['https://new.example']);
  });

  it('filters messages by range but always carries contacts', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    await addMessage(source, 'bob-id', { ts: 1000, remote_id: 'old' });
    await addMessage(source, 'bob-id', { ts: 2000, remote_id: 'new' });

    const bundle = await buildBundle(source, { sinceMs: 1500, untilMs: 2500 });

    expect(bundle.messages.map((message) => message.remote_id)).toEqual(['new']);
    expect(bundle.contacts).toHaveLength(1);
  });

  it('reports attachments over budget instead of dropping them silently', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    await source.store.putLocalBlob('chunk-small', new Uint8Array(10));
    await source.store.putLocalBlob('chunk-big', new Uint8Array(100));
    await addMessage(source, 'bob-id', {
      type: 'file',
      body: {
        caption: '',
        attachment: {
          chunks: [
            { id: 'chunk-small', nonce: b64e(randomBytes(12)) },
            { id: 'chunk-big', nonce: b64e(randomBytes(12)) },
          ],
        },
      },
    });

    const bundle = await buildBundle(source, { budgetBytes: 50 });

    expect(bundle.chunks.map((chunk) => chunk.id)).toEqual(['chunk-small']);
    expect(bundle.skipped).toEqual([{ id: 'chunk-big', reason: 'over budget' }]);
  });

  it('carries no local secrets', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    const contact = await source.store.getContact(source.identityId, 'bob-id');
    await source.store.upsertContact(source.identityId, {
      ...contact!,
      session: { v: 2, marker: 'device-local-ratchet' },
    });
    await addMessage(source, 'bob-id');

    const raw = new TextDecoder().decode(encodeBundle(await buildBundle(source)));

    expect(raw).not.toContain('device-local-ratchet');
    expect(raw).not.toContain(b64e(source.identity.edPrivateBytes));
  });
});

describe('history export files', () => {
  it('round-trips through the encrypted file', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    await addMessage(source, 'bob-id');

    const data = await exportHistory(source, 'correct horse');

    expect(isHistoryFile(data)).toBe(true);
    expect(readExportHeader(data).counts.messages).toBe(1);

    const target = await storeClient('target');
    const counts = await importHistory(target, data, 'correct horse');

    expect(counts.messages).toBe(1);
    expect((await target.messages('bob-id'))[0].body).toEqual({ text: 'hello' });
  });

  it('rejects a wrong passphrase, tampering and truncation', async () => {
    const source = await storeClient('source');
    await addContact(source, 'bob-id');
    const data = await exportHistory(source, 'right');

    const target = await storeClient('target');
    await expect(importHistory(target, data, 'wrong')).rejects.toThrow(/passphrase/);

    const tampered = new Uint8Array(data);
    tampered[tampered.length - 1] ^= 0x01;
    await expect(importHistory(target, tampered, 'right')).rejects.toThrow(HistoryError);

    await expect(importHistory(target, data.slice(0, 20), 'right')).rejects.toThrow(/truncated/);
  });

  it('needs a passphrase to export, and refuses foreign files', async () => {
    const source = await storeClient('source');
    await expect(exportHistory(source, '')).rejects.toThrow(HistoryError);
    expect(isHistoryFile(new TextEncoder().encode('not a history file'))).toBe(false);
    expect(HISTORY_MAGIC.length).toBe(4);
  });

  it('refuses an unsupported bundle version', () => {
    expect(() => decodeBundle(JSON.stringify({ v: 99, contacts: [], messages: [], chunks: [] }))).toThrow(
      HistoryError,
    );
  });
});

async function importHistoryBundle(client: Client, bundle: unknown) {
  const { mergeBundle } = await import('../src/core/history');
  return mergeBundle(client, bundle as any);
}