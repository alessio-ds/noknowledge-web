import 'fake-indexeddb/auto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '../src/core/client';
import { LocalStore } from '../src/core/store';
import { Identity } from '../src/crypto/identity';
import { exportHistory, importHistory } from '../src/core/history';
import { randomBytes } from '../src/crypto/random';
import { PythonPeer, startRelay, type RelayHandle } from './helpers';

let relay: RelayHandle;

beforeAll(async () => {
  relay = await startRelay();
}, 180_000);

afterAll(async () => {
  await relay?.stop();
});

async function webClient(name: string): Promise<Client> {
  const identity = Identity.generate(name)[0];
  const store = await LocalStore.open(randomBytes(32), identity.identityId);
  const client = new Client(identity, store, [relay.url], name, undefined, undefined, 5);
  await client.provision();
  return client;
}

describe('TypeScript client <-> Python reference client', () => {
  it('exchanges cards, text, receipts and files in both directions', async () => {
    const web = await webClient('web');
    const { peer, card, id: peerId } = await PythonPeer.start({
      relays: [relay.url],
      name: 'python',
    });

    try {
      // 1. The web client adds the Python card and opens the conversation.
      await web.addContact(card);
      await web.sendText(peerId, 'hello from the web');

      // 2. Python decrypts it, verifies the sealed-sender auth and auto-adds us.
      const pythonInbox = await peer.send({ cmd: 'sync', wait: 0 });
      expect(pythonInbox.ok).toBe(true);
      expect(
        pythonInbox.messages.some((m: any) => m.body?.text === 'hello from the web'),
      ).toBe(true);
      const pythonContacts = await peer.send({ cmd: 'contacts' });
      expect(pythonContacts.contacts.map((c: any) => c.id)).toContain(web.identityId);

      // 3. Python replies; our client decrypts a message produced by Python.
      await peer.send({ cmd: 'send_text', contact: web.identityId, text: 'hello from python' });
      const inbound = await web.sync(0);
      expect(inbound.some((m) => (m.body as any).text === 'hello from python')).toBe(true);

      // 4. Web -> Python attachment.
      const webPayload = randomBytes(200_000);
      await web.sendFile(peerId, webPayload, 'from-web.bin', 'application/octet-stream');
      const pythonFiles = await peer.send({ cmd: 'sync', wait: 0 });
      const pythonFile = pythonFiles.messages.find((m: any) => m.type === 'file');
      expect(pythonFile).toBeTruthy();
      const downloadedByPython = await peer.send({ cmd: 'download', message_id: pythonFile.id });
      expect(Buffer.from(downloadedByPython.data_b64, 'base64').equals(Buffer.from(webPayload))).toBe(true);

      // 5. Python -> web attachment, decrypted by the browser code.
      const dir = mkdtempSync(path.join(tmpdir(), 'nk-file-'));
      const filePath = path.join(dir, 'from-python.bin');
      const pythonPayload = randomBytes(300_000);
      writeFileSync(filePath, pythonPayload);
      await peer.send({ cmd: 'send_file', contact: web.identityId, path: filePath });
      await web.sync(0);
      const webFile = (await web.messages(peerId)).find(
        (m) => m.type === 'file' && (m.body as any)?.attachment?.name === 'from-python.bin',
      );
      expect(webFile).toBeTruthy();
      const downloadedByWeb = await web.downloadAttachment(webFile!);
      expect(Array.from(downloadedByWeb)).toEqual(Array.from(pythonPayload));

      // 6. Python read receipt reaches the web client's sent message.
      const webSent = (await web.messages(peerId)).find(
        (m) => m.direction === 'sent' && (m.body as any)?.text === 'hello from the web',
      );
      expect(webSent).toBeTruthy();
      const pythonReceived = pythonInbox.messages.find(
        (m: any) => m.body?.text === 'hello from the web',
      );
      await peer.send({ cmd: 'mark_read', contact: web.identityId, message_id: pythonReceived.id });
      await web.sync(0);
      const updated = (await web.messages(peerId)).find((m) => m.id === webSent!.id);
      expect(updated?.state).toBe('read');
    } finally {
      await peer.stop();
    }
  }, 120_000);
});

describe('history files across implementations', () => {
  async function webClientWithHistory(name: string): Promise<{ client: Client; contactId: string }> {
    const identity = Identity.generate(name)[0];
    const store = await LocalStore.open(randomBytes(32), identity.identityId, `interop-${name}`);
    const client = new Client(identity, store, [relay.url], name, undefined, undefined, 5);
    await client.provision();
    return { client, contactId: '' };
  }

  it('imports a history file written by the desktop client', async () => {
    const { peer, card, id: peerId } = await PythonPeer.start({
      relays: [relay.url],
      name: 'python-source',
    });
    try {
      // Give the Python side a real conversation with us.
      const web = await webClientWithHistory('web-target');
      await web.client.addContact(card);
      await web.client.sendText(peerId, 'from the web');
      await peer.send({ cmd: 'sync', wait: 0 });

      const dir = mkdtempSync(path.join(tmpdir(), 'nk-hist-'));
      const file = path.join(dir, 'from-python.nkx');
      const exported = await peer.send({
        cmd: 'export_history',
        path: file,
        passphrase: 'shared-passphrase',
      });
      expect(exported.ok).toBe(true);

      // The browser reads a file the desktop client wrote.
      const data = new Uint8Array(readFileSync(file));
      const counts = await importHistory(web.client, data, 'shared-passphrase');

      expect(counts.messages).toBeGreaterThanOrEqual(1);
      expect(counts.contacts).toBeGreaterThanOrEqual(1);
      const messages = await web.client.messages(peerId);
      expect(messages.some((m) => (m.body as any)?.text === 'from the web')).toBe(true);
    } finally {
      await peer.stop();
    }
  }, 120_000);

  it('writes a history file the desktop client can import', async () => {
    const web = await webClientWithHistory('web-source');
    const { peer, id: peerId } = await PythonPeer.start({
      relays: [relay.url],
      name: 'python-target',
    });
    try {
      await peer.send({ cmd: 'add_contact', card: await web.client.cardString() });
      await peer.send({ cmd: 'send_text', contact: web.client.identityId, text: 'from python' });
      const inbound = await web.client.sync(0);
      expect(inbound).toHaveLength(1);

      const dir = mkdtempSync(path.join(tmpdir(), 'nk-hist-'));
      const file = path.join(dir, 'from-web.nkx');
      writeFileSync(file, await exportHistory(web.client, 'shared-passphrase'));

      const imported = await peer.send({
        cmd: 'import_history',
        path: file,
        passphrase: 'shared-passphrase',
      });

      expect(imported.ok).toBe(true);
      expect(imported.counts.messages).toBe(1);
      const stored = await peer.send({ cmd: 'messages', contact: web.client.identityId });
      expect(stored.messages.map((m: any) => m.body?.text)).toContain('from python');
      expect(peerId).toBeTruthy();
    } finally {
      await peer.stop();
    }
  }, 120_000);
});
