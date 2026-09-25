import 'fake-indexeddb/auto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '../src/core/client';
import { LocalStore } from '../src/core/store';
import { Identity } from '../src/crypto/identity';
import { randomBytes } from '../src/crypto/random';
import { startRelay, type RelayHandle } from './helpers';

let relay: RelayHandle;
let relayB: RelayHandle;

beforeAll(async () => {
  relay = await startRelay();
  relayB = await startRelay();
}, 180_000);

afterAll(async () => {
  await relay?.stop();
  await relayB?.stop();
});

async function makeClient(name: string, relays: string[], opkCount = 5): Promise<Client> {
  const identity = Identity.generate(name)[0];
  const store = await LocalStore.open(randomBytes(32), identity.identityId);
  const client = new Client(identity, store, relays, name, undefined, undefined, opkCount);
  await client.provision();
  return client;
}

describe('browser client against a real relay', () => {
  it('performs a full X3DH handshake and exchanges text both ways', async () => {
    const alice = await makeClient('alice', [relay.url]);
    const bob = await makeClient('bob', [relay.url]);

    await alice.addContact(await bob.cardString());
    await alice.sendText(bob.identityId, 'hello bob');

    const atBob = await bob.sync(0);
    expect(atBob.map((m) => (m.body as any).text)).toContain('hello bob');
    // The first message carried Alice's card, so Bob learned the contact.
    const bobContacts = await bob.listContacts();
    expect(bobContacts.map((c) => c.id)).toContain(alice.identityId);

    await bob.sendText(alice.identityId, 'hi alice');
    const atAlice = await alice.sync(0);
    expect(atAlice.map((m) => (m.body as any).text)).toContain('hi alice');

    // Bob's client auto-acknowledged Alice's message with a delivery receipt.
    const aliceHistory = await alice.messages(bob.identityId);
    const original = aliceHistory.find((m) => (m.body as any).text === 'hello bob');
    expect(['delivered', 'read']).toContain(original?.state);

    // Marking read propagates back.
    const received = (await bob.messages(alice.identityId)).find((m) => (m.body as any).text === 'hello bob')!;
    await bob.markRead(alice.identityId, received.id);
    await alice.sync(0);
    const afterRead = (await alice.messages(bob.identityId)).find((m) => m.id === original!.id);
    expect(afterRead?.state).toBe('read');
  }, 60_000);

  it('sends and downloads an encrypted attachment', async () => {
    const alice = await makeClient('alice2', [relay.url]);
    const bob = await makeClient('bob2', [relay.url]);
    await alice.addContact(await bob.cardString());

    const payload = randomBytes(7000);
    await alice.sendFile(bob.identityId, payload, 'note.bin', 'application/octet-stream');
    await bob.sync(0);

    const fileMessage = (await bob.messages(alice.identityId)).find((m) => m.type === 'file');
    expect(fileMessage).toBeTruthy();
    const downloaded = await bob.downloadAttachment(fileMessage!);
    expect(Array.from(downloaded)).toEqual(Array.from(payload));
  }, 60_000);

  it('does not deliver duplicates when syncing repeatedly', async () => {
    const alice = await makeClient('alice3', [relay.url]);
    const bob = await makeClient('bob3', [relay.url]);
    await alice.addContact(await bob.cardString());
    await alice.sendText(bob.identityId, 'once');
    await bob.sync(0);
    const firstCount = (await bob.messages(alice.identityId)).length;
    await bob.sync(0);
    const secondCount = (await bob.messages(alice.identityId)).length;
    expect(secondCount).toBe(firstCount);
  }, 60_000);

  it('keeps working when one relay in the set goes down', async () => {
    const alice = await makeClient('alice4', [relay.url, relayB.url]);
    const bob = await makeClient('bob4', [relay.url, relayB.url]);
    await alice.addContact(await bob.cardString());

    await relayB.stop();
    await alice.sendText(bob.identityId, 'after failover');
    const atBob = await bob.sync(0);
    expect(atBob.map((m) => (m.body as any).text)).toContain('after failover');
  }, 60_000);
});
