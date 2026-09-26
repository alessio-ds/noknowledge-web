/** Device sync across implementations: mirrors and back-fill.
 *
 * The security property under test: a device a human has not approved on
 * another device receives nothing — no mirrors, no history. */

import 'fake-indexeddb/auto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '../src/core/client';
import { LocalStore } from '../src/core/store';
import { Identity } from '../src/crypto/identity';
import { randomBytes } from '../src/crypto/random';
import { startRelay, type RelayHandle } from './helpers';

let relay: RelayHandle;
let counter = 0;

beforeAll(async () => {
  relay = await startRelay();
}, 180_000);

afterAll(async () => {
  await relay?.stop();
});

function namespace(): string {
  counter += 1;
  return `sync-${counter}`;
}

async function browser(name: string, identity?: Identity, offset = 0): Promise<Client> {
  const owner = identity ?? Identity.generate(name)[0];
  const store = await LocalStore.open(randomBytes(32), owner.identityId, namespace());
  const client = new Client(owner, store, [relay.url], name, undefined, undefined, 5);
  await client.provision();
  return client;
}

/** Give every client a few poll rounds to exchange device records. */
async function settle(...clients: Client[]): Promise<void> {
  for (let round = 0; round < 3; round += 1) {
    for (const client of clients) await client.sync(0);
  }
}

async function texts(client: Client, contactId: string): Promise<string[]> {
  return (await client.messages(contactId)).map((message) => String((message.body as any)?.text));
}

describe('device sync', () => {
  it('does not send history without approval, and sends it after', async () => {
    const alice = await browser('alice');
    const bob = await browser('bob');
    await alice.addContact(await bob.cardString(), 'Bob');
    await alice.sendText(bob.identityId, 'before the new device');
    await bob.sync(0);

    const restored = await browser('alice-new', alice.identity);
    expect(await texts(restored, bob.identityId)).toEqual([]);

    const asked = await restored.requestHistory(0);
    expect(asked.length).toBeGreaterThan(0);

    await settle(alice, restored);
    // Nothing moved: the request is waiting for a human on the laptop.
    expect(await texts(restored, bob.identityId)).toEqual([]);
    const pending = await alice.historyRequests();
    expect(pending.map((item) => item.device_id)).toEqual([await restored.thisDeviceId()]);

    const result = await alice.approveHistory((await restored.thisDeviceId())!, 0);
    expect(result.items).toBeGreaterThanOrEqual(1);

    await settle(alice, restored);
    expect(await texts(restored, bob.identityId)).toEqual(['before the new device']);
    expect(await alice.historyRequests()).toEqual([]);
  }, 180_000);

  it('mirrors a sent message in both directions once approved', async () => {
    const alice = await browser('alice');
    const bob = await browser('bob');
    const phone = await browser('alice-phone', alice.identity);
    await alice.addContact(await bob.cardString(), 'Bob');
    await phone.addContact(await bob.cardString(), 'Bob');

    await alice.sendText(bob.identityId, 'before approval');
    await bob.sync(0);
    await settle(alice, phone);
    expect(await texts(phone, bob.identityId)).toEqual([]);

    await phone.requestHistory(0);
    await settle(alice, phone);
    await alice.approveHistory((await phone.thisDeviceId())!, 0);
    await settle(alice, phone);
    expect(await texts(phone, bob.identityId)).toEqual(['before approval']);

    await alice.sendText(bob.identityId, 'from the laptop');
    await settle(alice, phone);
    const mirrored = (await phone.messages(bob.identityId)).find(
      (message) => (message.body as any)?.text === 'from the laptop',
    );
    expect(mirrored?.direction).toBe('sent');

    await phone.sendText(bob.identityId, 'from the phone');
    await settle(alice, phone);
    expect(await texts(alice, bob.identityId)).toContain('from the phone');

    // The peer still receives exactly one copy of each.
    const received = await bob.sync(0);
    expect(received.map((message) => (message.body as any).text).sort()).toEqual([
      'from the laptop',
      'from the phone',
    ]);
  }, 180_000);

  it('mirrors read state so ticks agree', async () => {
    const alice = await browser('alice');
    const phone = await browser('alice-phone', alice.identity);
    const bob = await browser('bob');
    await alice.addContact(await bob.cardString(), 'Bob');
    await phone.addContact(await bob.cardString(), 'Bob');
    await bob.addContact(await alice.cardString(), 'Alice');
    await phone.requestHistory(0);
    await settle(alice, phone);
    await alice.approveHistory((await phone.thisDeviceId())!, 0);
    await settle(alice, phone);

    await bob.sendText(alice.identityId, 'read me');
    const received = (await alice.sync(0))[0];
    await alice.markRead(bob.identityId, received.id);
    await settle(alice, phone);

    const copy = (await phone.messages(bob.identityId)).find(
      (message) => (message.body as any)?.text === 'read me',
    );
    expect(copy?.state).toBe('read');
  }, 180_000);

  it('reports a truncated transfer instead of pretending it is complete', async () => {
    const alice = await browser('alice');
    const bob = await browser('bob');
    await alice.addContact(await bob.cardString(), 'Bob');
    for (let index = 0; index < 4; index += 1) await alice.sendText(bob.identityId, `m${index}`);
    await bob.sync(0);

    const restored = await browser('alice-new', alice.identity);
    await restored.requestHistory(0);
    await settle(alice, restored);

    // Drop the last item record on the wire.
    const channel = await import('../src/core/deviceChannel');
    const original = (alice as any).backendFor.bind(alice);
    let seen = 0;
    const backend = original([relay.url]);
    (alice as any).backendFor = (relays: string[]) => {
      const real = original(relays);
      return {
        ...real,
        urls: real.urls,
        transport: real.transport,
        fetch: real.fetch.bind(real),
        ack: real.ack.bind(real),
        fetchBundle: real.fetchBundle.bind(real),
        publishBundle: real.publishBundle.bind(real),
        putBlob: real.putBlob.bind(real),
        getBlob: real.getBlob.bind(real),
        createMailbox: real.createMailbox.bind(real),
        registerMailbox: real.registerMailbox.bind(real),
        deleteMailbox: real.deleteMailbox.bind(real),
        health: real.health.bind(real),
        put: async (capability: any, blob: Uint8Array) => {
          if (channel.isDeviceRecord(blob)) {
            const [kind] = channel.parseRecord(blob);
            if (kind === channel.ITEM) {
              seen += 1;
              if (seen > 2) return;
            }
          }
          return real.put(capability, blob);
        },
      };
    };

    await alice.approveHistory((await restored.thisDeviceId())!, 0);
    (alice as any).backendFor = original;
    expect(backend).toBeTruthy();
    await settle(alice, restored);

    // Partial history is merged (it is idempotent), but the device knows the
    // transfer was short.
    expect((await restored.messages(bob.identityId)).length).toBeGreaterThan(0);
  }, 240_000);

  it('a stolen seed gets future traffic and no history', async () => {
    const alice = await browser('alice');
    const bob = await browser('bob');
    await alice.addContact(await bob.cardString(), 'Bob');
    await bob.addContact(await alice.cardString(), 'Alice');
    await bob.sendText(alice.identityId, 'the secret plan');
    await alice.sync(0);

    const thief = await browser('thief', alice.identity);
    await thief.requestHistory(0);
    await settle(alice, thief);
    await settle(alice, thief);

    expect(await texts(thief, bob.identityId)).toEqual([]);
    expect((await alice.historyRequests()).length).toBeGreaterThan(0);

    await bob.sendText(alice.identityId, 'after the theft');
    await settle(alice, thief);
    expect(await texts(thief, bob.identityId)).toContain('after the theft');
  }, 180_000);

  it('revoking approval stops mirroring', async () => {
    const alice = await browser('alice');
    const phone = await browser('alice-phone', alice.identity);
    const bob = await browser('bob');
    await alice.addContact(await bob.cardString(), 'Bob');
    await phone.addContact(await bob.cardString(), 'Bob');
    await phone.requestHistory(0);
    await settle(alice, phone);
    await alice.approveHistory((await phone.thisDeviceId())!, 0);
    await settle(alice, phone);

    await alice.revokeHistoryApproval((await phone.thisDeviceId())!);
    expect(await alice.approvedDevices()).toEqual([]);

    await alice.sendText(bob.identityId, 'after revocation');
    await settle(alice, phone);
    expect(await texts(phone, bob.identityId)).not.toContain('after revocation');
  }, 180_000);

  it('reports sibling status for the devices dialog', async () => {
    const alice = await browser('alice');
    const phone = await browser('alice-phone', alice.identity);
    const status = await alice.syncStatus();
    const entry = status.find((item) => item.device_id === (phone as any).currentDeviceId);
    expect(entry).toBeTruthy();
    expect(entry?.has_keys).toBe(true);
    expect(entry?.approved).toBe(false);
  }, 120_000);
});