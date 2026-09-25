/** Multi-device accounts, end to end against a real relay.
 *
 * An account is the seed; a device is one mailbox with its own prekeys and its
 * own Double Ratchet sessions. These tests pin down that a second device — a
 * fresh install, or one restored from the seed phrase — really starts receiving,
 * and that a peer without a device list still works through the card's inbox. */

import 'fake-indexeddb/auto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '../src/core/client';
import { LocalStore } from '../src/core/store';
import { Identity } from '../src/crypto/identity';
import { randomBytes } from '../src/crypto/random';
import { startRelay, type RelayHandle } from './helpers';

let relay: RelayHandle;

beforeAll(async () => {
  relay = await startRelay();
}, 180_000);

afterAll(async () => {
  await relay?.stop();
});

async function browser(
  name: string,
  identity: Identity,
  namespace: string,
  relays: string[] = [relay.url],
): Promise<Client> {
  const store = await LocalStore.open(randomBytes(32), identity.identityId, namespace);
  return new Client(identity, store, relays, name, undefined, undefined, 5);
}

describe('multiple devices on one account', () => {
  it('delivers a copy to every device and lets each one read it', async () => {
    const alice = await browser('alice', Identity.generate('alice')[0], 'alice');
    const bobIdentity = Identity.generate('bob')[0];
    const bob = await browser('bob', bobIdentity, 'bob-laptop');
    const bob2 = await browser('bob-phone', bobIdentity, 'bob-phone');
    await alice.provision();
    await bob.provision();
    await bob2.provision();

    const devices = await bob.devices();
    expect(devices).toHaveLength(2);
    expect(new Set(devices.map((device) => device.deviceId)).size).toBe(2);
    // Each device keeps its own mailbox, which is the whole point.
    expect(devices[0].inbox.id).not.toBe(devices[1].inbox.id);

    await alice.addContact(await bob.cardString(), 'Bob');
    await alice.sendText(bobIdentity.identityId, 'to every device');

    expect((await bob.sync(0)).map((m) => (m.body as any).text)).toEqual(['to every device']);
    expect((await bob2.sync(0)).map((m) => (m.body as any).text)).toEqual(['to every device']);
  }, 120_000);

  it('lets a device restored from the seed phrase join and receive', async () => {
    const alice = await browser('alice', Identity.generate('alice')[0], 'alice');
    const bobIdentity = Identity.generate('bob')[0];
    const bob = await browser('bob', bobIdentity, 'bob-laptop');
    await alice.provision();
    await bob.provision();
    await alice.addContact(await bob.cardString(), 'Bob');

    await alice.sendText(bobIdentity.identityId, 'before recovery');
    expect((await bob.sync(0)).map((m) => (m.body as any).text)).toEqual(['before recovery']);

    // Restoring the seed phrase in a fresh browser profile: same keys, brand new
    // mailbox.
    const recovered = await browser('bob-new', bobIdentity, 'bob-restored');
    await recovered.provision();
    expect(recovered.identityId).toBe(bobIdentity.identityId);
    expect((await recovered.devices()).length).toBe(2);
    // Messages sent before it existed are not magically on the new device.
    expect(await recovered.sync(0)).toEqual([]);

    await alice.sendText(bobIdentity.identityId, 'after recovery');
    expect((await recovered.sync(0)).map((m) => (m.body as any).text)).toEqual(['after recovery']);
    expect((await bob.sync(0)).map((m) => (m.body as any).text)).toEqual(['after recovery']);
  }, 120_000);

  it('reaches a peer that published no device list through the card inbox', async () => {
    const alice = await browser('alice', Identity.generate('alice')[0], 'alice');
    const bob = await browser('bob', Identity.generate('bob')[0], 'bob');
    await alice.provision();
    // Simulate a peer that never registered (an older client).
    (bob as any).ensureDeviceRegistered = async () => {};
    await bob.provision();

    await alice.addContact(await bob.cardString(), 'Bob');
    await alice.sendText(bob.identityId, 'legacy path');

    expect((await bob.sync(0)).map((m) => (m.body as any).text)).toEqual(['legacy path']);
  }, 120_000);

  it('sends a file to every device, each with its own chunk ids', async () => {
    const alice = await browser('alice', Identity.generate('alice')[0], 'alice');
    const bobIdentity = Identity.generate('bob')[0];
    const bob = await browser('bob', bobIdentity, 'bob-laptop');
    const bob2 = await browser('bob-phone', bobIdentity, 'bob-phone');
    await alice.provision();
    await bob.provision();
    await bob2.provision();
    await alice.addContact(await bob.cardString(), 'Bob');

    const payload = randomBytes(300_000);
    await alice.sendFile(bobIdentity.identityId, payload, 'doc.bin', 'application/octet-stream');

    const first = await bob.sync(0);
    const second = await bob2.sync(0);
    expect(first).toHaveLength(1);
    expect(second).toHaveLength(1);
    expect(Array.from(await bob.downloadAttachment(first[0]))).toEqual(Array.from(payload));
    expect(Array.from(await bob2.downloadAttachment(second[0]))).toEqual(Array.from(payload));
  }, 120_000);

  it('keeps the ordinary one-device case working', async () => {
    const alice = await browser('alice', Identity.generate('alice')[0], 'alice');
    const bob = await browser('bob', Identity.generate('bob')[0], 'bob');
    await alice.provision();
    await bob.provision();
    await alice.addContact(await bob.cardString(), 'Bob');

    await alice.sendText(bob.identityId, 'one device, one copy');
    expect((await bob.sync(0)).map((m) => (m.body as any).text)).toEqual(['one device, one copy']);
    expect((await alice.devices()).length).toBe(1);
    expect((await bob.devices()).length).toBe(1);
    // A receipt from the single device still clears the sender's outbox row.
    await alice.sync(0);
    expect((await alice.messages(bob.identityId))[0].state).toBe('delivered');
  }, 120_000);
});