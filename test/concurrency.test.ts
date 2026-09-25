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

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function makeClient(name: string): Promise<Client> {
  const identity = Identity.generate(name)[0];
  const store = await LocalStore.open(randomBytes(32), identity.identityId);
  const client = new Client(identity, store, [relay.url], name, undefined, undefined, 10);
  await client.provision();
  return client;
}

/**
 * Mirrors the UI: a background long-poll loop runs *concurrently* with the user
 * sending messages. If session state is not serialized, a sync and a send can
 * clobber each other and a message is silently lost.
 */
describe('concurrent poll loop and sends', () => {
  it('loses no messages when syncing and sending overlap', async () => {
    const alice = await makeClient('alice');
    const bob = await makeClient('bob');
    await alice.addContact(await bob.cardString());

    const gotAlice: string[] = [];
    const gotBob: string[] = [];
    let running = true;

    const aliceLoop = (async () => {
      while (running) {
        try {
          for (const message of await alice.sync(1)) gotAlice.push(String((message.body as any)?.text));
        } catch {
          /* keep polling, like the UI does */
        }
      }
    })();
    const bobLoop = (async () => {
      while (running) {
        try {
          for (const message of await bob.sync(1)) gotBob.push(String((message.body as any)?.text));
        } catch {
          /* keep polling */
        }
      }
    })();

    // Alice initiates; Bob learns her contact from the first message's card.
    await alice.sendText(bob.identityId, 'a0');
    for (let i = 0; i < 100 && (await bob.listContacts()).length === 0; i++) await sleep(100);
    expect((await bob.listContacts()).length).toBeGreaterThan(0);

    const rounds = 10;
    for (let i = 1; i <= rounds; i++) {
      await bob.sendText(alice.identityId, `b${i}`);
      await alice.sendText(bob.identityId, `a${i}`);
    }

    await sleep(5000);
    running = false;
    await Promise.all([aliceLoop, bobLoop]);

    const expectedAlice = Array.from({ length: rounds }, (_, i) => `b${i + 1}`);
    const expectedBob = ['a0', ...Array.from({ length: rounds }, (_, i) => `a${i + 1}`)];
    const missingAlice = expectedAlice.filter((text) => !gotAlice.includes(text));
    const missingBob = expectedBob.filter((text) => !gotBob.includes(text));
    console.log('alice received:', gotAlice.length, 'missing:', missingAlice);
    console.log('bob received:', gotBob.length, 'missing:', missingBob);

    expect(missingAlice, `alice never received: ${missingAlice}`).toEqual([]);
    expect(missingBob, `bob never received: ${missingBob}`).toEqual([]);
  }, 180_000);
});
