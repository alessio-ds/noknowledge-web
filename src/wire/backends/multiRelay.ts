/** A pool of relays with replication and failover.
 *
 * Writes fan out to every relay in the set; reads aggregate whatever any relay
 * can answer. Because envelopes carry a client-generated id, duplicates across
 * relays are harmless and are filtered by the client core. Any single relay can
 * fail without losing data, which is what makes the relay set — rather than the
 * relay — the unit of availability. */

import { b64e } from '../../crypto/encoding';
import { randomBytes } from '../../crypto/random';
import { AllRelaysFailed, RelayHTTPError, RelayNotFound } from '../errors';
import { Transport } from '../transport';
import { CHUNK_ID_SIZE, MailboxCapability, type FetchedMessage } from './base';
import { HttpRelayBackend } from './httpRelay';

export function normalizeRelayUrls(urls: string[]): string[] {
  const seen: string[] = [];
  for (const url of urls) {
    let cleaned = url.trim().replace(/\/+$/, '');
    if (!cleaned) continue;
    if (!cleaned.startsWith('http://') && !cleaned.startsWith('https://')) {
      cleaned = 'https://' + cleaned;
    }
    if (!seen.includes(cleaned)) seen.push(cleaned);
  }
  return seen;
}

/** Fan-out / fan-in across an ordered set of relays. */
export class MultiRelayBackend {
  readonly transport: Transport;
  readonly relays: HttpRelayBackend[];

  constructor(urls: string[], transport?: Transport) {
    this.transport = transport ?? new Transport();
    this.relays = normalizeRelayUrls(urls).map((url) => new HttpRelayBackend(url, this.transport));
    if (this.relays.length === 0) throw new Error('at least one relay URL is required');
  }

  get urls(): string[] {
    return this.relays.map((relay) => relay.baseUrl);
  }

  // -- mailboxes --------------------------------------------------------

  /** Create one capability and register it on every relay. */
  async createMailbox(): Promise<MailboxCapability> {
    return this.registerMailbox(MailboxCapability.generate());
  }

  async registerMailbox(capability: MailboxCapability): Promise<MailboxCapability> {
    const results = await Promise.allSettled(
      this.relays.map((relay) => relay.createMailbox(capability)),
    );
    if (results.every((result) => result.status === 'rejected')) {
      const first = results.find((r) => r.status === 'rejected') as PromiseRejectedResult;
      throw new AllRelaysFailed(`could not register mailbox: ${String(first.reason)}`);
    }
    return capability;
  }

  async put(capability: MailboxCapability, envelope: Uint8Array): Promise<void> {
    const results = await Promise.allSettled(
      this.relays.map((relay) => relay.put(capability, envelope)),
    );
    let succeeded = 0;
    let lastError: unknown = null;
    for (const result of results) {
      if (result.status === 'fulfilled') succeeded += 1;
      else if (!(result.reason instanceof RelayNotFound)) lastError = result.reason;
    }
    if (succeeded === 0) {
      if (lastError) throw new AllRelaysFailed(`no relay accepted the message: ${String(lastError)}`);
      throw new RelayNotFound(404, 'mailbox not found on any relay');
    }
  }

  /** Fetch from all relays concurrently, tagging each blob with its origin. */
  async fetch(
    capability: MailboxCapability,
    cursors: Record<string, number> = {},
    wait = 0,
  ): Promise<FetchedMessage[]> {
    const results = await Promise.allSettled(
      this.relays.map(async (relay) => ({
        relay: relay.baseUrl,
        rows: await relay.fetch(capability, cursors[relay.baseUrl] ?? 0, wait),
      })),
    );
    const collected: FetchedMessage[] = [];
    for (const result of results) {
      if (result.status !== 'fulfilled') continue; // one relay failing is not an error
      for (const [seq, blob] of result.value.rows) {
        collected.push({ relay: result.value.relay, seq, blob });
      }
    }
    return collected;
  }

  async ack(capability: MailboxCapability, cursors: Record<string, number>): Promise<void> {
    await Promise.allSettled(
      this.relays
        .filter((relay) => cursors[relay.baseUrl] !== undefined)
        .map((relay) => relay.ack(capability, cursors[relay.baseUrl])),
    );
  }

  async deleteMailbox(capability: MailboxCapability): Promise<void> {
    await Promise.allSettled(this.relays.map((relay) => relay.deleteMailbox(capability)));
  }

  // -- prekeys ----------------------------------------------------------

  async publishBundle(bundleId: string, bundle: Uint8Array): Promise<string> {
    let succeeded = 0;
    let lastError: unknown = null;
    for (const relay of this.relays) {
      try {
        await relay.publishBundle(bundleId, bundle);
        succeeded += 1;
      } catch (error) {
        lastError = error;
      }
    }
    if (succeeded === 0) throw new AllRelaysFailed(`could not publish prekey bundle: ${String(lastError)}`);
    return bundleId;
  }

  async fetchBundle(bundleId: string): Promise<any> {
    let lastError: unknown = null;
    for (const relay of this.relays) {
      try {
        return await relay.fetchBundle(bundleId);
      } catch (error) {
        lastError = error;
      }
    }
    throw new RelayNotFound(404, `bundle not found on any relay: ${String(lastError)}`);
  }

  // -- blobs ------------------------------------------------------------

  async putBlob(capability: MailboxCapability, chunk: Uint8Array): Promise<string> {
    const chunkId = b64e(randomBytes(CHUNK_ID_SIZE));
    let succeeded = 0;
    let lastError: unknown = null;
    for (const relay of this.relays) {
      try {
        await relay.putBlob(capability, chunkId, chunk);
        succeeded += 1;
      } catch (error) {
        lastError = error;
      }
    }
    if (succeeded === 0) throw new AllRelaysFailed(`could not upload chunk: ${String(lastError)}`);
    return chunkId;
  }

  async getBlob(capability: MailboxCapability, chunkId: string): Promise<Uint8Array> {
    let lastError: unknown = null;
    for (const relay of this.relays) {
      try {
        return await relay.getBlob(capability, chunkId);
      } catch (error) {
        lastError = error;
      }
    }
    throw new RelayNotFound(404, `blob not found on any relay: ${String(lastError)}`);
  }

  async health(): Promise<Array<Record<string, unknown>>> {
    const results = await Promise.allSettled(
      this.relays.map(async (relay) => ({ url: relay.baseUrl, ...(await relay.health()) })),
    );
    return results.map((result, index) =>
      result.status === 'fulfilled'
        ? result.value
        : { url: this.relays[index].baseUrl, status: 'unreachable', error: String(result.reason) },
    );
  }
}

export { RelayHTTPError };
