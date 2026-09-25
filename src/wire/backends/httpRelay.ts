/** HTTP backend for a single relay. */

import { b64d } from '../../crypto/encoding';
import {
  AllRelaysFailed,
  RelayHTTPError,
  RelayNotFound,
  RelayQuotaExceeded,
  RelayUnauthorized,
} from '../errors';
import { Transport, type RequestOptions } from '../transport';
import { MailboxCapability } from './base';

export class HttpRelayBackend {
  readonly baseUrl: string;
  readonly transport: Transport;

  constructor(baseUrl: string, transport?: Transport) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.transport = transport ?? new Transport();
  }

  private url(path: string): string {
    return `${this.baseUrl}/api${path}`;
  }

  private static async raiseForStatus(response: Response): Promise<void> {
    const status = response.status;
    if (status < 400) return;
    let detail = '';
    try {
      detail = (await response.json())?.detail ?? '';
    } catch {
      detail = (await response.text().catch(() => '')).slice(0, 200);
    }
    if (status === 404) throw new RelayNotFound(status, detail);
    if (status === 401 || status === 403) throw new RelayUnauthorized(status, detail);
    if (status === 429) throw new RelayQuotaExceeded(status, detail);
    throw new RelayHTTPError(status, detail);
  }

  private async call(method: string, path: string, options?: RequestOptions): Promise<Response> {
    const response = await this.transport.request(method, this.url(path), options);
    await HttpRelayBackend.raiseForStatus(response);
    return response;
  }

  // -- mailboxes --------------------------------------------------------

  async createMailbox(capability: MailboxCapability): Promise<void> {
    await this.call('POST', '/mailbox', { json: capability.toJson() });
  }

  async put(capability: MailboxCapability, envelope: Uint8Array): Promise<number> {
    const response = await this.call('POST', `/mailbox/${capability.mailboxId}/messages`, {
      headers: { 'X-NK-Write': capability.writeToken },
      body: envelope,
    });
    return Number((await response.json()).seq);
  }

  async fetch(
    capability: MailboxCapability,
    afterSeq = 0,
    wait = 0,
  ): Promise<Array<[number, Uint8Array]>> {
    if (!capability.readToken) throw new RelayUnauthorized(401, 'no read capability for this mailbox');
    const response = await this.call('GET', `/mailbox/${capability.mailboxId}`, {
      headers: { 'X-NK-Read': capability.readToken },
      query: { after_seq: afterSeq, wait },
    });
    const payload = await response.json();
    return (payload.messages ?? []).map(
      (m: any): [number, Uint8Array] => [Number(m.seq), b64d(String(m.blob))],
    );
  }

  async ack(capability: MailboxCapability, uptoSeq: number): Promise<number> {
    if (!capability.readToken) throw new RelayUnauthorized(401, 'no read capability for this mailbox');
    const response = await this.call('POST', `/mailbox/${capability.mailboxId}/ack`, {
      headers: { 'X-NK-Read': capability.readToken },
      json: { upto_seq: Math.trunc(uptoSeq) },
    });
    return Number((await response.json()).deleted ?? 0);
  }

  async deleteMailbox(capability: MailboxCapability): Promise<void> {
    if (!capability.readToken) throw new RelayUnauthorized(401, 'no read capability for this mailbox');
    await this.call('DELETE', `/mailbox/${capability.mailboxId}`, {
      headers: { 'X-NK-Read': capability.readToken },
    });
  }

  // -- prekeys ----------------------------------------------------------

  async publishBundle(bundleId: string, bundle: Uint8Array): Promise<string> {
    const response = await this.call('POST', '/prekeys', {
      body: bundle,
      headers: { 'Content-Type': 'application/json' },
    });
    return String((await response.json()).bundle_id);
  }

  async fetchBundle(bundleId: string): Promise<any> {
    const response = await this.call('GET', `/prekeys/${bundleId}`);
    return response.json();
  }

  // -- blobs ------------------------------------------------------------

  async putBlob(capability: MailboxCapability, chunkId: string, chunk: Uint8Array): Promise<string> {
    const response = await this.call('POST', '/blob', {
      headers: {
        'X-NK-Write': capability.writeToken,
        'X-NK-Mailbox': capability.mailboxId,
        'X-NK-Chunk': chunkId,
      },
      body: chunk,
      // Chunks are large and relays can be slow; a 30s timeout would turn a
      // slow link into a hard failure. One attempt, generous deadline.
      timeoutMs: 180_000,
      retries: 1,
    });
    return String((await response.json()).chunk_id);
  }

  async getBlob(capability: MailboxCapability, chunkId: string): Promise<Uint8Array> {
    if (!capability.readToken) throw new RelayUnauthorized(401, 'no read capability for this mailbox');
    const response = await this.call('GET', `/blob/${chunkId}`, {
      headers: {
        'X-NK-Read': capability.readToken,
        'X-NK-Mailbox': capability.mailboxId,
      },
      timeoutMs: 180_000,
      retries: 1,
    });
    return new Uint8Array(await response.arrayBuffer());
  }

  async health(): Promise<any> {
    const response = await this.call('GET', '/health');
    return response.json();
  }
}

export { AllRelaysFailed };
