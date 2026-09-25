/** HTTP transport with retries and a timeout.
 *
 * The browser owns the network stack here: there is no proxy/`fail_closed`
 * option because a page cannot open raw sockets or honour a SOCKS5 setting.
 * Use a browser-level proxy (or Tor Browser) when that is the requirement. */

import { TransportError } from './errors';

export interface TransportOptions {
  timeoutMs?: number;
  retries?: number;
  backoffMs?: number;
}

export interface RequestOptions {
  headers?: Record<string, string>;
  body?: Uint8Array | string | null;
  json?: unknown;
  query?: Record<string, string | number>;
  signal?: AbortSignal;
  /** Override the transport timeout (e.g. large attachments on a slow link). */
  timeoutMs?: number;
  /** Override the retry count; blob transfers use a single attempt. */
  retries?: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class Transport {
  readonly timeoutMs: number;
  readonly retries: number;
  readonly backoffMs: number;

  constructor(options: TransportOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.retries = Math.max(1, options.retries ?? 3);
    this.backoffMs = options.backoffMs ?? 500;
  }

  async request(method: string, url: string, options: RequestOptions = {}): Promise<Response> {
    const target = new URL(url);
    for (const [key, value] of Object.entries(options.query ?? {})) {
      target.searchParams.set(key, String(value));
    }
    const headers: Record<string, string> = { ...(options.headers ?? {}) };
    let body: BodyInit | undefined;
    if (options.json !== undefined) {
      headers['Content-Type'] = headers['Content-Type'] ?? 'application/json';
      body = JSON.stringify(options.json);
    } else if (options.body != null) {
      body = options.body as BodyInit;
    }

    const timeoutMs = options.timeoutMs ?? this.timeoutMs;
    const attempts = Math.max(1, options.retries ?? this.retries);
    let lastError: unknown = null;
    for (let attempt = 0; attempt < attempts; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const onAbort = () => controller.abort();
      options.signal?.addEventListener('abort', onAbort, { once: true });
      try {
        return await fetch(target.toString(), {
          method,
          headers,
          body,
          signal: controller.signal,
          cache: 'no-store',
        });
      } catch (error) {
        lastError = error;
        if (options.signal?.aborted) break;
        if (attempt < attempts - 1) await sleep(this.backoffMs * 2 ** attempt);
      } finally {
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', onAbort);
      }
    }
    throw new TransportError(`${method} ${url} failed: ${String(lastError)}`);
  }
}
