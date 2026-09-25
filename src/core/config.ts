/** Relay configuration.
 *
 * The relay set is part of a contact card, so it is user-visible and editable.
 * A build can pin a default with `VITE_DEFAULT_RELAYS`; otherwise we assume the
 * page is served by (or proxied to) a relay on the same origin, which is the
 * simplest self-hosting arrangement and avoids cross-origin preflights. */

const RELAYS_KEY = 'noknowledge.relays';

export function defaultRelays(): string[] {
  const fromEnv = (import.meta as any)?.env?.VITE_DEFAULT_RELAYS as string | undefined;
  if (fromEnv) {
    const urls = fromEnv.split(',').map((url) => url.trim()).filter(Boolean);
    if (urls.length > 0) return urls;
  }
  if (typeof location !== 'undefined' && /^https?:$/.test(location.protocol)) {
    return [location.origin];
  }
  return ['http://127.0.0.1:8000'];
}

export function getRelays(): string[] {
  try {
    const raw = localStorage.getItem(RELAYS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed.map(String);
    }
  } catch {
    /* fall through to defaults */
  }
  return defaultRelays();
}

export function setRelays(relays: string[]): void {
  const cleaned = relays.map((relay) => relay.trim()).filter(Boolean);
  localStorage.setItem(RELAYS_KEY, JSON.stringify(cleaned));
}
