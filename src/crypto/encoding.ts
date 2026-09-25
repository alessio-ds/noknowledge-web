/** Canonical encoding helpers.
 *
 * Every value that is hashed, signed or authenticated goes through
 * {@link canonicalJson} so that this client and the Python reference agree
 * byte-for-byte. The output deliberately reproduces `json.dumps(obj,
 * sort_keys=True, separators=(",", ":"), ensure_ascii=False)` from Python:
 * code-point key ordering, no insignificant whitespace, control characters
 * escaped, non-ASCII left as UTF-8. */

import { utf8Encode } from './bytes';
import { zlibCompress, zlibDecompress } from './zlib';

export const CARD_PREFIX = 'nk://1/';

const B64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_LOOKUP = (() => {
  const table = new Int16Array(256).fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i++) {
    table[B64_ALPHABET.charCodeAt(i)] = i;
  }
  // Tolerate the standard alphabet too, like Python's urlsafe decoder does not
  // reject on input that only differs by these two characters.
  table['+'.charCodeAt(0)] = 62;
  table['/'.charCodeAt(0)] = 63;
  return table;
})();

/** base64url without padding. */
export function b64e(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i += 3) {
    const b0 = data[i];
    const b1 = i + 1 < data.length ? data[i + 1] : 0;
    const b2 = i + 2 < data.length ? data[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += B64_ALPHABET[(n >>> 18) & 63];
    out += B64_ALPHABET[(n >>> 12) & 63];
    if (i + 1 < data.length) out += B64_ALPHABET[(n >>> 6) & 63];
    if (i + 2 < data.length) out += B64_ALPHABET[n & 63];
  }
  return out;
}

/** Decode base64url that may or may not carry padding. */
export function b64d(text: string): Uint8Array {
  const clean = text.trim().replace(/=+$/, '');
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of clean) {
    const value = B64_LOOKUP[ch.charCodeAt(0)];
    if (value < 0) throw new Error(`b64d: invalid base64 character ${JSON.stringify(ch)}`);
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
    acc &= (1 << bits) - 1;
  }
  return Uint8Array.from(out);
}

const B32_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const B32_LOOKUP: Record<string, number> = {};
for (let i = 0; i < B32_ALPHABET.length; i++) B32_LOOKUP[B32_ALPHABET[i]] = i;
const B32_CONFUSABLES: Record<string, string> = { I: '1', L: '1', O: '0', U: 'V' };

/** Crockford base32 without padding (mirrors the Python bit accumulator). */
export function b32e(data: Uint8Array): string {
  let acc = 0;
  let bits = 0;
  let out = '';
  for (const byte of data) {
    acc = ((acc << 8) | byte) >>> 0;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32_ALPHABET[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits) out += B32_ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

/** Decode Crockford base32, tolerating confusable characters. */
export function b32d(text: string): Uint8Array {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (let ch of text.trim().replace(/-/g, '').toUpperCase()) {
    ch = B32_CONFUSABLES[ch] ?? ch;
    const digit = B32_LOOKUP[ch];
    if (digit === undefined) throw new Error(`invalid base32 character: ${JSON.stringify(ch)}`);
    acc = (acc << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
    acc &= (1 << bits) - 1;
  }
  return Uint8Array.from(out);
}

function quote(text: string): string {
  let out = '"';
  for (const ch of text) {
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else {
      const code = ch.codePointAt(0)!;
      out += code < 0x20 ? '\\u' + code.toString(16).padStart(4, '0') : ch;
    }
  }
  return out + '"';
}

/** Python compares strings by code point, not UTF-16 code unit. */
function compareCodePoints(a: string, b: string): number {
  const ai = a[Symbol.iterator]();
  const bi = b[Symbol.iterator]();
  for (;;) {
    const x = ai.next();
    const y = bi.next();
    if (x.done && y.done) return 0;
    if (x.done) return -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

function stringify(value: unknown): string {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    const n = value as number;
    if (!Number.isFinite(n)) throw new Error('canonicalJson: non-finite number');
    if (!Number.isInteger(n)) throw new Error('canonicalJson: non-integer number');
    return String(n);
  }
  if (type === 'string') return quote(value as string);
  if (Array.isArray(value)) return '[' + value.map(stringify).join(',') + ']';
  if (type === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(compareCodePoints);
    const parts: string[] = [];
    for (const key of keys) {
      const entry = obj[key];
      if (entry === undefined) throw new Error(`canonicalJson: undefined value for ${key}`);
      parts.push(quote(key) + ':' + stringify(entry));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonicalJson: unsupported type ${type}`);
}

/** Deterministic JSON: sorted keys, no whitespace, UTF-8. */
export function canonicalJson(value: unknown): string {
  return stringify(value);
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
  return utf8Encode(canonicalJson(value));
}

/** Serialise a contact-card payload to its compact `nk://1/...` form. */
export function cardEncode(payload: unknown): string {
  return CARD_PREFIX + b64e(zlibCompress(canonicalJsonBytes(payload)));
}

/** Parse a `nk://1/...` contact card string. */
export function cardDecode(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed.toLowerCase().startsWith(CARD_PREFIX)) {
    throw new Error('not a noknowledge contact card');
  }
  const raw = b64d(trimmed.slice(CARD_PREFIX.length));
  let json: string;
  try {
    json = new TextDecoder('utf-8', { fatal: true }).decode(zlibDecompress(raw));
  } catch {
    throw new Error('corrupt contact card');
  }
  return JSON.parse(json);
}
