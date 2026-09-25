/** Envelope padding.
 *
 * Plaintext envelopes are padded to a multiple of {@link BUCKET} bytes so that
 * ciphertext length does not reveal plaintext length. The padding is a random
 * alphanumeric string in the `pad` field; unpadding simply drops it. */

import { canonicalJsonBytes } from './encoding';
import { systemRng, type Rng } from './random';

export const BUCKET = 256;
export const DEFAULT_MAX = 2048;
export const MAX_ATTACHMENT_ENVELOPE = 65536;

const PAD_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export class PaddingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PaddingError';
  }
}

export function paddedSize(
  baseLength: number,
  bucket: number = BUCKET,
  maxSize?: number | null,
): number {
  let target = Math.max(bucket, (Math.floor(baseLength / bucket) + 1) * bucket);
  if (maxSize != null && target > maxSize) target = maxSize;
  return target;
}

/** Serialise `envelope` to canonical JSON padded to a size bucket. */
export function padEnvelope(
  envelope: Record<string, unknown>,
  maxSize?: number | null,
  rng: Rng = systemRng,
  bucket: number = BUCKET,
): Uint8Array {
  const copy: Record<string, unknown> = { ...envelope, pad: '' };
  const base = canonicalJsonBytes(copy);
  if (maxSize != null && base.length > maxSize) {
    throw new PaddingError(
      `envelope body is ${base.length} bytes, exceeds limit ${maxSize}`,
    );
  }
  const target = paddedSize(base.length, bucket, maxSize ?? null);
  const padLength = target - base.length;
  if (padLength < 0) throw new PaddingError('envelope too large to pad');
  let pad = '';
  for (let i = 0; i < padLength; i++) {
    pad += PAD_ALPHABET[Math.floor(rng() * PAD_ALPHABET.length) % PAD_ALPHABET.length];
  }
  copy.pad = pad;
  const data = canonicalJsonBytes(copy);
  if (data.length !== target) {
    throw new PaddingError(`padding produced ${data.length} bytes, wanted ${target}`);
  }
  return data;
}

export function unpadEnvelope(data: Uint8Array | string): Record<string, unknown> {
  const text = typeof data === 'string' ? data : new TextDecoder('utf-8', { fatal: true }).decode(data);
  const obj = JSON.parse(text);
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new PaddingError('envelope is not an object');
  }
  delete obj.pad;
  return obj as Record<string, unknown>;
}
