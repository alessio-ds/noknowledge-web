/** Randomness helpers. Uses the WebCrypto CSPRNG, available in every modern
 * browser and in Node >= 19, so the same code runs in tests and in the page. */

export type Rng = () => number;

function assertCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error('no CSPRNG available (globalThis.crypto.getRandomValues)');
  }
  return c;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  const crypto = assertCrypto();
  // getRandomValues rejects any single request larger than 65536 bytes, so fill
  // in slices; large callers (tests, future bulk key material) then just work.
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)));
  }
  return out;
}

/** Cryptographically secure float in [0, 1), for padding selection. */
export const systemRng: Rng = () => {
  const buf = new Uint32Array(1);
  assertCrypto().getRandomValues(buf);
  return buf[0] / 0x1_0000_0000;
};

/** Deterministic RNG for reproducible test vectors (NOT for production). */
export function seededRng(seed: number): Rng {
  let state = seed >>> 0 || 1;
  return () => {
    // xorshift32
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x1_0000_0000;
  };
}
