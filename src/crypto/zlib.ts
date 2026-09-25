/** zlib (RFC 1950) compress/decompress, byte-compatible with Python's `zlib`.
 *
 * `fflate.deflateSync` emits raw DEFLATE; `zlibSync` adds the zlib header and
 * Adler-32 trailer that Python's `zlib.compress` produces, so contact cards are
 * interchangeable between the web client and the desktop client. */

import { unzlibSync, zlibSync } from 'fflate';

export function zlibCompress(data: Uint8Array, level = 9): Uint8Array {
  return zlibSync(data, { level: level as 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 });
}

export function zlibDecompress(data: Uint8Array): Uint8Array {
  return unzlibSync(data);
}
