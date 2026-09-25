/** Chunked attachment encryption.
 *
 * A file is encrypted with a fresh key and split into independently nonced
 * chunks. Chunk ids come from the relay after upload. The manifest — key,
 * nonces, hashes, filename — travels inside the ratcheted message, so the relay
 * never sees it. */

import { sha256 } from '@noble/hashes/sha2';
import { decrypt, encrypt } from '../crypto/aead';
import { toHex } from '../crypto/bytes';
import { b64d, b64e } from '../crypto/encoding';
import { randomBytes } from '../crypto/random';

// Smaller than the Python client's 256 KiB on purpose: on a slow relay link a
// 256 KiB request can exceed any sane timeout, and many small chunks make
// progress visible. The manifest carries per-chunk nonces, so the chunk size is
// a sender-side choice and stays interoperable with the Python client.
export const CHUNK_SIZE = 64 * 1024;
export const KEY_SIZE = 32;
export const MAX_FILE_SIZE = 25 * 1024 * 1024;

export class AttachmentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AttachmentError';
  }
}

export interface EncryptedChunk {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export interface Attachment {
  key: Uint8Array;
  chunks: EncryptedChunk[];
  size: number;
  sha256: string;
}

export function encryptAttachment(data: Uint8Array): Attachment {
  if (data.length > MAX_FILE_SIZE) {
    throw new AttachmentError(`file is ${data.length} bytes; maximum is ${MAX_FILE_SIZE}`);
  }
  const key = randomBytes(KEY_SIZE);
  const chunks: EncryptedChunk[] = [];
  const limit = Math.max(data.length, 1);
  for (let offset = 0; offset < limit; offset += CHUNK_SIZE) {
    const piece = data.slice(offset, offset + CHUNK_SIZE);
    const [nonce, ciphertext] = encrypt(key, piece);
    chunks.push({ nonce, ciphertext });
  }
  return { key, chunks, size: data.length, sha256: toHex(sha256(data)) };
}

export function decryptAttachment(
  key: Uint8Array,
  nonces: Uint8Array[],
  ciphertexts: Uint8Array[],
  expectedSha256: string,
): Uint8Array {
  if (nonces.length !== ciphertexts.length) {
    throw new AttachmentError('chunk count mismatch');
  }
  const parts = ciphertexts.map((ciphertext, index) => decrypt(key, nonces[index], ciphertext));
  const total = parts.reduce((n, part) => n + part.length, 0);
  const data = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    data.set(part, offset);
    offset += part.length;
  }
  if (toHex(sha256(data)) !== expectedSha256) {
    throw new AttachmentError('attachment hash mismatch');
  }
  return data;
}

export function manifestDict(
  attachment: Attachment,
  chunkIds: string[],
): Record<string, unknown> {
  if (chunkIds.length !== attachment.chunks.length) {
    throw new AttachmentError('chunk id count mismatch');
  }
  return {
    key: b64e(attachment.key),
    size: attachment.size,
    sha256: attachment.sha256,
    chunks: attachment.chunks.map((chunk, index) => ({
      id: chunkIds[index],
      nonce: b64e(chunk.nonce),
    })),
  };
}

export interface DecodedManifest {
  key: Uint8Array;
  chunkIds: string[];
  nonces: Uint8Array[];
  sha256: string;
}

export function decodeManifest(manifest: any): DecodedManifest {
  let key: Uint8Array;
  let size: number;
  let sha: string;
  let chunkIds: string[];
  let nonces: Uint8Array[];
  try {
    key = b64d(String(manifest.key));
    size = Number(manifest.size);
    sha = String(manifest.sha256);
    chunkIds = (manifest.chunks ?? []).map((c: any) => String(c.id));
    nonces = (manifest.chunks ?? []).map((c: any) => b64d(String(c.nonce)));
  } catch {
    throw new AttachmentError('malformed attachment manifest');
  }
  if (key.length !== KEY_SIZE) throw new AttachmentError('bad attachment key');
  if (size > MAX_FILE_SIZE) throw new AttachmentError('attachment exceeds maximum size');
  return { key, chunkIds, nonces, sha256: sha };
}
