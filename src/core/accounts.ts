/** Account metadata and passphrase key derivation.
 *
 * Only non-secret metadata (identity id, label, KDF salt/iterations) lives in
 * localStorage. Private keys and all message state live encrypted in
 * IndexedDB under a key derived from the passphrase. */

import { b64d, b64e } from '../crypto/encoding';
import { randomBytes } from '../crypto/random';
import { utf8Encode } from '../crypto/bytes';

export const STORE_ITERATIONS = 600_000;
const ACCOUNTS_KEY = 'noknowledge.accounts';

export interface AccountMeta {
  id: string;
  label: string | null;
  salt: string;
  iterations: number;
  createdAt: number;
}

export function listAccounts(): AccountMeta[] {
  try {
    const raw = localStorage.getItem(ACCOUNTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeAccounts(accounts: AccountMeta[]): void {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts));
}

export function saveAccount(meta: AccountMeta): void {
  const accounts = listAccounts().filter((account) => account.id !== meta.id);
  accounts.push(meta);
  writeAccounts(accounts);
}

export function removeAccount(id: string): void {
  writeAccounts(listAccounts().filter((account) => account.id !== id));
}

export function newAccountSalt(): { salt: Uint8Array; saltB64: string } {
  const salt = randomBytes(16);
  return { salt, saltB64: b64e(salt) };
}

/** PBKDF2-SHA256 via WebCrypto: native speed, same parameters as the desktop store. */
export async function deriveStoreKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto is unavailable');
  const base = await subtle.importKey('raw', utf8Encode(passphrase) as unknown as BufferSource, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as unknown as BufferSource, iterations, hash: 'SHA-256' },
    base,
    256,
  );
  return new Uint8Array(bits);
}

export function saltFromMeta(meta: AccountMeta): Uint8Array {
  return b64d(meta.salt);
}
