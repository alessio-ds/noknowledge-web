/** Create, unlock and delete accounts.
 *
 * An "account" is an identity plus the passphrase-derived key that encrypts all
 * of its local state. The passphrase is never stored; it unlocks the IndexedDB
 * records and the sealed private keys inside them.
 *
 * Re-creating or re-importing an identity that already exists on this device
 * reuses the stored KDF salt, so the same password derives the same key and the
 * existing (still encrypted) history and ratchet state stay readable. */

import { b64d, b64e } from '../crypto/encoding';
import { Identity } from '../crypto/identity';
import { Client } from './client';
import {
  type AccountMeta,
  STORE_ITERATIONS,
  deriveStoreKey,
  listAccounts,
  newAccountSalt,
  removeAccount,
  saltFromMeta,
  saveAccount,
} from './accounts';
import { LocalStore } from './store';

export interface UnlockedAccount {
  meta: AccountMeta;
  identity: Identity;
  store: LocalStore;
  client: Client;
}

export interface CreatedAccount extends UnlockedAccount {
  mnemonic: string;
}

function existingMeta(identityId: string): AccountMeta | undefined {
  return listAccounts().find((account) => account.id === identityId);
}

function sealIdentity(store: LocalStore, identity: Identity, label: string | null): Promise<void> {
  return store.setState(identity.identityId, 'identity', {
    edSeed: b64e(identity.edPrivateBytes),
    xSeed: b64e(identity.xPrivateBytes),
    label,
  });
}

/**
 * Open (or create) the encrypted store for an identity and return the account
 * metadata to persist. If the identity already exists locally, its salt is
 * reused and the password must match, otherwise the old records are unreadable.
 */
async function openAccountStore(
  identity: Identity,
  label: string | null,
  password: string,
): Promise<{ store: LocalStore; meta: AccountMeta }> {
  const existing = existingMeta(identity.identityId);
  const salt = existing ? saltFromMeta(existing) : newAccountSalt().salt;
  const iterations = existing?.iterations ?? STORE_ITERATIONS;
  const key = await deriveStoreKey(password, salt, iterations);
  const store = await LocalStore.open(key, identity.identityId);

  if (existing) {
    let readable = true;
    try {
      await store.getState(identity.identityId, 'identity');
    } catch {
      readable = false;
    }
    if (!readable) {
      throw new Error(
        'An account with this identity already exists on this device. Unlock it with its original password first.',
      );
    }
  }

  const meta: AccountMeta = {
    id: identity.identityId,
    label: label ?? existing?.label ?? null,
    salt: b64e(salt),
    iterations,
    createdAt: existing?.createdAt ?? Date.now(),
  };
  return { store, meta };
}

async function buildClient(
  identity: Identity,
  store: LocalStore,
  label: string | null,
  relays: string[],
): Promise<Client> {
  const client = new Client(identity, store, relays, label);
  await client.provision();
  return client;
}

export async function createAccount(options: {
  name: string;
  password: string;
  relays: string[];
  mnemonic?: string;
}): Promise<CreatedAccount> {
  const { name, password, relays } = options;
  let mnemonic: string;
  let identity: Identity;
  if (options.mnemonic) {
    identity = Identity.fromMnemonic(options.mnemonic, '', name);
    mnemonic = options.mnemonic;
  } else {
    const generated = Identity.generate(name);
    identity = generated[0];
    mnemonic = generated[1];
  }

  const { store, meta } = await openAccountStore(identity, name, password);
  await sealIdentity(store, identity, name);
  saveAccount(meta);

  const client = await buildClient(identity, store, name, relays);
  return { meta, identity, store, client, mnemonic };
}

export async function importVaultAccount(options: {
  name: string;
  password: string;
  vaultJson: string;
  vaultPassphrase?: string;
  relays: string[];
}): Promise<UnlockedAccount> {
  const imported = Identity.fromVault(options.vaultJson, options.vaultPassphrase);
  const identity = new Identity(imported.edPrivateBytes, imported.xPrivateBytes, options.name);

  const { store, meta } = await openAccountStore(identity, options.name, options.password);
  await sealIdentity(store, identity, options.name);
  saveAccount(meta);

  const client = await buildClient(identity, store, options.name, options.relays);
  return { meta, identity, store, client };
}

export async function unlockAccount(
  meta: AccountMeta,
  password: string,
  relays: string[],
): Promise<UnlockedAccount> {
  const key = await deriveStoreKey(password, saltFromMeta(meta), meta.iterations);
  const store = await LocalStore.open(key, meta.id);

  let record: any;
  try {
    record = await store.getState(meta.id, 'identity');
  } catch {
    throw new Error('Wrong passphrase (local data could not be decrypted)');
  }
  if (!record?.edSeed || !record?.xSeed) {
    throw new Error('No local identity found for this account');
  }

  const identity = Identity.fromPrivateBytes(
    b64d(record.edSeed),
    b64d(record.xSeed),
    record.label ?? meta.label,
  );
  if (identity.identityId !== meta.id) {
    throw new Error('Local identity does not match the account');
  }

  const client = await buildClient(identity, store, record.label ?? meta.label, relays);
  return { meta, identity, store, client };
}

export async function deleteAccount(meta: AccountMeta, password: string): Promise<void> {
  try {
    const key = await deriveStoreKey(password, saltFromMeta(meta), meta.iterations);
    const store = await LocalStore.open(key, meta.id);
    await store.destroy();
  } catch {
    /* even if decrypting fails, drop the metadata */
  }
  removeAccount(meta.id);
}

export { listAccounts };
export type { AccountMeta };
