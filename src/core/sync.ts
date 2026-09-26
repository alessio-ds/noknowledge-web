/** Device sync: approvals, live mirroring and history back-fill.
 *
 * Three things travel between the devices of one account, all over the sealed
 * device channel in `deviceChannel.ts`:
 *
 * - **mirrors** — as you send a message from one device, a copy of it (and of
 *   your read/delivered state) goes to your other devices, so they show the same
 *   conversation. This is the XMPP "carbons" behaviour.
 * - **back-fill** — a device that asked, and was approved by a human on another
 *   device, receives the past inside a range it chose.
 * - **approvals** — the record of that human decision, which is what stops a
 *   stolen seed from pulling the past out of your devices.
 *
 * The rule that keeps this safe is simple: **a device sends data only to devices
 * its human approved**. Receiving is not a security boundary — every device of
 * the account is entitled to the account's traffic, and a forged record fails its
 * signature or its AEAD.
 *
 * Byte-compatible with the Python reference (`core/sync.py`).
 */

import { utf8Decode } from '../crypto/bytes';
import { agreementPublic, generateDeviceKeys, signingPublic } from '../crypto/deviceKeys';
import { b64d, b64e, canonicalJsonBytes } from '../crypto/encoding';
import type { Client } from './client';
import * as channel from './deviceChannel';
import { SyncError } from './deviceChannel';
import {
  DeviceEntry,
  DeviceKeys,
  deviceKeysId,
  openSignedPayload,
  sealPayload,
} from './devices';
import * as history from './history';
import type { LocalStore, Message } from './store';

const DEVICE_KEYS_STATE = 'device_keys';
const APPROVALS_STATE = 'sync_approvals';
const REQUESTED_STATE = 'sync_requested';
const INCOMING_STATE = 'sync_incoming';
const REQUESTS_STATE = 'sync_requests';
const SEEN_STATE = 'sync_seen';

const MAX_SEEN_TRANSFERS = 200;

export interface SyncRequest {
  device_id: string;
  name: string;
  since: number;
  ts: number;
  transfer?: string;
}

export interface SyncStatus {
  device_id: string;
  name: string;
  approved: boolean;
  received: number;
  expected: number;
  done: boolean;
  asked: boolean;
  has_keys: boolean;
}

// -- device keys -----------------------------------------------------------

export async function ensureDeviceKeys(
  client: Client,
): Promise<{ sdev: Uint8Array; sagree: Uint8Array }> {
  const store: LocalStore = client.store;
  const stored = await store.getState(client.identityId, DEVICE_KEYS_STATE);
  if (stored?.sdev && stored?.sagree) {
    return { sdev: b64d(stored.sdev), sagree: b64d(stored.sagree) };
  }
  const [sdev, sagree] = generateDeviceKeys();
  await store.setState(client.identityId, DEVICE_KEYS_STATE, {
    sdev: b64e(sdev),
    sagree: b64e(sagree),
  });
  return { sdev, sagree };
}

export async function deviceKeysRecord(client: Client): Promise<DeviceKeys> {
  const keys = await ensureDeviceKeys(client);
  const deviceId = await client.thisDeviceId();
  return DeviceKeys.create(
    client.identity,
    deviceId,
    signingPublic(keys.sdev),
    agreementPublic(keys.sagree),
  );
}

/** Publish this device's keys so siblings can seal records to it. */
export async function publishDeviceKeys(client: Client): Promise<void> {
  const record = await deviceKeysRecord(client);
  const sealed = sealPayload(record.isign, record.idh, record.address(), record.toBytes());
  try {
    await client.backend.publishBundle(record.address(), sealed);
  } catch {
    // A relay refusing the record must not break provisioning; sync simply stays
    // unavailable until it is published.
  }
}

/** Another device's key record, cached in memory for a day. */
export async function fetchDeviceKeys(
  client: Client,
  device: DeviceEntry,
): Promise<DeviceKeys | null> {
  const cache = client.siblingKeyCache;
  const cached = cache.get(device.deviceId);
  const now = Date.now();
  if (cached && now - cached.ts < 24 * 3600 * 1000) return cached.record;
  const address = deviceKeysId(
    client.identity.edPublicBytes,
    client.identity.xPublicBytes,
    device.deviceId,
  );
  try {
    const payload = await client.backendFor(device.relays).fetchBundle(address);
    const opened = openSignedPayload(
      payload as any,
      client.identity.edPublicBytes,
      client.identity.xPublicBytes,
    );
    const record = DeviceKeys.fromBytes(opened);
    if (record.deviceId !== device.deviceId) return null;
    if (
      !record.belongsTo(
        client.identityId,
        client.identity.edPublicBytes,
        client.identity.xPublicBytes,
      )
    ) {
      return null;
    }
    cache.set(device.deviceId, { record, ts: now });
    return record;
  } catch {
    return cached?.record ?? null;
  }
}

export async function siblingDevices(
  client: Client,
  options: { includeSelf?: boolean; fresh?: boolean } = {},
): Promise<DeviceEntry[]> {
  const listing = await client.ownDeviceList(options.fresh ? 0 : 300);
  const devices = listing?.devices ?? [];
  const mine = client.currentDeviceId;
  return devices.filter(
    (device) => options.includeSelf || device.deviceId !== mine,
  );
}

async function locateDevice(client: Client, deviceId: string): Promise<DeviceEntry | null> {
  const find = async (fresh: boolean) =>
    (await siblingDevices(client, { includeSelf: true, fresh })).find(
      (device) => device.deviceId === deviceId,
    ) ?? null;
  return (await find(false)) ?? (await find(true));
}

// -- approvals -------------------------------------------------------------

export async function approvals(client: Client): Promise<Record<string, any>> {
  return (await client.store.getState(client.identityId, APPROVALS_STATE)) ?? {};
}

export async function approvedDevices(client: Client): Promise<string[]> {
  return Object.keys(await approvals(client)).sort();
}

export async function markApproved(
  client: Client,
  deviceId: string,
  transfer: string,
  sinceMs: number | null,
  untilMs: number | null,
): Promise<void> {
  const value = await approvals(client);
  value[deviceId] = {
    transfer,
    since: Math.trunc(sinceMs ?? 0),
    until: Math.trunc(untilMs ?? Date.now()),
    ts: Date.now(),
  };
  await client.store.setState(client.identityId, APPROVALS_STATE, value);
}

export async function revokeApproval(client: Client, deviceId: string): Promise<void> {
  const value = await approvals(client);
  delete value[deviceId];
  await client.store.setState(client.identityId, APPROVALS_STATE, value);
}

async function markSeen(client: Client, transfer: string): Promise<boolean> {
  const seen: string[] = (await client.store.getState(client.identityId, SEEN_STATE)) ?? [];
  if (seen.includes(transfer)) return false;
  seen.push(transfer);
  await client.store.setState(
    client.identityId,
    SEEN_STATE,
    seen.slice(-MAX_SEEN_TRANSFERS),
  );
  return true;
}

async function recordRequest(
  client: Client,
  deviceId: string,
  transfer: string,
  sinceMs: number,
): Promise<void> {
  const pending = (await client.store.getState(client.identityId, REQUESTS_STATE)) ?? {};
  pending[deviceId] = { transfer, since: Math.trunc(sinceMs || 0), ts: Date.now() };
  await client.store.setState(client.identityId, REQUESTS_STATE, pending);
}

/** Devices asking for history, newest first, with the name we know them by. */
export async function pendingRequests(client: Client): Promise<SyncRequest[]> {
  const pending = (await client.store.getState(client.identityId, REQUESTS_STATE)) ?? {};
  const approved = await approvals(client);
  const known = new Map(
    (await siblingDevices(client, { includeSelf: true })).map((device) => [
      device.deviceId,
      device,
    ]),
  );
  return Object.entries(pending)
    .filter(([deviceId]) => !(deviceId in approved))
    .map(([deviceId, request]: [string, any]) => ({
      device_id: deviceId,
      name: known.get(deviceId)?.name ?? '',
      since: Number(request?.since ?? 0),
      ts: Number(request?.ts ?? 0),
      transfer: request?.transfer,
    }))
    .sort((a, b) => b.ts - a.ts);
}

async function requestedFrom(client: Client): Promise<Record<string, any>> {
  return (await client.store.getState(client.identityId, REQUESTED_STATE)) ?? {};
}

// -- writing records -------------------------------------------------------

async function writeRecord(
  client: Client,
  device: DeviceEntry,
  kind: number,
  plaintext: Uint8Array,
  transfer: string,
  seq = 0,
  extra?: Record<string, unknown>,
): Promise<Uint8Array> {
  const keys = await ensureDeviceKeys(client);
  const record = await fetchDeviceKeys(client, device);
  if (!record) throw new SyncError(`device ${device.deviceId} has not published sync keys`);
  const blob = channel.sealRecord(kind, plaintext, {
    recipientSagree: record.sagree,
    senderDeviceId: client.currentDeviceId ?? '',
    senderSdevPrivate: keys.sdev,
    transferId: transfer,
    seq,
    extra,
  });
  await client.backendFor(device.relays).put(client.deviceCapability(device), blob);
  return blob;
}

/** Ask every sibling device for the past. Returns who was asked. */
export async function requestHistory(
  client: Client,
  sinceMs?: number | null,
  budget?: number,
): Promise<string[]> {
  const transfer = channel.newTransferId();
  const payload = canonicalJsonBytes({
    since: Math.trunc(sinceMs ?? 0),
    budget: Math.trunc(budget ?? history.DEFAULT_BUDGET_BYTES),
    device: client.currentDeviceId ?? '',
  });
  const asked: string[] = [];
  for (const device of await siblingDevices(client)) {
    try {
      await writeRecord(client, device, channel.REQUEST, payload, transfer);
    } catch {
      continue;
    }
    asked.push(device.deviceId);
  }
  if (asked.length > 0) {
    await client.store.setState(client.identityId, REQUESTED_STATE, {
      transfer,
      since: Math.trunc(sinceMs ?? 0),
      asked,
      ts: Date.now(),
    });
  }
  return asked;
}

/** Approve a device and send it the history it asked for.
 *
 * This is the human decision that a stolen seed cannot make for you. */
export async function approveDevice(
  client: Client,
  deviceId: string,
  sinceMs?: number | null,
  budget?: number,
  onProgress?: (done: number, total: number) => void,
): Promise<{ device_id: string; since: number; transfer: string; items: number; skipped: number }> {
  const device = await locateDevice(client, deviceId);
  if (!device) throw new SyncError(`unknown device: ${deviceId}`);
  const pending = (await client.store.getState(client.identityId, REQUESTS_STATE)) ?? {};
  const request = pending[deviceId] ?? {};
  const since = Math.trunc(sinceMs ?? request.since ?? 0);
  const limit = Math.trunc(budget ?? history.DEFAULT_BUDGET_BYTES);
  const transfer = channel.newTransferId();
  const until = Date.now();

  await writeRecord(
    client,
    device,
    channel.APPROVAL,
    canonicalJsonBytes({ device: deviceId, since, until, budget: limit }),
    transfer,
    0,
    { since, until },
  );
  await markApproved(client, deviceId, transfer, since, until);

  const counts = await sendHistory(client, device, {
    sinceMs: since,
    untilMs: until,
    budget: limit,
    transfer,
    onProgress,
  });

  delete pending[deviceId];
  await client.store.setState(client.identityId, REQUESTS_STATE, pending);
  return { device_id: deviceId, since, transfer, ...counts };
}

export async function denyDevice(client: Client, deviceId: string): Promise<void> {
  const pending = (await client.store.getState(client.identityId, REQUESTS_STATE)) ?? {};
  delete pending[deviceId];
  await client.store.setState(client.identityId, REQUESTS_STATE, pending);
}

/** Stream a range of history to one approved device. */
export async function sendHistory(
  client: Client,
  device: DeviceEntry,
  options: {
    sinceMs: number | null;
    untilMs: number;
    budget: number;
    transfer?: string;
    onProgress?: (done: number, total: number) => void;
  },
): Promise<{ items: number; skipped: number }> {
  const transfer = options.transfer ?? channel.newTransferId();
  const bundle = await history.buildBundle(client, {
    sinceMs: options.sinceMs,
    untilMs: options.untilMs,
    budgetBytes: options.budget,
  });
  const items: Array<[string, Record<string, unknown>]> = [
    ...bundle.contacts.map((item) => ['contact', item] as [string, Record<string, unknown>]),
    ...bundle.messages.map((item) => ['message', item] as [string, Record<string, unknown>]),
    ...bundle.chunks.map((item) => ['chunk', item] as [string, Record<string, unknown>]),
  ];

  await writeRecord(
    client,
    device,
    channel.OFFER,
    canonicalJsonBytes({
      count: items.length,
      skipped: bundle.skipped.length,
      since: Math.trunc(options.sinceMs ?? 0),
      until: Math.trunc(options.untilMs),
      budget: options.budget,
    }),
    transfer,
    0,
    { count: items.length },
  );

  const chain = new channel.HashChain(transfer);
  let seq = 0;
  for (const [kind, payload] of items) {
    seq += 1;
    const raw = canonicalJsonBytes({ kind, ...payload });
    await writeRecord(client, device, channel.ITEM, raw, transfer, seq);
    chain.add(raw, seq);
    options.onProgress?.(seq, items.length);
  }

  await writeRecord(
    client,
    device,
    channel.COMPLETE,
    canonicalJsonBytes({ count: items.length, chain: chain.hexdigest() }),
    transfer,
    0,
    { count: items.length, chain: chain.hexdigest() },
  );
  return { items: items.length, skipped: bundle.skipped.length };
}

// -- mirroring -------------------------------------------------------------

async function mirrorTargets(client: Client): Promise<DeviceEntry[]> {
  const approved = await approvals(client);
  return (await siblingDevices(client)).filter((device) => device.deviceId in approved);
}

/** Copy one of our sent messages to the devices we approved. */
export async function mirrorMessage(
  client: Client,
  contactId: string,
  message: Message,
): Promise<number> {
  const targets = await mirrorTargets(client);
  if (targets.length === 0) return 0;
  const contact = await client.store.getContact(client.identityId, contactId);
  if (!contact) return 0;
  const item = history.messageItem(message);
  (item as Record<string, unknown>).id = message.id;
  const raw = canonicalJsonBytes({
    kind: 'mirror',
    contact: history.contactItem(contact),
    message: item,
  });
  let sent = 0;
  for (const device of targets) {
    try {
      await writeRecord(client, device, channel.MIRROR, raw, channel.newTransferId());
    } catch {
      continue;
    }
    sent += 1;
  }
  return sent;
}

/** Copy a read/delivered state change to the approved devices. */
export async function mirrorState(
  client: Client,
  contactId: string | null,
  message: Message,
): Promise<number> {
  const targets = await mirrorTargets(client);
  if (targets.length === 0) return 0;
  const raw = canonicalJsonBytes({
    kind: 'state',
    state: {
      id: message.id,
      remote_id: message.remote_id,
      contact_id: contactId ?? message.contact_id,
      state: message.state,
    },
  });
  let sent = 0;
  for (const device of targets) {
    try {
      await writeRecord(client, device, channel.MIRROR, raw, channel.newTransferId());
    } catch {
      continue;
    }
    sent += 1;
  }
  return sent;
}

// -- receiving -------------------------------------------------------------

function loads(plaintext: Uint8Array): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(utf8Decode(plaintext));
  } catch {
    throw new SyncError('device record payload is malformed');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new SyncError('device record payload is not an object');
  }
  return value as Record<string, unknown>;
}

/** Dispatch one inbound device record. */
export async function handleRecord(client: Client, blob: Uint8Array): Promise<string | null> {
  const [initialKind, header] = channel.parseRecord(blob);
  const deviceId = String(header.from ?? '');
  const device = await locateDevice(client, deviceId);
  if (!device) throw new SyncError(`record from unknown device: ${deviceId}`);
  const record = await fetchDeviceKeys(client, device);
  if (!record) throw new SyncError(`no sync keys for device: ${deviceId}`);
  const keys = await ensureDeviceKeys(client);
  const [kind, opened, plaintext] = channel.openRecord(blob, {
    mySagreePrivate: keys.sagree,
    senderSdev: record.sdev,
    senderDeviceId: deviceId,
  });
  if (kind !== initialKind) throw new SyncError('device record changed kind in flight');
  const transfer = String(opened.transfer ?? '');

  if (kind === channel.REQUEST) {
    const request = loads(plaintext);
    await recordRequest(client, deviceId, transfer, Number(request.since ?? 0));
    return `sync request from ${deviceId}`;
  }

  if (kind === channel.APPROVAL) {
    // They vouched for us; we may send them our mirrors from now on.
    if (await markSeen(client, transfer)) {
      await markApproved(client, deviceId, transfer, Number(opened.since ?? 0), Number(opened.until ?? 0));
    }
    return `history approved by ${deviceId}`;
  }

  if (kind === channel.OFFER) {
    const offer = loads(plaintext);
    const state = (await client.store.getState(client.identityId, INCOMING_STATE)) ?? {};
    state[deviceId] = {
      transfer,
      received: 0,
      expected: Number(offer.count ?? 0),
      skipped: Number(offer.skipped ?? 0),
      chain: '',
      done: false,
    };
    await client.store.setState(client.identityId, INCOMING_STATE, state);
    return `${offer.count} item(s) offered by ${deviceId}`;
  }

  if (kind === channel.ITEM) {
    return applyItem(client, deviceId, transfer, plaintext, Number(opened.seq ?? 0));
  }

  if (kind === channel.COMPLETE) {
    const complete = loads(plaintext);
    const state = (await client.store.getState(client.identityId, INCOMING_STATE)) ?? {};
    const entry = state[deviceId] ?? {};
    const expected = Number(complete.count ?? 0);
    const received = Number(entry.received ?? 0);
    entry.done = true;
    entry.expected = expected;
    entry.complete =
      received >= expected && String(entry.chain ?? '') === String(complete.chain ?? '');
    state[deviceId] = entry;
    await client.store.setState(client.identityId, INCOMING_STATE, state);
    if (!entry.complete) {
      return `history from ${deviceId} is incomplete (${received}/${expected})`;
    }
    return `history from ${deviceId} complete (${received} item(s))`;
  }

  if (kind === channel.MIRROR) {
    return applyMirror(client, loads(plaintext));
  }

  return null;
}

async function applyItem(
  client: Client,
  deviceId: string,
  transfer: string,
  plaintext: Uint8Array,
  seq: number,
): Promise<string> {
  const item = loads(plaintext);
  const kind = String(item.kind ?? '');
  const counts = history.newCounts();
  const state = (await client.store.getState(client.identityId, INCOMING_STATE)) ?? {};
  const entry = state[deviceId] ?? { transfer, received: 0, expected: 0, chain: '', done: false };

  const payload: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(item)) {
    if (key !== 'kind') payload[key] = value;
  }

  if (kind === 'contact') {
    await history.mergeContacts(client, [payload], counts);
  } else if (kind === 'message') {
    const index = await client.syncMessageIndex();
    await history.mergeMessages(client, [payload], index, counts);
  } else if (kind === 'chunk') {
    await history.mergeChunks(client, [payload as { id: string; ct: string }], counts);
  } else {
    throw new SyncError(`unknown history item: ${kind}`);
  }

  // Extend the running digest so COMPLETE can tell a full transfer from a
  // truncated one.
  const chain = new channel.HashChain(transfer, String(entry.chain ?? ''));
  chain.add(plaintext, seq);
  entry.transfer = transfer;
  entry.received = Number(entry.received ?? 0) + 1;
  entry.expected = Number(entry.expected ?? 0);
  entry.chain = chain.hexdigest();
  entry.done = false;
  state[deviceId] = entry;
  await client.store.setState(client.identityId, INCOMING_STATE, state);
  return `${kind} from ${deviceId}`;
}

async function applyMirror(client: Client, item: Record<string, unknown>): Promise<string> {
  const kind = item.kind;
  if (kind === 'mirror') {
    const counts = history.newCounts();
    if (item.contact) {
      await history.mergeContacts(client, [item.contact as Record<string, unknown>], counts);
    }
    const index = await client.syncMessageIndex();
    await history.mergeMessages(client, [item.message as Record<string, unknown>], index, counts);
    return counts.messages > 0 ? 'message mirrored' : 'mirror ignored';
  }

  if (kind === 'state') {
    const change = (item.state ?? {}) as Record<string, unknown>;
    let target: Message | null = null;
    if (change.remote_id) {
      target = await client.store.findByRemoteId(client.identityId, String(change.remote_id));
    }
    if (!target && change.id) {
      target = await client.store.getMessage(String(change.id));
    }
    if (!target) return 'state update for an unknown message';
    const state = String(change.state ?? '');
    if (history.stateRank(state) > history.stateRank(target.state)) {
      await client.store.updateMessage(target.id, { state });
      return `state ${state}`;
    }
    return 'state already newer';
  }

  return 'unknown mirror';
}

/** Per-sibling sync state, for the Devices dialog. */
export async function syncStatus(client: Client): Promise<SyncStatus[]> {
  const incoming = (await client.store.getState(client.identityId, INCOMING_STATE)) ?? {};
  const outgoing = await requestedFrom(client);
  const approved = await approvals(client);
  const out: SyncStatus[] = [];
  // Fresh: this drives a dialog a human is looking at, and the sibling they just
  // added is exactly what the cache would not show yet.
  for (const device of await siblingDevices(client, { fresh: true })) {
    const entry = incoming[device.deviceId] ?? {};
    out.push({
      device_id: device.deviceId,
      name: device.name,
      approved: device.deviceId in approved,
      received: Number(entry.received ?? 0),
      expected: Number(entry.expected ?? 0),
      done: Boolean(entry.done),
      asked: (outgoing.asked ?? []).includes(device.deviceId),
      has_keys: (await fetchDeviceKeys(client, device)) !== null,
    });
  }
  return out;
}

