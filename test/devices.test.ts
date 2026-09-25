/** Multi-device accounts: the sealed device list itself.
 *
 * The end-to-end behaviour lives in `devices.e2e.test.ts`; this file pins the
 * format, because it has to stay byte-compatible with the Python client. */

import { describe, expect, it } from 'vitest';
import {
  DeviceEntry,
  DeviceList,
  DeviceListError,
  deviceListId,
  openDeviceList,
  sealDeviceList,
} from '../src/core/devices';
import { Identity } from '../src/crypto/identity';

function identity(): Identity {
  return Identity.generate('listowner')[0];
}

function entry(deviceId = 'dev-one'): DeviceEntry {
  return new DeviceEntry(
    deviceId,
    { id: 'inbox-id', w: 'write-token' },
    ['https://relay.example'],
    'bundle-id',
    'laptop',
  );
}

describe('device list', () => {
  it('derives its address from the account public keys', () => {
    const owner = identity();
    const expected = deviceListId(owner.edPublicBytes, owner.xPublicBytes);
    expect(DeviceList.create(owner, [entry()]).address()).toBe(expected);
  });

  it('round-trips through the sealed record', () => {
    const owner = identity();
    const listing = DeviceList.create(owner, [entry()]);
    const opened = openDeviceList(
      sealDeviceList(listing),
      owner.edPublicBytes,
      owner.xPublicBytes,
    );
    expect(opened.account).toBe(owner.identityId);
    expect(opened.devices.map((device) => device.deviceId)).toEqual(['dev-one']);
    expect(opened.devices[0].relays).toEqual(['https://relay.example']);
    expect(opened.devices[0].name).toBe('laptop');
  });

  it('leaks no identity keys, id or mailbox into the stored record', () => {
    const owner = identity();
    const listing = DeviceList.create(owner, [entry()]);
    const stored = new TextDecoder().decode(sealDeviceList(listing));
    expect(stored).not.toContain('isign');
    expect(stored).not.toContain('idh');
    expect(stored).not.toContain(owner.identityId);
    expect(stored).not.toContain('relay.example');
    expect(stored).not.toContain('inbox-id');
    expect(stored).not.toContain('write-token');
  });

  it('cannot be opened with the wrong keys', () => {
    const owner = identity();
    const stranger = identity();
    const stored = sealDeviceList(DeviceList.create(owner, [entry()]));
    expect(() =>
      openDeviceList(stored, stranger.edPublicBytes, stranger.xPublicBytes),
    ).toThrow(DeviceListError);
  });

  it('rejects a tampered box', () => {
    const owner = identity();
    const stored = new TextDecoder().decode(sealDeviceList(DeviceList.create(owner, [entry()])));
    const box = /"box":"([^"]+)"/.exec(stored)![1];
    const flipped = box.slice(0, 4) + (box[4] === 'A' ? 'B' : 'A') + box.slice(5);
    const tampered = stored.replace(box, flipped);
    expect(() =>
      openDeviceList(tampered, owner.edPublicBytes, owner.xPublicBytes),
    ).toThrow(DeviceListError);
  });

  it('binds the device set with the account signature', () => {
    const owner = identity();
    const listing = DeviceList.create(owner, [entry()]);
    listing.devices.push(entry('smuggled'));
    // Re-serialising without re-signing must fail verification.
    expect(() => DeviceList.fromBytes(listing.toBytes())).toThrow(DeviceListError);
  });

  it('rejects a list that belongs to another account', () => {
    const owner = identity();
    const stranger = identity();
    const listing = DeviceList.create(stranger, [entry()]);
    expect(
      listing.belongsTo(owner.identityId, owner.edPublicBytes, owner.xPublicBytes),
    ).toBe(false);
  });

  it('rejects a list with no devices', () => {
    const owner = identity();
    const listing = DeviceList.create(owner, [entry()]);
    listing.devices = [];
    expect(() => DeviceList.fromBytes(listing.toBytes())).toThrow(DeviceListError);
  });
});