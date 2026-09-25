import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decrypt, encryptWithNonce } from '../src/crypto/aead';
import { fromHex, toHex } from '../src/crypto/bytes';
import { b32e, b64d, b64e, canonicalJson, cardDecode, cardEncode } from '../src/crypto/encoding';
import { Identity } from '../src/crypto/identity';
import { hkdfSha256, kdfCk, kdfRk, skCommitment } from '../src/crypto/kdf';
import { padEnvelope, unpadEnvelope } from '../src/crypto/padding';
import { PrekeyBundle, makeBundle, verifyBundle } from '../src/crypto/prekeys';
import { Ratchet } from '../src/crypto/ratchet';
import { buildAuth, initDict, initiate, respond, verifyAuth } from '../src/crypto/x3dh';
import { makeEnvelope, seal, unseal } from '../src/wire/protocol';

const vectors: any = JSON.parse(
  readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'),
);

/** Deterministic RNG matching the generator's `det_choice` (counter % 64). */
function counterRng(): () => number {
  let i = 0;
  return () => ((i++ % 62) + 0.5) / 62;
}

describe('encoding (Python interop)', () => {
  it('b64e matches and round-trips', () => {
    for (const c of vectors.encoding.b64e) {
      expect(b64e(fromHex(c.hex))).toBe(c.b64);
      expect(toHex(b64d(c.b64))).toBe(c.hex);
    }
  });

  it('b32e matches Crockford base32', () => {
    for (const c of vectors.encoding.b32e) {
      expect(b32e(fromHex(c.hex))).toBe(c.b32);
    }
  });

  it('canonicalJson matches json.dumps(sort_keys, separators, ensure_ascii=False)', () => {
    for (const c of vectors.encoding.canonical) {
      expect(canonicalJson(c.value)).toBe(c.json);
    }
  });

  it('decodes a contact card produced by the Python client', () => {
    expect(cardDecode(vectors.encoding.card.card)).toEqual(vectors.encoding.card.payload);
  });

  it('round-trips contact cards through its own encoder', () => {
    const encoded = cardEncode(vectors.encoding.card.payload);
    expect(encoded.startsWith('nk://1/')).toBe(true);
    expect(cardDecode(encoded)).toEqual(vectors.encoding.card.payload);
  });
});

describe('kdf (Python interop)', () => {
  it('hkdf matches', () => {
    for (const c of vectors.kdf.hkdf) {
      expect(toHex(hkdfSha256(fromHex(c.ikm_hex), fromHex(c.salt_hex), fromHex(c.info_hex), c.length))).toBe(c.out_hex);
    }
  });

  it('kdfRk matches', () => {
    for (const c of vectors.kdf.kdf_rk) {
      const [rk, ck] = kdfRk(fromHex(c.rk_hex), fromHex(c.dh_hex));
      expect(toHex(rk)).toBe(c.new_rk_hex);
      expect(toHex(ck)).toBe(c.ck_hex);
    }
  });

  it('kdfCk matches', () => {
    for (const c of vectors.kdf.kdf_ck) {
      const [mk, next] = kdfCk(fromHex(c.ck_hex));
      expect(toHex(mk)).toBe(c.mk_hex);
      expect(toHex(next)).toBe(c.next_ck_hex);
    }
  });

  it('skCommitment matches', () => {
    for (const c of vectors.kdf.sk_commitment) {
      expect(toHex(skCommitment(fromHex(c.sk_hex)))).toBe(c.out_hex);
    }
  });
});

describe('aead (Python interop)', () => {
  it('ChaCha20-Poly1305 ciphertexts match the cryptography backend', () => {
    for (const c of vectors.aead) {
      const key = fromHex(c.key_hex);
      const nonce = fromHex(c.nonce_hex);
      const pt = fromHex(c.pt_hex);
      const ad = fromHex(c.ad_hex);
      expect(toHex(encryptWithNonce(key, nonce, pt, ad))).toBe(c.ct_hex);
      expect(toHex(decrypt(key, nonce, fromHex(c.ct_hex), ad))).toBe(c.pt_hex);
    }
  });

  it('rejects tampered ciphertext', () => {
    const c = vectors.aead[0];
    const ct = fromHex(c.ct_hex);
    ct[0] ^= 0x01;
    expect(() => decrypt(fromHex(c.key_hex), fromHex(c.nonce_hex), ct, fromHex(c.ad_hex))).toThrow();
  });
});

describe('identity (Python interop)', () => {
  it('derives the same public keys, id and signatures', () => {
    const v = vectors.identity.from_private;
    const identity = Identity.fromPrivateBytes(fromHex(v.ed_seed_hex), fromHex(v.x_seed_hex));
    expect(toHex(identity.edPublicBytes)).toBe(v.ed_pub_hex);
    expect(toHex(identity.xPublicBytes)).toBe(v.x_pub_hex);
    expect(identity.identityId).toBe(v.id);
    expect(toHex(identity.sign(fromHex(v.msg_hex)))).toBe(v.sig_hex);
    expect(Identity.verify(fromHex(v.ed_pub_hex), fromHex(v.sig_hex), fromHex(v.msg_hex))).toBe(true);
  });

  it('derives the same identity from a BIP39 mnemonic', () => {
    const v = vectors.identity.mnemonic;
    const identity = Identity.fromMnemonic(v.mnemonic, v.passphrase);
    expect(toHex(identity.edPublicBytes)).toBe(v.ed_pub_hex);
    expect(identity.identityId).toBe(v.id);
  });

  it('loads an encrypted vault produced by the desktop client', () => {
    const v = vectors.identity.vault;
    const identity = Identity.fromVault(v.vault_json, v.passphrase);
    expect(identity.identityId).toBe(v.id);
    expect(() => Identity.fromVault(v.vault_json, 'wrong')).toThrow();
  });

  it('round-trips its own encrypted vault', () => {
    const identity = Identity.generate(null, undefined)[0];
    const vault = identity.toVault('pw');
    expect(Identity.fromVault(vault, 'pw').identityId).toBe(identity.identityId);
  });
});

describe('prekeys (Python interop)', () => {
  it('produces the same signed-prekey signature and public bundle bytes', () => {
    const v = vectors.prekeys;
    const alice = Identity.fromPrivateBytes(fromHex(vectors.identity.from_private.ed_seed_hex), fromHex(vectors.identity.from_private.x_seed_hex));
    const bundle = makeBundle(alice, fromHex(v.bundle_id_hex), v.spk_id, fromHex(v.spk_hex), [[v.opks[0].opk_id, fromHex(v.opks[0].opk_hex)]]);
    expect(toHex(bundle.spkSig)).toBe(v.spk_sig_hex);
    expect(canonicalJson(bundle.toPublicDict())).toBe(v.public_bytes_json);
    expect(() => verifyBundle(bundle, fromHex(v.isign_hex))).not.toThrow();
  });
});

describe('x3dh (Python interop)', () => {
  const v = vectors.x3dh;
  const isign = fromHex(v.initiate.expected_isign_hex);
  const idh = fromHex(v.initiate.expected_idh_hex);
  const bundle = new PrekeyBundle(
    fromHex(v.initiate.bundle_id_hex),
    isign,
    idh,
    v.initiate.spk_id,
    fromHex(v.initiate.spk_hex),
    fromHex(v.initiate.spk_sig_hex),
    [[v.initiate.opk_id, fromHex(v.initiate.opk_hex)]],
  );

  it('initiator derives the same shared secret and ephemeral key', () => {
    const initiation = initiate(bundle, isign, idh, fromHex(v.initiate.ek_private_hex));
    expect(toHex(initiation.ekPublic)).toBe(v.initiate.ek_public_hex);
    expect(toHex(initiation.sk)).toBe(v.initiate.sk_hex);
    expect(canonicalJson(initDict(initiation))).toBe(canonicalJson(v.initiate.init_dict));
  });

  it('responder derives the same shared secret', () => {
    const sk = respond(
      fromHex(v.respond.identity_x_private_hex),
      fromHex(v.respond.signed_prekey_private_hex),
      fromHex(v.respond.opk_private_hex),
      fromHex(v.respond.ek_public_hex),
    );
    expect(toHex(sk)).toBe(v.respond.sk_hex);
  });

  it('builds and verifies the same sender-auth proof', () => {
    const alice = Identity.fromPrivateBytes(
      fromHex(vectors.identity.from_private.ed_seed_hex),
      fromHex(vectors.identity.from_private.x_seed_hex),
    );
    const sid = fromHex(v.auth.sid_hex);
    const sk = fromHex(v.auth.sk_hex);
    const auth = buildAuth(alice, sid, v.auth.init_dict, sk);
    expect(canonicalJson(auth)).toBe(canonicalJson(v.auth.auth));
    expect(verifyAuth(auth, sid, v.auth.init_dict, sk)).toBe(true);
    expect(verifyAuth(auth, sid, v.auth.init_dict, new Uint8Array(32))).toBe(false);
  });
});

describe('padding (Python interop)', () => {
  it('pads to the identical canonical bytes', () => {
    for (const c of vectors.padding) {
      expect(toHex(padEnvelope(c.envelope, c.max_size, counterRng()))).toBe(c.padded_hex);
    }
  });

  it('round-trips through pad/unpad', () => {
    const env = { v: 1, type: 'text', id: 'x', ts: 1, body: { text: 'hi' } };
    const padded = padEnvelope(env, 2048);
    expect(padded.length % 256).toBe(0);
    expect(unpadEnvelope(padded)).toEqual(env);
  });
});

describe('ratchet (Python interop)', () => {
  it('initiator performs the same initial DH ratchet step', () => {
    const v = vectors.ratchet.initiator;
    const ratchet = Ratchet.initiator(
      fromHex(v.session_key_hex),
      fromHex(v.remote_ratchet_public_hex),
      [fromHex(v.dhs_private_hex), fromHex(v.dhs_public_hex)],
    );
    expect(toHex(ratchet.state.rootKey)).toBe(v.rk_hex);
    expect(toHex(ratchet.state.sendingChain as Uint8Array)).toBe(v.cks_hex);
  });
});

describe('end-to-end TS session', () => {
  function pair() {
    const alice = Identity.generate('alice')[0];
    const bob = Identity.generate('bob')[0];
    const spkPriv = fromHex(toHex(Identity.generate()[0].xPrivateBytes));
    const spkPub = Identity.fromPrivateBytes(Identity.generate()[0].edPrivateBytes, spkPriv).xPublicBytes;
    const opkPriv = Identity.generate()[0].xPrivateBytes;
    const opkPub = Identity.fromPrivateBytes(Identity.generate()[0].edPrivateBytes, opkPriv).xPublicBytes;
    const bundle = makeBundle(bob, new Uint8Array(16).fill(7), 1, spkPub, [[1, opkPub]]);
    const initiation = initiate(bundle, bob.edPublicBytes, bob.xPublicBytes);
    const aliceRatchet = Ratchet.initiator(initiation.sk, bundle.spk);
    const bobRatchet = Ratchet.responder(initiation.sk, spkPriv, spkPub);
    return { alice, bob, initiation, aliceRatchet, bobRatchet };
  }

  it('seals and unseals a first message carrying the handshake', () => {
    const { initiation, aliceRatchet, bobRatchet } = pair();
    const sid = new Uint8Array(16).fill(3);
    const envelope = makeEnvelope('text', { text: 'hello bob' }, 'id-1', 1730000000000);
    const blob = seal(aliceRatchet, envelope, sid, initDict(initiation));
    const [decoded, decodedSid, init] = unseal(bobRatchet, blob);
    expect(decoded.type).toBe('text');
    expect(decoded.body).toEqual({ text: 'hello bob' });
    expect(toHex(decodedSid)).toBe(toHex(sid));
    expect(init).toEqual(initDict(initiation));
  });

  it('handles a bidirectional exchange with out-of-order and replay rejection', () => {
    const { aliceRatchet, bobRatchet, initiation } = pair();
    const sid = new Uint8Array(16).fill(4);
    const first = seal(aliceRatchet, makeEnvelope('text', { text: 'one' }, 'a1', 1), sid, initDict(initiation));
    // Bob creates his first sending chain by receiving the first message.
    expect(unseal(bobRatchet, first)[0].body).toEqual({ text: 'one' });

    const second = seal(aliceRatchet, makeEnvelope('text', { text: 'two' }, 'a2', 2), sid);
    const third = seal(aliceRatchet, makeEnvelope('text', { text: 'three' }, 'a3', 3), sid);
    // Deliver 3 then 2: the skipped-key cache must handle reordering.
    expect(unseal(bobRatchet, third)[0].body).toEqual({ text: 'three' });
    expect(unseal(bobRatchet, second)[0].body).toEqual({ text: 'two' });
    // Replay of 2 must fail.
    expect(() => unseal(bobRatchet, second)).toThrow();

    const reply = seal(bobRatchet, makeEnvelope('text', { text: 'pong' }, 'b1', 4), sid);
    expect(unseal(aliceRatchet, reply)[0].body).toEqual({ text: 'pong' });
  });
});
