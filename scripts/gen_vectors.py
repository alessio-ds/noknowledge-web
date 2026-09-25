#!/usr/bin/env python3
"""Generate cross-implementation test vectors from the Python reference.

Run with the reference project's interpreter:

    NK_PYTHON_REPO=/path/to/noknowledge \
      /path/to/noknowledge/.venv/bin/python scripts/gen_vectors.py --out .vectors/vectors.json

All randomness is replaced with deterministic streams so the vectors pin exact
byte values. The TypeScript test suite replays them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.environ.get("NK_PYTHON_REPO", os.getcwd()))

from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: E402

import noknowledge.crypto.padding as padding_mod  # noqa: E402
import noknowledge.crypto.ratchet as ratchet_mod  # noqa: E402
import noknowledge.crypto.x3dh as x3dh_mod  # noqa: E402
from noknowledge.crypto import x3dh  # noqa: E402
from noknowledge.crypto.encoding import (  # noqa: E402
    b32e,
    b64d,
    b64e,
    canonical_json,
    card_encode,
)
from noknowledge.crypto.identity import Identity  # noqa: E402
from noknowledge.crypto.kdf import (  # noqa: E402
    hkdf,
    kdf_ck,
    kdf_rk,
    sk_commitment,
)
from noknowledge.crypto.padding import pad_envelope  # noqa: E402
from noknowledge.crypto.prekeys import make_bundle, verify_bundle  # noqa: E402
from noknowledge.crypto.ratchet import Ratchet  # noqa: E402

# --------------------------------------------------------------------------
# deterministic randomness
# --------------------------------------------------------------------------

_urand_counter = [0]


def det_urandom(n: int) -> bytes:
    out = b""
    block = 0
    while len(out) < n:
        out += hashlib.sha256(
            b"nk/det/urandom" + str(_urand_counter[0]).encode() + block.to_bytes(4, "big")
        ).digest()
        block += 1
    _urand_counter[0] += 1
    return out[:n]


os.urandom = det_urandom  # type: ignore[assignment]


class _DetX25519Private:
    @staticmethod
    def generate():
        return X25519PrivateKey.from_private_bytes(det_urandom(32))

    @staticmethod
    def from_private_bytes(data: bytes):
        return X25519PrivateKey.from_private_bytes(data)

    @staticmethod
    def from_public_bytes(data: bytes):
        return X25519PublicKey.from_public_bytes(data)


x3dh_mod.X25519PrivateKey = _DetX25519Private  # type: ignore[assignment]
ratchet_mod.X25519PrivateKey = _DetX25519Private  # type: ignore[assignment]

_choice_counter = [0]


def det_choice(seq):
    value = seq[_choice_counter[0] % len(seq)]
    _choice_counter[0] += 1
    return value


padding_mod.secrets.choice = det_choice  # type: ignore[assignment]


def reset() -> None:
    _urand_counter[0] = 0
    _choice_counter[0] = 0


def hexb(data: bytes) -> str:
    return data.hex()


# --------------------------------------------------------------------------
# fixed material
# --------------------------------------------------------------------------

ED_SEED = bytes(range(32))
X_SEED = bytes(range(32, 64))
SPK_SEED = bytes(range(64, 96))
OPK_SEED = bytes(range(96, 128))
BUNDLE_ID = bytes(range(16))
SID = bytes(range(16, 32))
MSG = b"noknowledge vector message"


def build_vectors() -> dict:
    vectors: dict = {"version": 1}

    # -- encoding ----------------------------------------------------------
    enc_b64 = []
    for raw in (b"", b"\x00", b"\x00\x01\x02", bytes(range(32)), bytes(range(255))):
        enc_b64.append({"hex": hexb(raw), "b64": b64e(raw)})

    enc_b32 = []
    for raw in (b"", b"\x00", bytes(range(32)), hashlib.sha256(b"nk-id").digest()):
        enc_b32.append({"hex": hexb(raw), "b32": b32e(raw)})

    canonical_cases = [
        {"b": 2, "a": 1},
        {"nested": {"z": [1, 2, {"y": None}], "a": True}, "empty": {}, "list": []},
        {"unicode": "héllo ☃ 😀", "control": "a\tb\nc\x01"},
        {"quote": 'he said "hi" \\ back', "neg": -17},
        {"b64": b64e(bytes(range(40)))},
    ]
    enc_canonical = [
        {"value": case, "json": canonical_json(case).decode("utf-8")}
        for case in canonical_cases
    ]

    card_payload = {
        "v": 1,
        "id": "ABCDEFGHJKMNPQRSTVWXYZ0123",
        "isign": b64e(bytes(range(32))),
        "idh": b64e(bytes(range(32, 64))),
        "bundle": b64e(BUNDLE_ID),
        "inbox": {"id": b64e(bytes(range(16))), "w": b64e(bytes(range(32)))},
        "relays": ["https://relay1.example", "https://relay2.example"],
        "name": "Alice ☃",
        "sig": b64e(bytes(range(64))),
    }

    vectors["encoding"] = {
        "b64e": enc_b64,
        "b32e": enc_b32,
        "canonical": enc_canonical,
        "card": {"payload": card_payload, "card": card_encode(card_payload)},
    }

    # -- kdf ---------------------------------------------------------------
    hkdf_cases = []
    for ikm, salt, info, length in (
        (bytes(range(32)), b"", b"noknowledge/identity/v1", 64),
        (bytes(range(32, 64)), b"\x00" * 32, b"noknowledge/x3dh/v1", 32),
        (b"short", b"salt", b"nk/ratchet-root/v1", 64),
    ):
        hkdf_cases.append(
            {
                "ikm_hex": hexb(ikm),
                "salt_hex": hexb(salt),
                "info_hex": hexb(info),
                "length": length,
                "out_hex": hexb(hkdf(ikm, salt=salt, info=info, length=length)),
            }
        )
    kdf_rk_cases = []
    for rk, dh in ((bytes(range(32)), bytes(range(32, 64))), (b"r" * 32, b"d" * 32)):
        new_rk, ck = kdf_rk(rk, dh)
        kdf_rk_cases.append(
            {"rk_hex": hexb(rk), "dh_hex": hexb(dh), "new_rk_hex": hexb(new_rk), "ck_hex": hexb(ck)}
        )
    kdf_ck_cases = []
    for ck in (bytes(range(32)), b"c" * 32):
        mk, next_ck = kdf_ck(ck)
        kdf_ck_cases.append(
            {"ck_hex": hexb(ck), "mk_hex": hexb(mk), "next_ck_hex": hexb(next_ck)}
        )
    vectors["kdf"] = {
        "hkdf": hkdf_cases,
        "kdf_rk": kdf_rk_cases,
        "kdf_ck": kdf_ck_cases,
        "sk_commitment": [
            {"sk_hex": hexb(sk), "out_hex": hexb(sk_commitment(sk))}
            for sk in (bytes(range(32)), b"s" * 32)
        ],
    }

    # -- aead --------------------------------------------------------------
    aead_cases = []
    for key, nonce, pt, ad in (
        (bytes(range(32)), bytes(range(12)), b"hello", b"nk/v1/msg"),
        (b"k" * 32, b"n" * 12, bytes(300), b"aad"),
        (b"z" * 32, b"0" * 12, b"", b""),
    ):
        ct = ChaCha20Poly1305(key).encrypt(nonce, pt, ad)
        aead_cases.append(
            {
                "key_hex": hexb(key),
                "nonce_hex": hexb(nonce),
                "pt_hex": hexb(pt),
                "ad_hex": hexb(ad),
                "ct_hex": hexb(ct),
            }
        )
    vectors["aead"] = aead_cases

    # -- identity ----------------------------------------------------------
    alice = Identity.from_private_bytes(ED_SEED, X_SEED, label="alice")
    sig = alice.sign(MSG)
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon art"
    )
    from_mnemonic = Identity.from_mnemonic(mnemonic, passphrase="TREZOR")
    vault_pass = "correct horse battery staple"
    vault = alice.to_vault(passphrase=vault_pass).decode("utf-8")

    vectors["identity"] = {
        "from_private": {
            "ed_seed_hex": hexb(ED_SEED),
            "x_seed_hex": hexb(X_SEED),
            "ed_pub_hex": hexb(alice.ed_public_bytes),
            "x_pub_hex": hexb(alice.x_public_bytes),
            "id": alice.identity_id,
            "msg_hex": hexb(MSG),
            "sig_hex": hexb(sig),
        },
        "mnemonic": {
            "mnemonic": mnemonic,
            "passphrase": "TREZOR",
            "ed_pub_hex": hexb(from_mnemonic.ed_public_bytes),
            "x_pub_hex": hexb(from_mnemonic.x_public_bytes),
            "id": from_mnemonic.identity_id,
        },
        "vault": {
            "passphrase": vault_pass,
            "vault_json": vault,
            "id": alice.identity_id,
        },
    }

    # -- prekeys -----------------------------------------------------------
    bundle = make_bundle(alice, BUNDLE_ID, 7, SPK_SEED, [(42, OPK_SEED)])
    verify_bundle(bundle, alice.ed_public_bytes)
    vectors["prekeys"] = {
        "bundle_id_hex": hexb(BUNDLE_ID),
        "spk_id": 7,
        "spk_hex": hexb(SPK_SEED),
        "isign_hex": hexb(alice.ed_public_bytes),
        "idh_hex": hexb(alice.x_public_bytes),
        "spk_sig_hex": hexb(bundle.spk_sig),
        "public_bytes_json": bundle.to_bytes().decode("utf-8"),
        "opks": [{"opk_id": i, "opk_hex": hexb(p)} for i, p in bundle.opks],
    }

    # -- x3dh --------------------------------------------------------------
    reset()
    initiation = x3dh.initiate(bundle, alice.ed_public_bytes, alice.x_public_bytes)
    initiate_vector = {
        "expected_isign_hex": hexb(alice.ed_public_bytes),
        "expected_idh_hex": hexb(alice.x_public_bytes),
        "bundle_id_hex": hexb(BUNDLE_ID),
        "spk_id": 7,
        "spk_hex": hexb(SPK_SEED),
        "spk_sig_hex": hexb(bundle.spk_sig),
        "opk_id": 42,
        "opk_hex": hexb(OPK_SEED),
        "ek_public_hex": hexb(initiation.ek_public),
        "ek_private_hex": hexb(initiation.ek_private),
        "sk_hex": hexb(initiation.sk),
        "init_dict": initiation.init_dict(),
    }

    reset()
    responder_sk = x3dh.respond(X_SEED, SPK_SEED, OPK_SEED, initiation.ek_public)
    respond_vector = {
        "identity_x_private_hex": hexb(X_SEED),
        "signed_prekey_private_hex": hexb(SPK_SEED),
        "opk_private_hex": hexb(OPK_SEED),
        "ek_public_hex": hexb(initiation.ek_public),
        "sk_hex": hexb(responder_sk),
    }

    auth = x3dh.build_auth(alice, SID, initiation.init_dict(), initiation.sk)
    auth_vector = {
        "sid_hex": hexb(SID),
        "sk_hex": hexb(initiation.sk),
        "init_dict": initiation.init_dict(),
        "auth": auth,
    }

    vectors["x3dh"] = {
        "initiate": initiate_vector,
        "respond": respond_vector,
        "auth": auth_vector,
    }

    # -- padding -----------------------------------------------------------
    padding_cases = []
    for env, max_size in (
        (
            {"v": 1, "type": "text", "id": "abc", "ts": 1730000000000, "body": {"text": "hi"}},
            2048,
        ),
        (
            {"v": 1, "type": "receipt", "id": "r1", "ts": 1730000000001, "body": {"of": "abc", "kind": "read"}},
            2048,
        ),
        (
            {"v": 1, "type": "text", "id": "long", "ts": 1730000000002, "body": {"text": "x" * 400}},
            2048,
        ),
    ):
        _choice_counter[0] = 0
        padded = pad_envelope(env, max_size=max_size)
        padding_cases.append(
            {"envelope": env, "max_size": max_size, "padded_hex": hexb(padded)}
        )
    vectors["padding"] = padding_cases

    # -- ratchet -----------------------------------------------------------
    reset()
    alice_ratchet = Ratchet.initiator(initiation.sk, SPK_SEED)
    vectors["ratchet"] = {
        "initiator": {
            "session_key_hex": hexb(initiation.sk),
            "remote_ratchet_public_hex": hexb(SPK_SEED),
            "rk_hex": hexb(alice_ratchet.state.root_key),
            "cks_hex": hexb(alice_ratchet.state.sending_chain or b""),
            "dhs_private_hex": hexb(alice_ratchet.state.dh_self_private or b""),
            "dhs_public_hex": hexb(alice_ratchet.state.dh_self_public or b""),
        },
        "responder": {
            "session_key_hex": hexb(initiation.sk),
            "spk_private_hex": hexb(SPK_SEED),
            "spk_public_hex": hexb(SPK_SEED),
        },
    }

    return vectors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="test/vectors.json")
    args = parser.parse_args()
    vectors = build_vectors()
    directory = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(directory, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(vectors, handle, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
