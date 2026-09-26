#!/usr/bin/env python3
"""A scriptable Python noknowledge client, for cross-implementation tests.

Speaks newline-delimited JSON on stdin/stdout so the TypeScript test suite can
drive a *reference* client against the same relay as the browser client. This
is a test harness only: the web app never runs Python.

Commands: init, add_contact, send_text, send_file, sync, contacts, messages,
download, mark_read, export_history, import_history, device_id, request_history,
history_requests, approve_history, sync_status, quit.
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.environ.get("NK_PYTHON_REPO", os.getcwd()))

from noknowledge.core import history as history_mod  # noqa: E402
from noknowledge.core.client import Client  # noqa: E402
from noknowledge.core.store import LocalStore, resolve_store_key  # noqa: E402
from noknowledge.crypto.identity import Identity  # noqa: E402

STATE: dict = {}


def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def serialize_message(message: dict) -> dict:
    return {
        "id": message["id"],
        "contact_id": message["contact_id"],
        "direction": message["direction"],
        "type": message["type"],
        "body": message["body"],
        "remote_id": message.get("remote_id"),
        "state": message.get("state"),
        "ts": message.get("ts"),
    }


def handle(request: dict) -> dict:
    command = request.get("cmd")
    if command == "init":
        data_dir = request["data_dir"]
        os.makedirs(data_dir, exist_ok=True)
        STATE["dir"] = data_dir
        identity_path = os.path.join(data_dir, "identity.nk")
        if request.get("mnemonic"):
            # The same account as another device under test.
            identity = Identity.from_mnemonic(
                request["mnemonic"], None, label=request.get("name")
            )
            identity.save(identity_path)
        elif os.path.exists(identity_path):
            identity = Identity.load(identity_path)
        else:
            identity, _mnemonic = Identity.generate(label=request.get("name"))
            identity.save(identity_path)
        key = resolve_store_key(data_dir, identity.identity_id)
        store = LocalStore(os.path.join(data_dir, "local.db"), key=key)
        store.initialize()
        client = Client(identity, store, list(request["relays"]), name=request.get("name"))
        client.provision()
        STATE["client"] = client
        return {"ok": True, "id": identity.identity_id, "card": client.card_string()}

    client = STATE["client"]
    if command == "add_contact":
        contact = client.add_contact(request["card"])
        return {"ok": True, "contact": contact["id"]}
    if command == "send_text":
        return {"ok": True, "message_id": client.send_text(request["contact"], request["text"])}
    if command == "send_file":
        return {"ok": True, "message_id": client.send_file(request["contact"], request["path"])}
    if command == "sync":
        messages = client.sync(wait=int(request.get("wait", 0)))
        return {"ok": True, "messages": [serialize_message(m) for m in messages]}
    if command == "contacts":
        return {"ok": True, "contacts": [{"id": c["id"], "nickname": c["nickname"]} for c in client.list_contacts()]}
    if command == "messages":
        return {
            "ok": True,
            "messages": [serialize_message(m) for m in client.messages(request["contact"])],
        }
    if command == "download":
        message = client.store.get_message(request["message_id"])
        data = client.download_attachment(message)
        return {"ok": True, "data_b64": base64.b64encode(data).decode("ascii")}
    if command == "mark_read":
        client.mark_read(request["contact"], request["message_id"])
        return {"ok": True}
    if command == "card":
        return {"ok": True, "card": client.card_string()}
    if command == "device_id":
        return {"ok": True, "device_id": client.device_id()}
    if command == "request_history":
        asked = client.request_history(since_ms=request.get("since_ms"))
        return {"ok": True, "asked": asked}
    if command == "history_requests":
        return {"ok": True, "requests": client.history_requests()}
    if command == "approve_history":
        result = client.approve_history(
            request["device_id"], since_ms=request.get("since_ms")
        )
        return {"ok": True, "result": result}
    if command == "sync_status":
        return {"ok": True, "status": client.sync_status()}
    if command == "export_history":
        # Written to a file so a large bundle never has to cross the line protocol.
        data = history_mod.export_history(
            client,
            request["passphrase"],
            budget_bytes=int(request.get("budget_bytes", 100 * 1024 * 1024)),
        )
        with open(request["path"], "wb") as handle:
            handle.write(data)
        return {"ok": True, "bytes": len(data)}
    if command == "import_history":
        with open(request["path"], "rb") as handle:
            data = handle.read()
        counts = history_mod.import_history(client, data, request["passphrase"])
        return {"ok": True, "counts": counts}
    if command == "quit":
        return {"ok": True, "bye": True}
    return {"ok": False, "error": f"unknown command: {command}"}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            response = handle(json.loads(line))
        except Exception as exc:  # surface any failure to the test, never crash silently
            response = {"ok": False, "error": repr(exc)}
        emit(response)
        if response.get("bye"):
            break


if __name__ == "__main__":
    main()
