"""Live end-to-end smoke test against a real PeerJS signaling server.

Not collected by pytest — run directly:

    uv run python tests/e2e_smoke.py

Spins up a host and a joiner in one process, exchanges messages both ways
through real WebRTC DataChannels, and checks that a wrong password is
rejected. Exits non-zero on failure. The signaling server defaults to the
public 0.peerjs.com and can be overridden with HOLLER_SIGNALING.

CI runs this in a non-blocking job: a failure emits a workflow warning
rather than failing the pipeline, since it depends on a third-party
service and the runner's network.
"""

import asyncio
import os
import sys
import time

from holler.client import Client
from holler.errors import AuthenticationError

SIGNALING = os.environ.get("HOLLER_SIGNALING", "wss://0.peerjs.com/peerjs")


def log(message: str):
    print(f"[{time.strftime('%X')}] {message}", flush=True)


def make_client(name: str, password: str = "smoke-pw", join: "str | None" = None):
    events = []
    client = Client(
        name,
        password,
        join_id=join,
        signaling_url=SIGNALING,
        on_event=lambda kind, payload, e=events: e.append((kind, payload)),
    )
    return client, events


async def eventually(cond, timeout: float = 60.0, what: str = ""):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        await asyncio.sleep(0.2)
    raise AssertionError(f"timed out waiting for: {what}")


async def main():
    log(f"signaling server: {SIGNALING}")
    alice, alice_events = make_client("alice")
    bob = None
    try:
        await alice.start()
        log(f"alice created room {alice.room_id}")

        bob, bob_events = make_client("bob", join=alice.room_id)
        await bob.start()
        log("bob joined")
        await eventually(lambda: sorted(alice.online) == ["alice", "bob"], what="alice sees bob")

        await alice.send_chat("hello bob")
        await eventually(
            lambda: any(k == "chat" and p["text"] == "hello bob" for k, p in bob_events),
            what="bob receives alice's message",
        )
        await bob.send_chat("hi alice")
        await eventually(
            lambda: any(k == "chat" and p["text"] == "hi alice" for k, p in alice_events),
            what="alice receives bob's message",
        )
        log("two-way encrypted chat OK")

        eve, _ = make_client("eve", password="wrong", join=alice.room_id)
        try:
            await eve.start()
            raise AssertionError("wrong password was accepted")
        except AuthenticationError:
            log("wrong password rejected OK")

        log("E2E SMOKE PASS")
    finally:
        if bob is not None:
            await bob.stop()
        await alice.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        log(f"E2E SMOKE FAIL: {type(exc).__name__}: {exc}")
        sys.exit(1)
