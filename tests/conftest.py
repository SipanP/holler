import time
from typing import Any

import pytest

from holler.client import Client
from tests.fakes import FakeHub, FakePeerConnection


async def eventually(cond, timeout: float = 5.0) -> bool:
    """Polls ``cond`` until it is truthy or the timeout elapses."""
    import asyncio

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        await asyncio.sleep(0.02)
    return bool(cond())


@pytest.fixture
def hub():
    return FakeHub()


@pytest.fixture
async def make_client(hub):
    """Factory building fast-timing clients on the fake hub; auto-stops them."""
    clients = []

    def factory(username: str, password: str = "pw", join: "str | None" = None, **overrides):
        events = []
        kwargs: "dict[str, Any]" = dict(
            peer_factory=lambda: FakePeerConnection(hub),
            ping_interval=0.05,
            stale_after=0.5,
            handshake_timeout=5.0,
            join_timeout=5.0,
            reconnect_delays=(0.05, 0.1),
            on_event=lambda kind, payload: events.append((kind, payload)),
        )
        kwargs.update(overrides)
        client = Client(username, password, join_id=join, **kwargs)
        clients.append(client)
        return client, events

    yield factory

    for client in clients:
        await client.stop()
