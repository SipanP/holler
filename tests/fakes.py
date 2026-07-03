"""In-memory fake transport mirroring the ``PeerConnection`` interface.

Faithfully reproduces the PeerJS quirk that matters to the client: a dialer's
channel is keyed by the ID it dialed (which may be a room *alias*), while the
answerer's channel is keyed by the dialer's real peer ID. Links can be severed
silently to simulate a dead network path without close events.
"""

import asyncio
from dataclasses import dataclass
from typing import Callable, Optional

from holler.crypto import rand_id
from holler.errors import PeerUnreachableError


class _Link:
    def __init__(self):
        self.alive = True


@dataclass
class _Endpoint:
    remote: "FakePeerConnection"
    remote_key: str
    link: _Link


class FakeHub:
    """Shared registry standing in for the PeerJS signaling server."""

    def __init__(self):
        self.owners: "dict[str, FakePeerConnection]" = {}

    def sever(self, a: "FakePeerConnection", b: "FakePeerConnection"):
        """Silently kills every link between two peers — no close events fire."""
        for ep in a._links.values():
            if ep.remote is b:
                ep.link.alive = False


class FakePeerConnection:
    """Drop-in replacement for ``holler.peer.PeerConnection`` in tests."""

    def __init__(self, hub: FakeHub):
        self.hub = hub
        self.peer_id = rand_id()
        self._links: "dict[str, _Endpoint]" = {}

        self.on_message: Optional[Callable[[str, str], None]] = None
        self.on_peer_connected: Optional[Callable[[str], None]] = None
        self.on_peer_disconnected: Optional[Callable[[str], None]] = None
        self.on_alias_lost: Optional[Callable[[str], None]] = None
        self.on_signaling_lost: Optional[Callable[[], None]] = None

    @property
    def connected_peers(self) -> "list[str]":
        return [k for k, ep in self._links.items() if ep.link.alive]

    async def start(self):
        if self.peer_id in self.hub.owners:
            raise ConnectionError("id taken")
        self.hub.owners[self.peer_id] = self

    async def register_alias(self, alias_id: str):
        if alias_id in self.hub.owners:
            raise ConnectionError("id taken")
        self.hub.owners[alias_id] = self

    async def unregister_alias(self, alias_id: str):
        if self.hub.owners.get(alias_id) is self:
            del self.hub.owners[alias_id]

    async def connect_to(self, target: str, timeout: float = 30.0):
        owner = self.hub.owners.get(target)
        if owner is None or owner is self:
            raise PeerUnreachableError(f"{target} is not reachable")
        existing = self._links.get(target)
        if existing and existing.link.alive:
            return
        link = _Link()
        self._attach(target, _Endpoint(owner, self.peer_id, link))
        owner._attach(self.peer_id, _Endpoint(self, target, link))
        # Let the scheduled connected/disconnected callbacks run.
        for _ in range(3):
            await asyncio.sleep(0)

    async def send_to(self, key: str, data: str):
        ep = self._links.get(key)
        if ep and ep.link.alive:
            asyncio.get_running_loop().call_soon(ep.remote._deliver, ep.remote_key, data)

    async def broadcast(self, data: str):
        for key in list(self._links.keys()):
            await self.send_to(key, data)

    async def drop(self, key: str):
        ep = self._links.pop(key, None)
        if ep is None:
            return
        if self.on_peer_disconnected:
            self.on_peer_disconnected(key)
        if ep.link.alive:
            ep.link.alive = False
            rep = ep.remote._links.pop(ep.remote_key, None)
            if rep is not None and ep.remote.on_peer_disconnected:
                loop = asyncio.get_running_loop()
                loop.call_soon(ep.remote.on_peer_disconnected, ep.remote_key)

    async def close(self):
        for key in list(self._links.keys()):
            await self.drop(key)
        for registered in [k for k, owner in self.hub.owners.items() if owner is self]:
            del self.hub.owners[registered]

    # ── internals ────────────────────────────────────────────────────────────

    def _attach(self, key: str, ep: _Endpoint):
        loop = asyncio.get_event_loop()
        old = self._links.pop(key, None)
        if old is not None:
            old.link.alive = False
            if self.on_peer_disconnected:
                loop.call_soon(self.on_peer_disconnected, key)
        self._links[key] = ep
        if self.on_peer_connected:
            loop.call_soon(self.on_peer_connected, key)

    def _deliver(self, key: str, data: str):
        if key in self._links and self.on_message:
            self.on_message(key, data)
