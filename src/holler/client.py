"""Encrypted group chat client built on top of PeerConnection.

Wire protocol (v3)
==================

Direct messages (one DataChannel, never relayed):

- ``holler.kex``      — real peer ID + SPAKE2 message + X25519 public key.
- ``holler.confirm``  — key-confirmation MAC; fails loudly on password mismatch.
- ``holler.sec``      — pairwise-encrypted payload: sender key, username, and
  (from the host side) the roster and room ID.
- ``holler.rekey``    — pairwise-encrypted replacement sender key, sent when
  the group membership shrinks.
- ``holler.ping``     — liveness heartbeat; any inbound traffic counts.

Gossip envelopes (``holler.gossip``) carry chat, leave, and typing events.
Every envelope has a unique ID, the origin's real peer ID, a TTL, and a
Lamport timestamp; the body is AES-256-GCM sealed with the origin's sender
key, with all envelope metadata bound as AAD. Peers re-broadcast envelopes
they have not seen before, so messages survive individual dead links as long
as any path through the mesh exists.
"""

import asyncio
import base64
import bisect
import contextlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from holler.crypto import LamportClock, PairwiseHandshake, SeenCache, open_any, rand_id, seal
from holler.errors import AuthenticationError, PeerUnreachableError, ProtocolError
from holler.peer import PeerConnection

GOSSIP_TTL = 8
MAX_LOG_ENTRIES = 1000
TYPING_EXPIRY = 4.0
TYPING_SEND_GAP = 2.0


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64d(data: dict, name: str) -> bytes:
    value = data.get(name)
    if not isinstance(value, str):
        raise ProtocolError(f"missing field: {name}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise ProtocolError(f"invalid base64 in field: {name}") from None


@dataclass
class PeerState:
    """Per-connection state established during the handshake.

    Attributes:
        channel_key: The transport-level key for this DataChannel. For a
            joiner's first connection this is the *room alias*, not the host's
            real peer ID — which is why ``peer_id`` is exchanged explicitly.
        peer_id: The remote peer's real (self-registered) ID, learned in kex.
        username: Display name received during the handshake.
        pairwise: Pairwise AEAD established via SPAKE2 + X25519. Used only for
            handshake payloads and rekeys, never for chat messages.
        ready: True once the handshake completed and the peer is in the mesh.
        last_seen: ``time.monotonic()`` of the last inbound message.
    """

    channel_key: str
    peer_id: Optional[str] = None
    username: Optional[str] = None
    pairwise: Optional[Any] = None
    ready: bool = False
    last_seen: float = field(default_factory=time.monotonic)


class Client:
    """Headless chat client managing the mesh, encryption, and resilience.

    All user-visible output flows through the ``on_event`` callback, so the
    client can run under a terminal UI or a test harness unchanged.

    Emitted events (``on_event(kind, payload)``):

    - ``room``      — ``{room_id}`` after creating a room.
    - ``chat``      — ``{username, text, wall, lam, origin}``.
    - ``info``      — ``{text}`` status lines (joins, leaves, reconnects).
    - ``error``     — ``{text}`` recoverable failures worth surfacing.
    - ``presence``  — ``{online: [usernames]}`` whenever membership changes.
    - ``typing``    — ``{users: [usernames]}`` whenever the typing set changes.

    Args:
        username: Display name shown to other peers.
        password: Shared secret proven via SPAKE2 during every pairwise
            handshake. Never transmitted, and not offline-attackable by an
            active MITM.
        join_id: Room ID to join. If ``None``, a new room is created.
        signaling_url: PeerJS-compatible signaling server websocket URL.
        ice_servers: Optional list of ``RTCIceServer`` (STUN/TURN).
        peer_factory: Factory returning a ``PeerConnection``-compatible
            transport; injectable for tests.
        ping_interval: Seconds between liveness pings on each channel.
        stale_after: Seconds without inbound traffic before a link is
            considered dead and reconnection starts.
        reconnect_delays: Backoff schedule (seconds) for redial attempts.
        on_event: Callback receiving ``(kind, payload)`` events.
    """

    def __init__(
        self,
        username: str,
        password: str,
        join_id: Optional[str] = None,
        *,
        signaling_url: Optional[str] = None,
        ice_servers: Optional[list] = None,
        peer_factory: Optional[Callable[[], Any]] = None,
        ping_interval: float = 5.0,
        stale_after: float = 30.0,
        handshake_timeout: float = 45.0,
        join_timeout: float = 60.0,
        reconnect_delays: "tuple[float, ...]" = (1, 2, 4, 8, 16),
        on_event: Optional[Callable[[str, dict], None]] = None,
    ):
        self.username = username[:64]
        self.password = password.encode()
        self.join_id = join_id
        self.on_event = on_event
        self.running = False
        self.log: list = []  # entries sorted by (lamport, origin, msg_id)

        def default_factory() -> PeerConnection:
            kwargs: dict = {}
            if signaling_url:
                kwargs["signaling_url"] = signaling_url
            if ice_servers:
                kwargs["ice_servers"] = ice_servers
            return PeerConnection(**kwargs)

        self._peer_factory = peer_factory or default_factory
        self._ping_interval = ping_interval
        self._stale_after = stale_after
        self._handshake_timeout = handshake_timeout
        self._join_timeout = join_timeout
        self._reconnect_delays = reconnect_delays

        self._peer: Optional[Any] = None
        self._sender_key: bytes = b""
        self._sender_keys: dict[str, list] = {}  # real peer ID -> [newest, previous]
        self._usernames: dict[str, str] = {}  # real peer ID -> display name
        self._states: dict[str, PeerState] = {}  # channel key -> state
        self._queues: dict[str, asyncio.Queue] = {}  # channel key -> handshake queue
        self._initiated: set = set()
        self._connecting: set = set()
        self._reconnecting: set = set()  # real peer IDs mid-reconnect
        self._departing: set = set()  # real peer IDs that announced leaving
        self._typing: dict[str, float] = {}  # username -> last typing signal
        self._last_typing_sent = 0.0

        self._clock = LamportClock()
        self._seen = SeenCache()

        self._room_id: Optional[str] = None
        self._holding_room = False
        self._acquiring_room = False

        self._join_future: Optional[asyncio.Future] = None
        self._monitor_task: Optional[asyncio.Task] = None
        self._tasks: set = set()
        self._stopped = False

    # ── public API ────────────────────────────────────────────────────────────

    @property
    def room_id(self) -> Optional[str]:
        return self._room_id

    @property
    def online(self) -> "list[str]":
        """Usernames currently in the mesh, self first."""
        others = sorted(st.username for st in self._states.values() if st.ready and st.username)
        return [self.username] + others

    async def start(self):
        """Connects to signaling and either creates or joins a room.

        Raises:
            AuthenticationError: Wrong password (key confirmation failed).
            PeerUnreachableError: The room ID does not exist or timed out.
            ConnectionError: The signaling server rejected us.
        """
        self._sender_key = os.urandom(32)
        peer = self._peer_factory()
        self._peer = peer
        peer.on_message = self._on_message
        peer.on_peer_connected = self._on_peer_connected
        peer.on_peer_disconnected = self._on_channel_closed
        peer.on_alias_lost = self._on_alias_lost
        peer.on_signaling_lost = self._on_signaling_lost
        await peer.start()
        self.running = True
        self._monitor_task = asyncio.create_task(self._monitor())

        if self.join_id:
            self._join_future = asyncio.get_running_loop().create_future()
            self._track(asyncio.create_task(self._connect_to_peer(self.join_id)))
            try:
                await asyncio.wait_for(self._join_future, self._join_timeout)
            except asyncio.TimeoutError:
                await self.stop()
                raise PeerUnreachableError("timed out joining the room") from None
            except Exception:
                await self.stop()
                raise
        else:
            self._room_id = rand_id()
            await self._acquire_room()
            if not self._holding_room:
                await self.stop()
                raise ConnectionError("could not register a room ID with the signaling server")
            self._emit("room", room_id=self._room_id)

    async def send_chat(self, text: str):
        """Encrypts ``text`` with the sender key and gossips it to the group."""
        assert self._peer is not None
        wall = self._now()
        msg_id, lam = await self._gossip_out("chat", {"text": text, "wall": wall})
        self._append_log(lam, self._peer.peer_id, msg_id, self.username, text, wall)

    def notify_typing(self):
        """Signals (rate-limited) that this user is typing."""
        if not self.running:
            return
        now = time.monotonic()
        if now - self._last_typing_sent < TYPING_SEND_GAP:
            return
        self._last_typing_sent = now
        self._track(asyncio.create_task(self._gossip_out("typing", {})))

    async def stop(self):
        """Announces departure, releases the room, and tears everything down."""
        if self._stopped:
            return
        self._stopped = True
        self.running = False
        if self._peer:
            with contextlib.suppress(Exception):
                await self._gossip_out("leave", {})
                await asyncio.sleep(0.1)
            if self._holding_room:
                with contextlib.suppress(Exception):
                    await self._release_room()
            with contextlib.suppress(Exception):
                await self._peer.close()
        if self._monitor_task:
            self._monitor_task.cancel()
        # Two passes: tasks may spawn small cleanup tasks from their finally blocks.
        for _ in range(2):
            pending = list(self._tasks)
            if not pending:
                break
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _emit(self, kind: str, **payload):
        if self.on_event:
            try:
                self.on_event(kind, payload)
            except Exception:
                pass

    def _track(self, task: asyncio.Task) -> asyncio.Task:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()[:19].replace("T", " ")

    async def _send(self, channel_key: str, obj: dict):
        assert self._peer is not None
        await self._peer.send_to(channel_key, json.dumps(obj))

    def _append_log(self, lam: int, origin: str, msg_id: str, username: str, text: str, wall: str):
        entry = {
            "lam": lam,
            "origin": origin,
            "username": username,
            "text": text,
            "wall": wall,
        }
        bisect.insort(self.log, ((lam, origin, msg_id), entry))
        if len(self.log) > MAX_LOG_ENTRIES:
            del self.log[0]
        self._emit("chat", **entry)

    def _find_ready(self, real_id: str) -> Optional[PeerState]:
        for st in self._states.values():
            if st.peer_id == real_id and st.ready:
                return st
        return None

    def _emit_presence(self):
        self._emit("presence", online=self.online)

    # ── room holder logic ─────────────────────────────────────────────────────

    def _should_hold_room(self) -> bool:
        """True if this peer has the lexicographically lowest real ID in the mesh."""
        assert self._peer is not None
        ids = [self._peer.peer_id] + [
            st.peer_id for st in self._states.values() if st.ready and st.peer_id
        ]
        return min(ids) == self._peer.peer_id

    async def _acquire_room(self):
        """Registers the room ID alias with PeerJS, retrying up to 5 times.

        Retries handle the race window where the previous holder's PeerJS
        registration has not yet expired after an ungraceful disconnect.
        """
        assert self._peer is not None
        assert self._room_id is not None
        if self._holding_room or self._acquiring_room:
            return
        self._acquiring_room = True
        try:
            for _ in range(5):
                try:
                    await self._peer.register_alias(self._room_id)
                    self._holding_room = True
                    return
                except ConnectionError:
                    await asyncio.sleep(1)
        finally:
            self._acquiring_room = False

    async def _release_room(self):
        assert self._peer is not None
        assert self._room_id is not None
        if not self._holding_room:
            return
        await self._peer.unregister_alias(self._room_id)
        self._holding_room = False

    async def _reevaluate_room_holder(self):
        """Acquires or releases the room ID based on the current peer list.

        Idempotent and called on every membership change plus periodically
        from the monitor loop, so a lost registration heals on its own.
        """
        if self._room_id is None or not self.running:
            return
        if self._should_hold_room() and not self._holding_room:
            await self._acquire_room()
        elif not self._should_hold_room() and self._holding_room:
            await self._release_room()

    def _on_alias_lost(self, alias: str):
        if alias == self._room_id:
            self._holding_room = False
            self._emit("info", text="room registration lost — retrying in background")

    def _on_signaling_lost(self):
        self._emit(
            "error",
            text="signaling connection lost — existing chats keep working, "
            "but new peers cannot join through you",
        )

    # ── transport callbacks ───────────────────────────────────────────────────

    def _on_message(self, channel_key: str, raw: str):
        st = self._states.get(channel_key)
        if st:
            st.last_seen = time.monotonic()
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return
        if not isinstance(data, dict):
            return

        t = data.get("type")
        if t == "holler.gossip":
            if st and st.ready:
                self._handle_gossip(channel_key, data)
        elif t == "holler.ping":
            pass  # last_seen already updated
        elif t == "holler.rekey":
            if st and st.ready:
                self._handle_rekey(st, data)
        else:
            q = self._queues.get(channel_key)
            if q:
                q.put_nowait(data)

    def _on_peer_connected(self, channel_key: str):
        st = PeerState(channel_key)
        self._states[channel_key] = st
        queue: asyncio.Queue = asyncio.Queue()
        self._queues[channel_key] = queue
        is_initiator = channel_key in self._initiated
        self._initiated.discard(channel_key)
        self._track(asyncio.create_task(self._peer_session(st, queue, is_initiator)))

    def _on_channel_closed(self, channel_key: str):
        q = self._queues.get(channel_key)
        if q:
            q.put_nowait(None)

    # ── connection management ─────────────────────────────────────────────────

    async def _connect_to_peer(self, target: str):
        """Dials ``target`` unless it is us, already connected, or in progress."""
        assert self._peer is not None
        if target == self._peer.peer_id or target in self._connecting:
            return
        if target in self._states:
            return
        if any(st.peer_id == target for st in self._states.values()):
            return
        self._connecting.add(target)
        self._initiated.add(target)
        try:
            await self._peer.connect_to(target)
        except Exception as exc:
            self._initiated.discard(target)
            if self._join_future and target == self.join_id and not self._join_future.done():
                self._join_future.set_exception(exc)
            else:
                self._emit("info", text=f"could not reach peer {target}")
        finally:
            self._connecting.discard(target)

    # ── per-peer session ──────────────────────────────────────────────────────

    async def _peer_session(self, st: PeerState, queue: asyncio.Queue, is_initiator: bool):
        """Runs the full lifecycle for one channel: handshake, then idle pump."""
        key = st.channel_key
        try:
            await asyncio.wait_for(
                self._handshake(st, queue, is_initiator), self._handshake_timeout
            )
            while self.running:
                item = await queue.get()
                if item is None:
                    break
        except AuthenticationError as exc:
            self._fail_join(key, exc)
            self._emit("error", text=f"authentication failed with a peer — {exc}")
        except (ProtocolError, asyncio.TimeoutError) as exc:
            reason = exc if isinstance(exc, ProtocolError) else ProtocolError("handshake timed out")
            self._fail_join(key, reason)
            if st.ready or not isinstance(exc, asyncio.TimeoutError):
                self._emit("info", text=f"connection to a peer failed: {reason}")
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            superseded = self._states.get(key) is not st
            if not superseded:
                self._states.pop(key, None)
            if self._queues.get(key) is queue:
                self._queues.pop(key, None)
            self._after_session(st, superseded)

    def _fail_join(self, channel_key: str, exc: Exception):
        if self._join_future and channel_key == self.join_id and not self._join_future.done():
            self._join_future.set_exception(exc)

    def _after_session(self, st: PeerState, superseded: bool):
        """Post-session bookkeeping: departures, reconnects, room re-election."""
        real = st.peer_id
        if superseded or not st.ready or real is None:
            return
        if self.running:
            if real in self._departing:
                self._departing.discard(real)
                self._finalize_departure(real)
            elif real not in self._reconnecting:
                self._begin_reconnect(real, st.username or real)
        self._emit_presence()
        if self.running:
            self._track(asyncio.create_task(self._reevaluate_room_holder()))

    async def _handshake(self, st: PeerState, queue: asyncio.Queue, is_initiator: bool):
        """SPAKE2 + X25519 handshake with explicit key confirmation.

        Both sides run the same steps concurrently:

        1. **kex** — exchange real peer IDs, SPAKE2 messages, X25519 keys.
        2. **confirm** — exchange MACs over own peer ID; a mismatch means the
           passwords differ and raises :class:`AuthenticationError` loudly.
        3. **sec** — exchange pairwise-encrypted sender keys and usernames;
           the host side additionally sends the roster and room ID.
        """
        assert self._peer is not None
        key = st.channel_key
        hs = PairwiseHandshake(self.password)
        spake_msg, pub = hs.outbound()
        await self._send(
            key,
            {
                "type": "holler.kex",
                "peer": self._peer.peer_id,
                "spake": _b64e(spake_msg),
                "pub": _b64e(pub),
            },
        )
        data = await self._expect(queue, "holler.kex")
        real = data.get("peer")
        if not isinstance(real, str) or not (1 <= len(real) <= 64):
            raise ProtocolError("invalid peer id in key exchange")
        if real == self._peer.peer_id:
            raise ProtocolError("peer claims our own id")
        st.peer_id = real
        st.pairwise = hs.finish(_b64d(data, "spake"), _b64d(data, "pub"))

        await self._send(
            key,
            {
                "type": "holler.confirm",
                "mac": _b64e(st.pairwise.confirmation(self._peer.peer_id)),
            },
        )
        data = await self._expect(queue, "holler.confirm")
        if not st.pairwise.verify_confirmation(real, _b64d(data, "mac")):
            raise AuthenticationError("key confirmation failed (wrong password?)")

        sec: dict = {"sender_key": _b64e(self._sender_key), "username": self.username}
        if not is_initiator:
            sec["roster"] = [
                s.peer_id
                for s in self._states.values()
                if s.ready and s.peer_id and s.peer_id != real
            ]
            sec["room_id"] = self._room_id
        blob = st.pairwise.encrypt(
            json.dumps(sec).encode(), b"holler.sec:" + self._peer.peer_id.encode()
        )
        await self._send(key, {"type": "holler.sec", "blob": _b64e(blob)})
        data = await self._expect(queue, "holler.sec")
        plaintext = st.pairwise.decrypt(_b64d(data, "blob"), b"holler.sec:" + real.encode())
        try:
            sec_in = json.loads(plaintext)
        except (json.JSONDecodeError, ValueError):
            raise ProtocolError("malformed secure payload") from None

        username = sec_in.get("username")
        if not isinstance(username, str) or not username.strip():
            raise ProtocolError("missing username")
        try:
            their_sender_key = base64.b64decode(sec_in.get("sender_key", ""), validate=True)
        except Exception:
            raise ProtocolError("invalid sender key") from None
        if len(their_sender_key) != 32:
            raise ProtocolError("invalid sender key length")

        st.username = username.strip()[:64]
        self._store_sender_key(real, their_sender_key)
        self._usernames[real] = st.username

        if is_initiator:
            room = sec_in.get("room_id")
            if isinstance(room, str) and self._room_id is None:
                self._room_id = room
            for pid in sec_in.get("roster") or []:
                if isinstance(pid, str) and pid:
                    self._track(asyncio.create_task(self._connect_to_peer(pid)))

        was_reconnecting = real in self._reconnecting
        st.ready = True
        verb = "reconnected" if was_reconnecting else "joined"
        self._emit("info", text=f"{st.username} {verb}")
        self._emit_presence()
        if self._join_future and key == self.join_id and not self._join_future.done():
            self._join_future.set_result(None)
        self._track(asyncio.create_task(self._reevaluate_room_holder()))

    async def _expect(self, queue: asyncio.Queue, msg_type: str) -> dict:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=20)
        except asyncio.TimeoutError:
            raise ProtocolError(f"timed out waiting for {msg_type}") from None
        if item is None:
            raise ProtocolError("peer disconnected during handshake")
        if item.get("type") != msg_type:
            raise ProtocolError(f"expected {msg_type}, got {item.get('type')!r}")
        return item

    def _store_sender_key(self, real_id: str, new_key: bytes):
        """Stores a peer's sender key, keeping the previous one as a fallback."""
        old = self._sender_keys.get(real_id, [])
        self._sender_keys[real_id] = [new_key] + [k for k in old if k != new_key][:1]

    # ── gossip ────────────────────────────────────────────────────────────────

    def _gossip_aad(self, msg_id: str, origin: str, lam: int, kind: str) -> bytes:
        return f"holler.gossip:{msg_id}:{origin}:{lam}:{kind}".encode()

    async def _gossip_out(self, kind: str, payload: dict) -> "tuple[str, int]":
        """Seals ``payload`` with our sender key and broadcasts the envelope."""
        assert self._peer is not None
        origin = self._peer.peer_id
        msg_id = secrets.token_hex(8)
        lam = self._clock.tick()
        aad = self._gossip_aad(msg_id, origin, lam, kind)
        blob = seal(self._sender_key, json.dumps(payload).encode(), aad)
        self._seen.check_and_add(msg_id)
        envelope = json.dumps(
            {
                "type": "holler.gossip",
                "id": msg_id,
                "origin": origin,
                "ttl": GOSSIP_TTL,
                "lam": lam,
                "kind": kind,
                "blob": _b64e(blob),
            }
        )
        for st in list(self._states.values()):
            if st.ready:
                await self._peer.send_to(st.channel_key, envelope)
        return msg_id, lam

    def _handle_gossip(self, via_key: str, msg: dict):
        assert self._peer is not None
        msg_id = msg.get("id")
        origin = msg.get("origin")
        ttl = msg.get("ttl")
        lam = msg.get("lam")
        kind = msg.get("kind")
        blob64 = msg.get("blob")
        if not (
            isinstance(msg_id, str)
            and isinstance(origin, str)
            and isinstance(ttl, int)
            and isinstance(lam, int)
            and isinstance(kind, str)
            and isinstance(blob64, str)
            and 0 < ttl <= 32
            and 0 <= lam
            and len(msg_id) <= 64
            and len(origin) <= 64
        ):
            return
        if not self._seen.check_and_add(msg_id):
            return
        if origin == self._peer.peer_id:
            return
        self._clock.update(lam)

        payload: Optional[dict] = None
        keys = self._sender_keys.get(origin)
        if keys:
            try:
                aad = self._gossip_aad(msg_id, origin, lam, kind)
                raw = open_any(keys, base64.b64decode(blob64), aad)
                decoded = json.loads(raw)
                if isinstance(decoded, dict):
                    payload = decoded
            except Exception:
                return  # forged or corrupted — do not deliver, do not forward

        if ttl > 1:
            forwarded = dict(msg)
            forwarded["ttl"] = ttl - 1
            raw_out = json.dumps(forwarded)
            for st in list(self._states.values()):
                if st.ready and st.channel_key != via_key:
                    self._track(asyncio.create_task(self._peer.send_to(st.channel_key, raw_out)))

        if payload is None:
            return
        username = self._usernames.get(origin, "?")
        if kind == "chat":
            text = payload.get("text")
            wall = payload.get("wall")
            if isinstance(text, str):
                self._append_log(
                    lam, origin, msg_id, username, text, wall if isinstance(wall, str) else ""
                )
        elif kind == "leave":
            self._handle_peer_leave(origin)
        elif kind == "typing":
            if username != "?":
                self._typing[username] = time.monotonic()
                self._emit("typing", users=sorted(self._typing))

    def _handle_rekey(self, st: PeerState, data: dict):
        if not st.pairwise or not st.peer_id:
            return
        try:
            plaintext = st.pairwise.decrypt(
                _b64d(data, "blob"), b"holler.rekey:" + st.peer_id.encode()
            )
            new_key = base64.b64decode(json.loads(plaintext)["sender_key"], validate=True)
        except Exception:
            return
        if len(new_key) == 32:
            self._store_sender_key(st.peer_id, new_key)

    # ── membership changes ────────────────────────────────────────────────────

    def _handle_peer_leave(self, origin: str):
        """Processes a graceful leave announcement from ``origin``."""
        self._departing.add(origin)
        st = self._find_ready(origin)
        if st:
            assert self._peer is not None
            self._track(asyncio.create_task(self._peer.drop(st.channel_key)))
        else:
            self._departing.discard(origin)
            self._finalize_departure(origin)

    def _finalize_departure(self, real_id: str, suffix: str = ""):
        """Forgets a departed peer and rotates our sender key."""
        username = self._usernames.pop(real_id, None)
        had_keys = self._sender_keys.pop(real_id, None) is not None
        if username is None and not had_keys:
            return
        self._emit("info", text=f"{username or real_id} left{suffix}")
        self._emit_presence()
        if self.running:
            self._track(asyncio.create_task(self._rotate_sender_key()))
            self._track(asyncio.create_task(self._reevaluate_room_holder()))

    async def _rotate_sender_key(self):
        """Generates a fresh sender key and distributes it pairwise.

        Called when the group shrinks so a departed member cannot decrypt
        future traffic even if they somehow kept receiving ciphertext.
        """
        if not self.running or self._peer is None:
            return
        self._sender_key = os.urandom(32)
        plaintext = json.dumps({"sender_key": _b64e(self._sender_key)}).encode()
        aad = b"holler.rekey:" + self._peer.peer_id.encode()
        for st in list(self._states.values()):
            if st.ready and st.pairwise:
                blob = st.pairwise.encrypt(plaintext, aad)
                await self._send(st.channel_key, {"type": "holler.rekey", "blob": _b64e(blob)})

    # ── liveness & reconnection ───────────────────────────────────────────────

    def _begin_reconnect(self, real_id: str, username: str):
        if real_id in self._reconnecting or not self.running:
            return
        self._reconnecting.add(real_id)
        self._track(asyncio.create_task(self._reconnect(real_id, username)))

    async def _reconnect(self, real_id: str, username: str):
        """Attempts to restore a dead link; lower peer ID redials, higher waits.

        Redial and wait both end in a fresh full handshake (new SPAKE2, new
        X25519, re-exchanged sender keys). After the backoff schedule is
        exhausted the peer is declared gone.
        """
        assert self._peer is not None
        self._emit("info", text=f"connection to {username} lost — reconnecting…")
        success = False
        try:
            if self._peer.peer_id < real_id:
                for delay in self._reconnect_delays:
                    if not self.running:
                        return
                    if self._find_ready(real_id):
                        success = True
                        break
                    self._initiated.add(real_id)
                    try:
                        await self._peer.connect_to(real_id, timeout=20)
                    except Exception:
                        self._initiated.discard(real_id)
                        await asyncio.sleep(delay)
                        continue
                    if await self._await_ready(real_id, self._handshake_timeout):
                        success = True
                        break
            else:
                total = sum(self._reconnect_delays) + self._handshake_timeout
                success = await self._await_ready(real_id, total)
        finally:
            self._reconnecting.discard(real_id)
        if not success and self.running:
            self._finalize_departure(real_id, suffix=" (unreachable)")

    async def _await_ready(self, real_id: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.running:
            if self._find_ready(real_id):
                return True
            await asyncio.sleep(0.1)
        return self._find_ready(real_id) is not None

    async def _monitor(self):
        """Periodic housekeeping: pings, staleness detection, typing expiry."""
        assert self._peer is not None
        ping = json.dumps({"type": "holler.ping"})
        tick = 0
        while self.running:
            await asyncio.sleep(self._ping_interval)
            tick += 1
            now = time.monotonic()
            for st in list(self._states.values()):
                if not st.ready:
                    continue
                await self._peer.send_to(st.channel_key, ping)
                real = st.peer_id
                if (
                    real
                    and now - st.last_seen > self._stale_after
                    and real not in self._reconnecting
                    and real not in self._departing
                ):
                    self._begin_reconnect(real, st.username or real)
                    await self._peer.drop(st.channel_key)
            expired = [u for u, ts in self._typing.items() if now - ts > TYPING_EXPIRY]
            if expired:
                for u in expired:
                    del self._typing[u]
                self._emit("typing", users=sorted(self._typing))
            if tick % 3 == 0:
                await self._reevaluate_room_holder()
