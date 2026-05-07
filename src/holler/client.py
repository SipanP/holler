"""Encrypted group chat client built on top of PeerConnection."""

import asyncio
import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from rich.console import Console
from rich.panel import Panel

from holler.peer import PeerConnection, _rand


@dataclass
class PeerState:
    """Per-peer cryptographic state established during the handshake.

    Attributes:
        username: Display name received during the join exchange.
        pairwise_fernet: Fernet instance keyed with the ECDH-derived pairwise
            key. Used only to distribute and receive sender keys, not for chat
            messages.
        their_sender_fernet: Fernet instance keyed with the remote peer's
            sender key. Used to decrypt all incoming chat messages from that
            peer.
    """

    username: Optional[str] = None
    pairwise_fernet: Optional[Fernet] = None
    their_sender_fernet: Optional[Fernet] = None


class Client:
    """Terminal chat client that manages the full mesh and encryption lifecycle.

    Each ``Client`` instance owns one ``PeerConnection`` (its ephemeral peer
    ID) plus optionally a room ID alias when it is the current room holder.
    Cryptographic state is split into two layers:

    - **Pairwise layer** — one ECDH-derived key per peer pair, used only to
      distribute sender keys during the handshake.
    - **Sender key layer** — one random 32-byte key per peer. Each peer
      encrypts all their outbound messages with their own sender key and
      broadcasts the ciphertext; recipients decrypt with the stored copy.

    Args:
        username: Display name shown to other peers.
        password: Shared secret used to authenticate the ECDH key exchange.
            Never transmitted.
        join_id: Room ID to join. If ``None``, a new room is created.
    """

    def __init__(self, username: str, password: str, join_id: Optional[str] = None):
        self.username = username
        self.password = password.encode()
        self.join_id = join_id

        self.console = Console()
        self.messages: list[dict] = []
        self.running = False

        self._private_key: Optional[X25519PrivateKey] = None
        self._sender_key: Optional[bytes] = None
        self._sender_fernet: Optional[Fernet] = None

        self._peer: Optional[PeerConnection] = None
        self._peers: dict[str, PeerState] = {}
        self._peer_queues: dict[str, asyncio.Queue] = {}
        self._initiated: set[str] = set()
        self._connecting: set[str] = set()
        self._first_peer_ready: asyncio.Event = asyncio.Event()

        self._room_id: Optional[str] = None
        self._holding_room: bool = False
        self._acquiring_room: bool = False

    def _generate_keypair(self):
        self._private_key = X25519PrivateKey.generate()

    def _generate_sender_key(self):
        self._sender_key = os.urandom(32)
        self._sender_fernet = Fernet(base64.urlsafe_b64encode(self._sender_key))

    def _derive_pairwise_key(self, peer_public_bytes: bytes) -> bytes:
        """Derives the pairwise key from an ECDH exchange authenticated by the password.

        Args:
            peer_public_bytes: The remote peer's raw X25519 public key bytes.

        Returns:
            32-byte pairwise key suitable for use as a Fernet key.
        """
        assert self._private_key is not None
        shared = self._private_key.exchange(X25519PublicKey.from_public_bytes(peer_public_bytes))
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"holler-p2p-v2",
            info=b"holler-pairwise-key",
        ).derive(shared + self.password)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()[:19].replace("T", " ")

    def _info(self, msg: str):
        self.console.print(f"[green]✓ {msg}[/]")

    def render(self):
        """Redraws the terminal UI with the current online list and message history."""
        self.console.clear()
        usernames = [self.username] + [s.username for s in self._peers.values() if s.username]
        self.console.print(f"[dim]Online: {', '.join(usernames)}[/]")
        self.console.print("─" * 60)

        for msg in self.messages[-15:]:
            style = "green" if msg["username"] == self.username else "cyan"
            self.console.print(
                f"[dim]{msg['timestamp']}[/] [{style}]{msg['username']}[/]: {msg['text']}"
            )

        if not self.messages:
            self.console.print("[dim italic]No messages yet...[/]")

        self.console.print("─" * 60)
        self.console.print("[dim]Type message and press Enter. 'q' to quit.[/]")

    # ── room holder logic ─────────────────────────────────────────────────────

    def _should_hold_room(self) -> bool:
        """Returns True if this peer has the lexicographically lowest ID in the mesh.

        The room holder is always the peer with the lowest ID, giving a
        deterministic tiebreaker that all peers can compute independently
        without coordination.
        """
        assert self._peer is not None
        all_ids = [self._peer.peer_id] + list(self._peers.keys())
        return min(all_ids) == self._peer.peer_id

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
        for _ in range(5):
            try:
                await self._peer.register_alias(self._room_id)
                self._holding_room = True
                break
            except ConnectionError:
                await asyncio.sleep(1)
        self._acquiring_room = False

    async def _release_room(self):
        """Deregisters the room ID alias from PeerJS."""
        assert self._peer is not None
        assert self._room_id is not None
        if not self._holding_room:
            return
        await self._peer.unregister_alias(self._room_id)
        self._holding_room = False

    async def _reevaluate_room_holder(self):
        """Acquires or releases the room ID based on the current peer list.

        Called whenever a peer joins or leaves. Because all peers apply the
        same deterministic rule (lowest peer ID holds the room), no
        coordination messages are needed.
        """
        if self._room_id is None:
            return
        if self._should_hold_room() and not self._holding_room:
            await self._acquire_room()
        elif not self._should_hold_room() and self._holding_room:
            await self._release_room()

    # ── peer event callbacks ──────────────────────────────────────────────────

    def _on_message(self, peer_id: str, raw: str):
        q = self._peer_queues.get(peer_id)
        if q:
            q.put_nowait(raw)

    def _on_peer_connected(self, peer_id: str):
        self._peers[peer_id] = PeerState()
        self._peer_queues[peer_id] = asyncio.Queue()
        is_initiator = peer_id in self._initiated
        self._initiated.discard(peer_id)
        self._connecting.discard(peer_id)
        asyncio.create_task(self._peer_session(peer_id, is_initiator))

    def _on_channel_closed(self, peer_id: str):
        q = self._peer_queues.get(peer_id)
        if q:
            q.put_nowait(json.dumps({"type": "_disconnect"}))

    # ── connection management ─────────────────────────────────────────────────

    async def _connect_to_peer(self, peer_id: str):
        assert self._peer is not None
        if peer_id == self._peer.peer_id:
            return
        if peer_id in self._peers or peer_id in self._connecting:
            return
        self._connecting.add(peer_id)
        self._initiated.add(peer_id)
        await self._peer.connect_to(peer_id)

    # ── per-peer session ──────────────────────────────────────────────────────

    async def _peer_session(self, peer_id: str, is_initiator: bool):
        """Runs the full lifecycle for one peer: handshake then message loop.

        Args:
            peer_id: The remote peer's ID.
            is_initiator: True if we sent the offer; False if we received it.
                The initiator receives the roster; the receiver sends it.
        """
        try:
            await self._handshake(peer_id, is_initiator)
            await self._message_loop(peer_id)
        except Exception:
            pass
        finally:
            state = self._peers.pop(peer_id, None)
            self._peer_queues.pop(peer_id, None)
            if state and state.username:
                self.messages.append(
                    {"username": "—", "text": f"{state.username} left", "timestamp": self._now()}
                )
                self.render()
            asyncio.create_task(self._reevaluate_room_holder())

    async def _handshake(self, peer_id: str, is_initiator: bool):
        """Executes the four-step handshake with a newly connected peer.

        Steps (both sides run concurrently):

        1. **kex** — exchange ephemeral X25519 public keys and derive the
           pairwise key via ``HKDF(ecdh_secret ‖ password)``.
        2. **sender_key** — exchange sender keys encrypted with the pairwise
           key. After this step both peers can encrypt/decrypt chat messages.
        3. **roster** — the receiver (host) sends the list of existing peer
           IDs and the room ID; the initiator (joiner) connects to each.
        4. **join** — exchange display names.

        Args:
            peer_id: The remote peer's ID.
            is_initiator: True if we sent the WebRTC offer.
        """
        assert self._peer is not None
        assert self._private_key is not None
        assert self._sender_key is not None
        state = self._peers[peer_id]
        queue = self._peer_queues[peer_id]

        # kex — both sides send simultaneously, then wait
        pub_bytes = self._private_key.public_key().public_bytes_raw()
        await self._peer.send_to(
            peer_id,
            json.dumps({"type": "holler.kex", "pubkey": base64.b64encode(pub_bytes).decode()}),
        )
        data = json.loads(await asyncio.wait_for(queue.get(), timeout=30))
        assert data["type"] == "holler.kex"

        pairwise_key = self._derive_pairwise_key(base64.b64decode(data["pubkey"]))
        state.pairwise_fernet = Fernet(base64.urlsafe_b64encode(pairwise_key))

        # sender key exchange — both sides send, then wait
        encrypted_sender = state.pairwise_fernet.encrypt(self._sender_key)
        await self._peer.send_to(
            peer_id,
            json.dumps(
                {"type": "holler.sender_key", "key": base64.b64encode(encrypted_sender).decode()}
            ),
        )
        data = json.loads(await asyncio.wait_for(queue.get(), timeout=30))
        assert data["type"] == "holler.sender_key"

        their_key = state.pairwise_fernet.decrypt(base64.b64decode(data["key"]))
        state.their_sender_fernet = Fernet(base64.urlsafe_b64encode(their_key))

        # roster — host sends peer list + room_id, joiner connects to them
        if not is_initiator:
            other_peers = [pid for pid in self._peers if pid != peer_id]
            await self._peer.send_to(
                peer_id,
                json.dumps(
                    {"type": "holler.roster", "peers": other_peers, "room_id": self._room_id}
                ),
            )
        else:
            data = json.loads(await asyncio.wait_for(queue.get(), timeout=30))
            assert data["type"] == "holler.roster"
            self._room_id = data.get("room_id")
            for pid in data.get("peers", []):
                asyncio.create_task(self._connect_to_peer(pid))

        # username exchange
        await self._peer.send_to(
            peer_id, json.dumps({"type": "join", "username": self.username})
        )
        data = json.loads(await asyncio.wait_for(queue.get(), timeout=30))
        assert data["type"] == "join"
        state.username = data["username"]

        self._first_peer_ready.set()
        self._info(f"{state.username} joined")
        self.render()
        asyncio.create_task(self._reevaluate_room_holder())

    async def _message_loop(self, peer_id: str):
        state = self._peers[peer_id]
        queue = self._peer_queues[peer_id]

        while self.running:
            try:
                raw = await asyncio.wait_for(queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            t = data.get("type")
            if t == "message":
                assert state.their_sender_fernet is not None
                try:
                    text = state.their_sender_fernet.decrypt(data["text"].encode()).decode()
                except Exception:
                    text = "[decrypt failed]"
                self.messages.append(
                    {
                        "username": data.get("username", "?"),
                        "text": text,
                        "timestamp": data.get("timestamp", ""),
                    }
                )
                self.render()
            elif t in ("leave", "_disconnect"):
                break

    async def _input_loop(self):
        assert self._sender_fernet is not None
        assert self._peer is not None
        loop = asyncio.get_event_loop()
        while self.running:
            try:
                text = await loop.run_in_executor(None, input)
                if text.lower() in ("q", "quit", "exit"):
                    self.running = False
                    break
                if text.strip():
                    encrypted = self._sender_fernet.encrypt(text.encode()).decode()
                    await self._peer.broadcast(
                        json.dumps(
                            {
                                "type": "message",
                                "username": self.username,
                                "text": encrypted,
                                "timestamp": self._now(),
                            }
                        )
                    )
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break

    async def run_async(self):
        """Runs the full client lifecycle: connect, chat, disconnect."""
        self.console.clear()
        self.console.print(Panel("[bold cyan]holler[/]", expand=False))

        self._generate_keypair()
        self._generate_sender_key()

        self._peer = PeerConnection()
        self._peer.on_message = self._on_message
        self._peer.on_peer_connected = self._on_peer_connected
        self._peer.on_peer_disconnected = self._on_channel_closed

        await self._peer.start()

        if not self.join_id:
            self._room_id = _rand()
            await self._acquire_room()
            self.console.print(f"\n[bold]Room ID:[/] [yellow]{self._room_id}[/]")
            self.console.print("[dim]Share this with peers to invite them.[/]\n")
            self.running = True
        else:
            with self.console.status("[cyan]Connecting...[/]", spinner="dots"):
                await self._connect_to_peer(self.join_id)
                await self._first_peer_ready.wait()
            self.running = True
            self.render()

        try:
            await self._input_loop()
        finally:
            self.running = False
            try:
                if self._holding_room:
                    await self._release_room()
                await self._peer.broadcast(
                    json.dumps({"type": "leave", "username": self.username})
                )
                await asyncio.sleep(0.1)
            except Exception:
                pass
            await self._peer.close()
            self.console.print("\n[yellow]Disconnected[/]")

    def run(self):
        """Blocking entry point. Calls ``run_async`` inside ``asyncio.run``."""
        try:
            asyncio.run(self.run_async())
        except KeyboardInterrupt:
            pass
