"""WebRTC peer connection management backed by PeerJS signaling."""

import asyncio
import json
import random
import string
from typing import Any, Callable, Optional

import websockets
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription

PEERJS_WS_URL = "wss://0.peerjs.com/peerjs"
PEERJS_KEY = "peerjs"

_ICE_CONFIG = RTCConfiguration(iceServers=[RTCIceServer(urls="stun:stun.l.google.com:19302")])


def _rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


async def _wait_for_ice(pc: RTCPeerConnection):
    if pc.iceGatheringState == "complete":
        return
    done = asyncio.Event()

    @pc.on("icegatheringstatechange")
    def on_state_change():
        if pc.iceGatheringState == "complete":
            done.set()

    await done.wait()


class PeerConnection:
    """Manages multiple WebRTC DataChannel connections via PeerJS signaling.

    One instance holds a single PeerJS websocket (the peer's own ID) plus an
    optional alias websocket (the room ID). All RTCPeerConnections and
    DataChannels are managed centrally regardless of which websocket brokered
    the handshake.

    Attributes:
        peer_id: The ephemeral ID registered with PeerJS on start.
        on_message: Callback fired when a message arrives on any channel.
            Signature: ``(peer_id: str, data: str) -> None``
        on_peer_connected: Callback fired when a DataChannel opens.
            Signature: ``(peer_id: str) -> None``
        on_peer_disconnected: Callback fired when a DataChannel closes.
            Signature: ``(peer_id: str) -> None``
    """

    def __init__(self):
        self.peer_id = _rand()
        self._websockets: dict[str, Any] = {}
        self._signaling_tasks: dict[str, asyncio.Task] = {}
        self._pcs: dict[str, RTCPeerConnection] = {}
        self._channels: dict = {}
        self._pending: dict[str, asyncio.Event] = {}

        self.on_message: Optional[Callable[[str, str], None]] = None
        self.on_peer_connected: Optional[Callable[[str], None]] = None
        self.on_peer_disconnected: Optional[Callable[[str], None]] = None

    @property
    def connected_peers(self) -> list[str]:
        """Returns the peer IDs of all currently open DataChannels."""
        return list(self._channels.keys())

    async def start(self):
        """Registers ``peer_id`` with PeerJS and starts the signaling loop."""
        await self._register(self.peer_id)

    async def register_alias(self, alias_id: str):
        """Registers an additional ID with PeerJS (used for the room ID).

        Args:
            alias_id: The ID to register. Incoming offers on this ID are
                handled identically to offers on ``peer_id``.

        Raises:
            ConnectionError: If PeerJS rejects the registration (e.g. ID taken).
        """
        await self._register(alias_id)

    async def unregister_alias(self, alias_id: str):
        """Closes the PeerJS websocket for a previously registered alias.

        Args:
            alias_id: The alias ID to deregister.
        """
        task = self._signaling_tasks.pop(alias_id, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        ws = self._websockets.pop(alias_id, None)
        if ws:
            await ws.close()

    async def connect_to(self, target_peer_id: str):
        """Initiates a WebRTC connection to another peer and waits for the
        DataChannel to open.

        Args:
            target_peer_id: The PeerJS ID of the remote peer.

        Raises:
            asyncio.TimeoutError: If the channel does not open within 30 s.
        """
        event = asyncio.Event()
        self._pending[target_peer_id] = event
        await self._send_offer(target_peer_id)
        await asyncio.wait_for(event.wait(), timeout=30)

    async def send_to(self, peer_id: str, data: str):
        """Sends a message to a specific connected peer.

        Args:
            peer_id: Recipient's peer ID.
            data: Message string to send.
        """
        ch = self._channels.get(peer_id)
        if ch and ch.readyState == "open":
            ch.send(data)

    async def broadcast(self, data: str):
        """Sends a message to every currently open DataChannel.

        Args:
            data: Message string to send.
        """
        for ch in list(self._channels.values()):
            if ch.readyState == "open":
                ch.send(data)

    async def close(self):
        """Cancels all signaling tasks, closes all websockets and RTCPeerConnections."""
        for task in list(self._signaling_tasks.values()):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        for ws in list(self._websockets.values()):
            await ws.close()
        for pc in self._pcs.values():
            await pc.close()

    # ── internals ────────────────────────────────────────────────────────────

    async def _register(self, peer_id: str):
        url = f"{PEERJS_WS_URL}?key={PEERJS_KEY}&id={peer_id}&token={_rand()}"
        ws = await websockets.connect(url)
        msg = json.loads(await ws.recv())
        if msg.get("type") != "OPEN":
            await ws.close()
            raise ConnectionError(f"PeerJS registration failed: {msg}")
        self._websockets[peer_id] = ws
        self._signaling_tasks[peer_id] = asyncio.create_task(self._signaling_loop(ws))

    async def _send_offer(self, target: str):
        ws = self._websockets[self.peer_id]
        pc = RTCPeerConnection(configuration=_ICE_CONFIG)
        self._pcs[target] = pc
        ch = pc.createDataChannel("chat")
        self._bind_channel(target, ch)

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        await _wait_for_ice(pc)

        await ws.send(
            json.dumps(
                {
                    "type": "OFFER",
                    "dst": target,
                    "payload": {"sdp": pc.localDescription.sdp, "type": "offer"},
                }
            )
        )

    async def _handle_offer(self, ws: Any, src: str, payload: dict):
        pc = RTCPeerConnection(configuration=_ICE_CONFIG)
        self._pcs[src] = pc

        @pc.on("datachannel")
        def on_datachannel(ch):
            self._bind_channel(src, ch)

        await pc.setRemoteDescription(RTCSessionDescription(sdp=payload["sdp"], type="offer"))
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        await _wait_for_ice(pc)

        await ws.send(
            json.dumps(
                {
                    "type": "ANSWER",
                    "dst": src,
                    "payload": {"sdp": pc.localDescription.sdp, "type": "answer"},
                }
            )
        )

    async def _handle_answer(self, src: str, payload: dict):
        pc = self._pcs.get(src)
        if pc:
            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=payload["sdp"], type="answer")
            )

    def _bind_channel(self, peer_id: str, ch):
        @ch.on("open")
        def on_open():
            self._channels[peer_id] = ch
            if peer_id in self._pending:
                self._pending.pop(peer_id).set()
            if self.on_peer_connected:
                self.on_peer_connected(peer_id)

        @ch.on("message")
        def on_message(data):
            if self.on_message:
                self.on_message(peer_id, data)

        @ch.on("close")
        def on_close():
            self._channels.pop(peer_id, None)
            if self.on_peer_disconnected:
                self.on_peer_disconnected(peer_id)

    async def _signaling_loop(self, ws: Any):
        try:
            async for raw in ws:
                msg = json.loads(raw)
                t = msg.get("type")

                if t == "HEARTBEAT":
                    await ws.send(json.dumps({"type": "HEARTBEAT"}))
                elif t == "OFFER":
                    await self._handle_offer(ws, msg["src"], msg["payload"])
                elif t == "ANSWER":
                    await self._handle_answer(msg["src"], msg["payload"])
                elif t in ("LEAVE", "EXPIRE"):
                    src = msg.get("src")
                    if src:
                        self._channels.pop(src, None)
        except (websockets.ConnectionClosed, asyncio.CancelledError):
            pass
